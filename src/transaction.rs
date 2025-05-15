use bitcoin::{
    absolute::LockTime, network::Network as BitcoinNetwork, script::{PushBytesBuf}, secp256k1::{All, Message, Secp256k1}, sighash::{EcdsaSighashType, SighashCache}, Address, Amount, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid
};
use std::str::FromStr;

use crate::{
    config::InputConfig,
    error::{AppError, },
    types::{ProcessedUtxo, ScriptType}, // ScriptType が Clone または Copy を実装していることを確認してください
};

// Bitcoin Coreのデフォルトダスト閾値 (P2PKH/P2WPKH出力に対して)
const DUST_THRESHOLD_SATS: u64 = 546;

// トランザクションサイズの推定に使用するダミーデータ
const DUMMY_SIGNATURE_LEN: usize = 72;

// 署名に必要な情報を一時的に保持するための構造体
struct SigningInfo {
    input_index: usize,
    sighash_message: Message,
    private_key: PrivateKey, // bitcoin::PrivateKey は Clone を実装
    public_key: PublicKey,   // bitcoin::PublicKey は Copy (かつ Clone) を実装
    script_type: ScriptType, // ScriptType が Copy または Clone を実装している必要あり
}

pub fn create_and_sign_transaction(
    config: InputConfig,
    cli_network: BitcoinNetwork,
    secp: &Secp256k1<All>,
) -> Result<Transaction, AppError> {
    log::info!("トランザクション構築処理を開始します。");

    // (1. 入力データの検証とProcessedUtxoへの変換 ... 変更なし)
    let mut processed_utxos: Vec<ProcessedUtxo> = Vec::new();
    let mut total_input_value_sats = 0;

    for utxo_input in config.utxos.iter() {
        let private_key = PrivateKey::from_wif(&utxo_input.private_key_wif)
            .map_err(AppError::BitcoinKey)?;
        if private_key.network != cli_network.into() {
            return Err(AppError::NetworkMismatch {
                cli_network: format!("{:?}", cli_network),
                inferred_network: format!("{:?}", private_key.network),
            });
        }
        let public_key = private_key.public_key(secp);

        let txid = Txid::from_str(&utxo_input.txid)
            .map_err(|e| AppError::InputValidation(format!("無効なTXID形式 ({}): {}", utxo_input.txid, e)))?;
        let out_point = OutPoint::new(txid, utxo_input.vout);

        let script_pubkey_bytes = hex::decode(&utxo_input.script_pubkey_hex)
            .map_err(|e| AppError::InputValidation(format!("scriptPubKeyHexのデコード失敗: {}", e)))?;
        let script_pubkey = ScriptBuf::from_bytes(script_pubkey_bytes);
        let script_type = ScriptType::from_script_buf(&script_pubkey)?; // ScriptTypeの導出

        let sequence_num = utxo_input.sequence.or(config.default_sequence).unwrap_or(Sequence::MAX.0);
        let sequence = Sequence(sequence_num);

        let utxo_value = Amount::from_sat(utxo_input.value_sats);
        let tx_out = TxOut {
            value: utxo_value,
            script_pubkey: script_pubkey.clone(),
        };

        processed_utxos.push(ProcessedUtxo {
            out_point,
            tx_out,
            private_key, // private_key はここでムーブされるか、Clone される
            public_key,
            script_type, // script_type が Copy または Clone であることを確認
            sequence,
            value: utxo_value,
        });
        total_input_value_sats += utxo_input.value_sats;
        log::debug!("処理済みUTXO追加: txid={}, vout={}, value={}, type={:?}",
            utxo_input.txid, utxo_input.vout, utxo_input.value_sats, script_type);
    }

    // (2. 受信者出力の作成 ... 変更なし)
    let mut outputs: Vec<TxOut> = Vec::new();
    let mut total_recipient_output_value_sats = 0;
    for output_def in config.outputs.iter() {
        let address = Address::from_str(&output_def.address)
            .and_then(|addr| addr.require_network(cli_network))
            .map_err(|e| AppError::InputValidation(format!("受信者アドレス形式エラーまたはネットワーク不整合 ({}): {}", output_def.address, e)))?;
        outputs.push(TxOut {
            value: Amount::from_sat(output_def.value_sats),
            script_pubkey: address.script_pubkey(),
        });
        total_recipient_output_value_sats += output_def.value_sats;
        log::debug!("受信者出力追加: address={}, value={}", output_def.address, output_def.value_sats);
    }

    // (3. 手数料計算と変更（おつり）処理 ... 変更なし)
    let initial_inputs: Vec<TxIn> = processed_utxos
        .iter()
        .map(|pu| {
            let mut tx_in = TxIn {
                previous_output: pu.out_point,
                script_sig: ScriptBuf::new(), // 手数料計算時は空の script_sig
                sequence: pu.sequence,
                witness: bitcoin::Witness::new(), // 手数料計算時は空の witness
            };
            // 手数料計算のためのダミー署名と公開鍵のサイズをscript_sig/witnessに反映
            match pu.script_type {
                ScriptType::P2PKH => {
                    tx_in.script_sig = bitcoin::script::Builder::new()
                        .push_slice([0u8; DUMMY_SIGNATURE_LEN])
                        .push_key(&pu.public_key)
                        .into_script();
                }
                ScriptType::P2WPKH => {
                    tx_in.witness.push(vec![0u8; DUMMY_SIGNATURE_LEN]);
                    tx_in.witness.push(pu.public_key.to_bytes());
                }
            }
            tx_in
        })
        .collect();

    let mut temp_outputs_for_size_calc = outputs.clone();
    let change_address_str = config.change_address.clone();
    let change_address = Address::from_str(&change_address_str)
        .and_then(|addr| addr.require_network(cli_network))
        .map_err(|e| AppError::ChangeAddressDerivation(format!("おつりアドレス形式エラーまたはネットワーク不整合 ({}): {}", config.change_address, e)))?;

    let change_tx_out_for_size = TxOut {
        value: Amount::from_sat(0), // ダミーの金額
        script_pubkey: change_address.script_pubkey(),
    };
    temp_outputs_for_size_calc.push(change_tx_out_for_size); // おつり出力もサイズ計算に含める

    let temp_tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: initial_inputs.clone(), // ダミー署名入りの入力
        output: temp_outputs_for_size_calc.clone(),
    };

    let estimated_vsize = temp_tx.vsize();
    let total_fee_sats = estimated_vsize as u64 * config.fee_rate_sats_per_vb;
    log::debug!("推定vsize: {} vB, 手数料率: {} sats/vB, 計算された手数料: {} sats", estimated_vsize, config.fee_rate_sats_per_vb, total_fee_sats);

    if total_input_value_sats < total_recipient_output_value_sats + total_fee_sats {
        return Err(AppError::InsufficientFunds {
            available: total_input_value_sats,
            required: total_recipient_output_value_sats + total_fee_sats,
            fee: total_fee_sats,
        });
    }

    let change_value_sats = total_input_value_sats - total_recipient_output_value_sats - total_fee_sats;
    let mut final_outputs = outputs; // 受信者出力

    if change_value_sats >= DUST_THRESHOLD_SATS {
        log::debug!("おつり発生: {} sats, おつりアドレス: {}", change_value_sats, change_address);
        final_outputs.push(TxOut {
            value: Amount::from_sat(change_value_sats),
            script_pubkey: change_address.script_pubkey(),
        });
    } else if change_value_sats > 0 {
        log::warn!("おつり {} sats はダスト閾値 {} sats 未満のため手数料に含めます。", change_value_sats, DUST_THRESHOLD_SATS);
        // この場合、手数料が実質的に total_fee_sats + change_value_sats となる
    }
    
    // 署名対象のトランザクションを初期化 (script_sig と witness は空)
    let mut transaction = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: processed_utxos.iter().map(|pu| TxIn {
            previous_output: pu.out_point,
            script_sig: ScriptBuf::new(), // 署名前は空
            sequence: pu.sequence,
            witness: bitcoin::Witness::new(), // 署名前は空
        }).collect(),
        output: final_outputs,
    };

    // --- ここから署名処理の変更 ---
    log::info!("トランザクション署名処理を開始します。");
    let mut signing_infos: Vec<SigningInfo> = Vec::new();

    // 1. 署名ハッシュ計算フェーズ
    // このスコープ内で SighashCache を使用し、transaction を可変借用する
    {
        // SighashCache は署名がまだないトランザクションのコピーまたは参照で初期化
        // SighashCache::new に渡す transaction は、このスコープ内でのみ可変借用される
        let mut sighash_cache = SighashCache::new(&mut transaction);

        for (input_index, p_utxo) in processed_utxos.iter().enumerate() {
            log::debug!("入力 {} (txid={}, vout={}) の署名ハッシュ計算を開始します。", input_index, p_utxo.out_point.txid, p_utxo.out_point.vout);
            let sighash_type = EcdsaSighashType::All;
            let current_sighash_message: Message;

            match &p_utxo.tx_out.script_pubkey { // 直接script_pubkeyオブジェクトに対してメソッドを呼ぶ
                script if script.is_p2pkh() => {
                    // P2PKHの処理
                    let sighash = sighash_cache.legacy_signature_hash(
                        input_index,
                        script,
                        sighash_type.to_u32(),
                    ).map_err(|e| AppError::IndexError { input_index, source: e })?;
                    current_sighash_message = Message::from_digest_slice(sighash.as_ref())
                         .map_err(|e| AppError::SignatureError{input_index, source: bitcoin::ecdsa::Error::Secp256k1(e)})?;
                },
                script if script.is_p2wpkh() => {
                    // P2WPKHの処理
                    let script_code = script.p2wpkh_script_code() // script_pubkeyからscript_codeを取得
                        .ok_or_else(|| AppError::Internal(format!("P2WPKH script codeの取得に失敗 (input {})", input_index)))?;

                    let sighash = sighash_cache.p2wpkh_signature_hash(
                        input_index,
                        &script_code, // script_codeを渡す
                        p_utxo.value,
                        sighash_type,
                    ).map_err(|e| AppError::SighashError{input_index, source: e})?;
                    current_sighash_message = Message::from_digest_slice(sighash.as_ref())
                        .map_err(|e| AppError::SignatureError{input_index, source: bitcoin::ecdsa::Error::Secp256k1(e)})?;
                },
                _script => {
                    return Err(AppError::UnknownScriptType {
                        script_hex: _script.to_string(), // スクリプトの16進数表現を渡す
                    });
                } 
            }            // ProcessedUtxoから clone するか、必要なフィールドをSigningInfoにコピーする
            // PrivateKey, PublicKey, ScriptType は Clone または Copy が必要
            signing_infos.push(SigningInfo {
                input_index,
                sighash_message: current_sighash_message,
                private_key: p_utxo.private_key.clone(), // PrivateKeyはClone
                public_key: p_utxo.public_key,         // PublicKeyはCopy
                script_type: p_utxo.script_type,       // ScriptTypeがCopyかCloneであることを確認
            });
        }
    } // ここで sighash_cache が破棄され、transaction の可変借用が解放される

    log::info!("全ての署名ハッシュの計算が完了しました。署名生成と適用を開始します。");

    // 2. 署名生成と適用フェーズ
    // この時点では transaction は可変借用されていないため、直接変更可能
    for info in signing_infos {
        log::debug!("入力 {} ({:?}) の署名生成と適用を開始します。", info.input_index, info.script_type);

        let secp_sig = secp.sign_ecdsa(&info.sighash_message, &info.private_key.inner);
        let btc_ecdsa_sig = bitcoin::ecdsa::Signature::from_slice(&secp_sig.serialize_compact())
            .map_err(|e| AppError::SignatureError { input_index: info.input_index, source: e })?;

        match info.script_type {
            ScriptType::P2PKH => {
                let final_script_sig = bitcoin::script::Builder::new()
                    .push_slice(PushBytesBuf::try_from(btc_ecdsa_sig.to_vec())
                        .map_err(|_| AppError::Internal(format!("P2PKH署名のPushBytes変換失敗 (input {})", info.input_index)))?)
                    .push_key(&info.public_key)
                    .into_script();
                transaction.input[info.input_index].script_sig = final_script_sig;
                log::debug!("入力 {} (P2PKH) の署名適用完了。", info.input_index);
            }
            ScriptType::P2WPKH => {
                let mut final_witness = bitcoin::Witness::new();
                final_witness.push(btc_ecdsa_sig.to_vec());
                final_witness.push(info.public_key.to_bytes());
                transaction.input[info.input_index].witness = final_witness;
                log::debug!("入力 {} (P2WPKH) の署名適用完了。", info.input_index);
            }
        }
    }
    log::info!("全ての入力の署名が完了しました。");

    Ok(transaction)
}