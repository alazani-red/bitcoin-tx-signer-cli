use bitcoin::{
    Address, Amount, OutPoint, PrivateKey, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    absolute::LockTime, network::Network as BitcoinNetwork, sighash::{SighashCache, EcdsaSighashType},
    secp256k1::{Secp256k1, Message, constants::SECRET_KEY_SIZE, All}, // All context
    consensus::encode,
    // ecdsa, // bitcoin::ecdsa::Signature を直接使う場合。今回は bitcoin::Signature でよい
    key::FromWifError as KeyError, // from_wifが返すエラー型
    // taproot::TaprootSpendInfo, // 今回は未使用
    // key::TweakedPublicKey, // 今回は未使用
    // psbt::Input as PsbtInput, // 今回は未使用
    // bitcoin::Signature を使う (secp256k1::ecdsa::Signatureではない)
    // bitcoin 0.32では bitcoin::ecdsa::Signature ではなく bitcoin::sighash:: स्थित EcdsaSig を使うか、
    // bitcoin::taproot::Signature を使うことが多い。P2PKH/P2WPKHでは EcdsaSig。
    // bitcoin::ecdsa::Signature は bitcoin::secp256k1::ecdsa::Signature のラッパー
    // 0.32でも bitcoin::ecdsa::Signature は存在する
    ecdsa::Signature as BitcoinEcdsaSignature,
};
use std::str::FromStr;

use crate::{
    config::{InputConfig, UtxoInput, TransactionOutputDef},
    error::AppError,
    types::{ProcessedUtxo, ScriptType},
};

// Bitcoin Coreのデフォルトダスト閾値 (P2PKH/P2WPKH出力に対して)
const DUST_THRESHOLD_SATS: u64 = 546;

// トランザクションサイズの推定に使用するダミーデータ
// DER署名(71-73バイト) + SIGHASHフラグ(1バイト)
const DUMMY_SIGNATURE_LEN: usize = 72; // 71(max DER) + 1(sighash type)
// 圧縮公開鍵
// const COMPRESSED_PUBLIC_KEY_LEN: usize = 33;


pub fn create_and_sign_transaction(
    config: InputConfig,
    cli_network: BitcoinNetwork,
    secp: &Secp256k1<All>,
) -> Result<Transaction, AppError> {
    log::info!("トランザクション構築処理を開始します。");

    // 1. 入力データの検証とProcessedUtxoへの変換
    let mut processed_utxos: Vec<ProcessedUtxo> = Vec::new();
    let mut total_input_value_sats = 0;

    for utxo_input in config.utxos.iter() {
        let private_key = PrivateKey::from_wif(&utxo_input.private_key_wif)
            .map_err(AppError::BitcoinKey)?; // エラー型を明示的に変換
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
        let script_type = ScriptType::from_script_buf(&script_pubkey)?;

        let sequence_num = utxo_input.sequence.or(config.default_sequence).unwrap_or(Sequence::MAX.0); // Sequence::MAX.0 を使用
        let sequence = Sequence(sequence_num);

        let utxo_value = Amount::from_sat(utxo_input.value_sats);
        let tx_out = TxOut {
            value: utxo_value,
            script_pubkey: script_pubkey.clone(),
        };

        processed_utxos.push(ProcessedUtxo {
            out_point,
            tx_out,
            private_key,
            public_key,
            script_type,
            sequence,
            value: utxo_value, // Amount型で保持
        });
        total_input_value_sats += utxo_input.value_sats;
        log::debug!("処理済みUTXO追加: txid={}, vout={}, value={}, type={:?}",
            utxo_input.txid, utxo_input.vout, utxo_input.value_sats, script_type);
    }

    // 2. 受信者出力の作成
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

    // 3. 手数料計算と変更（おつり）処理
    let initial_inputs: Vec<TxIn> = processed_utxos
        .iter()
        .map(|pu| {
            let mut tx_in = TxIn {
                previous_output: pu.out_point,
                script_sig: ScriptBuf::new(),
                sequence: pu.sequence,
                witness: bitcoin::Witness::new(),
            };
            match pu.script_type {
                ScriptType::P2PKH => {
                    let dummy_sig_bytes = [0u8; DUMMY_SIGNATURE_LEN];
                    let dummy_pk_bytes = pu.public_key.to_bytes();
                    tx_in.script_sig = bitcoin::script::Builder::new()
                        .push_slice(&dummy_sig_bytes) // convert to slice
                        .push_key(&pu.public_key) // public key ref
                        .into_script();
                }
                ScriptType::P2WPKH => {
                     tx_in.witness.push(vec![0u8; DUMMY_SIGNATURE_LEN]); // Vec<u8>
                     tx_in.witness.push(pu.public_key.to_bytes()); // Vec<u8>
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
        value: Amount::from_sat(0),
        script_pubkey: change_address.script_pubkey(),
    };
    temp_outputs_for_size_calc.push(change_tx_out_for_size);


    let temp_tx = Transaction {
        version: bitcoin::transaction::Version(2), // 明示的に Version(2)
        lock_time: LockTime::ZERO,
        input: initial_inputs.clone(),
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
    let mut final_outputs = outputs;

    if change_value_sats >= DUST_THRESHOLD_SATS {
        log::debug!("おつり発生: {} sats, おつりアドレス: {}", change_value_sats, change_address);
        final_outputs.push(TxOut {
            value: Amount::from_sat(change_value_sats),
            script_pubkey: change_address.script_pubkey(),
        });
    } else if change_value_sats > 0 {
        log::warn!("おつり {} sats はダスト閾値 {} sats 未満のため手数料に含めます。", change_value_sats, DUST_THRESHOLD_SATS);
    }
    
    let mut transaction = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: LockTime::ZERO,
        input: processed_utxos.iter().map(|pu| TxIn {
            previous_output: pu.out_point,
            script_sig: ScriptBuf::new(),
            sequence: pu.sequence,
            witness: bitcoin::Witness::new(),
        }).collect(),
        output: final_outputs,
    };

    log::info!("トランザクション署名処理を開始します。");
    let mut sighash_cache = SighashCache::new(&mut transaction);

    for (input_index, p_utxo) in processed_utxos.iter().enumerate() {
        log::debug!("入力 {} (txid={}, vout={}) の署名を開始します。", input_index, p_utxo.out_point.txid, p_utxo.out_point.vout);
        let sighash_type = EcdsaSighashType::All;
        let sighash_message: Message;

        match p_utxo.script_type {
            ScriptType::P2PKH => {
                // value は Amount 型
                let sighash = sighash_cache.legacy_signature_hash(
                    input_index,
                    &p_utxo.tx_out.script_pubkey,
                    sighash_type.to_u32(),
                ).map_err(|e| AppError::SighashError { input_index, source:e })?;
                sighash_message = Message::from_digest_slice(sighash.as_ref()) // Sighash は Hash なので as_ref()
                    .map_err(|e| AppError::SighashError { input_index, source: e })?;
                // secp256k1::ecdsa::Signature を生成
                let secp_sig = secp.sign_ecdsa(&sighash_message, &p_utxo.private_key.inner);
                
                // bitcoin::ecdsa::Signature を作成
                let btc_ecdsa_sig = bitcoin::ecdsa::Signature::from_slice(&secp_sig.serialize_compact())
                    .map_err(|e| AppError::SignatureError { input_index, source: e })?;

                let script_sig = bitcoin::script::Builder::new()
                    .push_slice(btc_ecdsa_sig.to_vec())
                    .push_key(&p_utxo.public_key)
                    .into_script();
                sighash_cache.transaction_mut().input[input_index].script_sig = script_sig;
                log::debug!("入力 {} (P2PKH) の署名完了。", input_index);
            }
            ScriptType::P2WPKH => {
                let script_code = p_utxo.tx_out.script_pubkey.p2wpkh_script_code()
                    .ok_or_else(|| AppError::Internal("P2WPKH script codeの取得に失敗".to_string()))?;
                
                // value は Amount 型, script_code は値渡し
                let sighash = sighash_cache.segwit_signature_hash(
                    input_index,
                    script_code, // ScriptBuf (値渡し)
                    p_utxo.value, // Amount 型の UTXO の value
                    sighash_type,
                ).map_err(|e| AppError::SighashError{input_index, source: e})?;
                sighash_message = Message::from_slice(sighash.as_ref()) // Sighash は Hash なので as_ref()
                     .map_err(|e| AppError::Secp256k1(e))?;

                let secp_sig = secp.sign_ecdsa(&sighash_message, &p_utxo.private_key.inner);
                let btc_ecdsa_sig = BitcoinEcdsaSignature::from_secp_ecdsa(secp_sig, sighash_type);

                let mut witness = bitcoin::Witness::new();
                witness.push(btc_ecdsa_sig.to_vec());
                witness.push(p_utxo.public_key.to_bytes());
                sighash_cache.transaction_mut().input[input_index].witness = witness;
                log::debug!("入力 {} (P2WPKH) の署名完了。", input_index);
            }
        }
    }
    log::info!("全ての入力の署名が完了しました。");

    Ok(sighash_cache.into_transaction())
}