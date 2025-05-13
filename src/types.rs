use bitcoin::{OutPoint, TxOut, PrivateKey, PublicKey, Sequence, script::ScriptBuf, Amount};
use crate::error::AppError;

// #[derive(Debug, Clone, PartialEq, Eq)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)] // <- Copy と Clone を追加 (他に必要なトレイトも適宜)
pub enum ScriptType {
    P2PKH,
    P2WPKH,
    // 他のタイプも追加可能
}

impl ScriptType {
    pub fn from_script_buf(script: &ScriptBuf) -> Result<Self, AppError> {
        if script.is_p2pkh() {
            Ok(ScriptType::P2PKH)
        } else if script.is_p2wpkh() {
            Ok(ScriptType::P2WPKH)
        }
        // is_p2sh(), is_p2wsh(), is_v0_p2tr() なども将来的に対応可能
        else {
            Err(AppError::UnknownScriptType { script_hex: script.to_hex_string() })
        }
    }
}


#[derive(Debug)]
pub struct ProcessedUtxo {
    pub out_point: OutPoint,
    pub tx_out: TxOut, // 元の value と script_pubkey を含む
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub script_type: ScriptType,
    pub sequence: Sequence,
    pub value: Amount, // u64 から Amount に変更 (Sighash計算にAmount型が必要なため)
}