use std::path::PathBuf;
use bitcoin::consensus::encode::Error as BitcoinEncodeError;
use bitcoin::address::ParseError as BitcoinAddressError;
// use bitcoin::sighash::InvalidSighashTypeError as BitcoinSighashError;
use bitcoin::sighash::InvalidSighashTypeError as BitcoinSighashError;
use bitcoin::key::FromWifError as BitcoinKeyError; // WIFデコードエラー用
use secp256k1::Error as SecpError;
use thiserror::Error; // use thiserror::Error; を追加

#[derive(Debug, Error)] // thiserror::Error を使用
pub enum AppError {
    #[error("I/Oエラー: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSONパースエラー ファイル: {file_path:?}, 詳細: {source}")]
    JsonParse {
        file_path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("Bitcoinコンセンサスエンコードエラー: {0}")]
    BitcoinConsensus(#[from] BitcoinEncodeError),

    #[error("Bitcoinアドレスエラー: {0}")]
    BitcoinAddress(#[from] BitcoinAddressError),

    #[error("Bitcoin秘密鍵(WIF)処理エラー: {0}")]
    BitcoinKey(#[from] BitcoinKeyError),

    #[error("secp256k1エラー: {0}")]
    Secp256k1(#[from] SecpError),

    #[error("Sighash計算エラー (入力インデックス {input_index}): {source}")]
    SighashError{
        input_index: usize,
        #[source]
        source: BitcoinSighashError,
    },

    #[error("署名エラー (入力インデックス {input_index}): {source}")]
    SignatureError {
        input_index: usize,
        #[source]
        source: secp256k1::Error, // secp256k1のエラー型
    },

    #[error("ネットワーク不整合: CLI指定 ({cli_network}) vs WIF/アドレス ({inferred_network})")]
    NetworkMismatch {
        cli_network: String,
        inferred_network: String,
    },

    #[error("入力検証エラー: {0}")]
    InputValidation(String),

    #[error("資金不足: 利用可能な総額 {available} sats, 要求額 {required} sats (手数料 {fee} sats を含む)")]
    InsufficientFunds {
        available: u64,
        required: u64,
        fee: u64,
    },

    #[error("おつりアドレスの導出に失敗しました: {0}")]
    ChangeAddressDerivation(String),

    #[error("トランザクション構築エラー: {0}")]
    TransactionBuild(String),

    #[error("不明なスクリプトタイプ: {script_hex}")]
    UnknownScriptType { script_hex: String },

    #[error("UTXOのscript_pubkey_hexからのスクリプト導出に失敗: {0}")]
    ScriptConversionError(String),

    #[error("内部エラー: {0}")]
    Internal(String),
}