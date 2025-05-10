use std::fs::{self, File};
use std::io::Write;
use bitcoin::consensus::encode;
use bitcoin::secp256k1::Secp256k1; // All context を使う場合は secp256k1::All が必要
use bitcoin::secp256k1::All as AllContext; // エイリアス
use clap::Parser;

mod config;
mod transaction;
mod error;
mod types;
mod cli;

use config::InputConfig;
use error::AppError;
use cli::{CliArgs, parse_network};

fn main() -> Result<(), AppError> {
    env_logger::init();

    let args = CliArgs::parse();
    log::info!("アプリケーションを開始します。引数: {:?}", args);

    let cli_network = parse_network(&args.network)?;
    log::info!("指定されたネットワーク: {:?}", cli_network);

    let input_file_content = fs::read_to_string(&args.input_file).map_err(|e| {
        log::error!("入力ファイルの読み込みに失敗しました: {:?}", args.input_file);
        AppError::Io(e)
    })?;

    let config: InputConfig = serde_json::from_str(&input_file_content).map_err(|e| {
        log::error!("入力JSONのパースに失敗しました。");
        AppError::JsonParse {
            file_path: args.input_file.clone(),
            source: e,
        }
    })?;
    log::debug!("入力設定ファイルのパース成功: {:?}", config);

    let secp: Secp256k1<AllContext> = Secp256k1::new(); // 明示的に AllContext を指定

    let signed_tx = transaction::create_and_sign_transaction(config, cli_network, &secp)?;
    log::info!("署名済みトランザクションの生成に成功しました。");

    // トランザクションのシリアライズ (16進数形式)
    // bitcoin 0.32 では serialize_hex は consensus::encode::hex::encode かもしれない
    // -> 確認したところ、bitcoin::consensus::encode::serialize_hex で引き続き利用可能
    let serialized_tx = encode::serialize_hex(&signed_tx);
    log::info!("Raw transaction hex: {}", serialized_tx);

    println!("{}", serialized_tx);

    let mut output_file = File::create(&args.output_file).map_err(|e| {
        log::error!("出力ファイルの作成に失敗しました: {:?}", args.output_file);
        AppError::Io(e)
    })?;
    output_file.write_all(serialized_tx.as_bytes()).map_err(|e| {
        log::error!("出力ファイルへの書き込みに失敗しました。");
        AppError::Io(e)
    })?;
    log::info!("Raw transactionを {:?} に保存しました。", args.output_file);

    log::info!("処理が正常に完了しました。");
    Ok(())
}