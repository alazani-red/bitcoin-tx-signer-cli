use clap::Parser;
use std::path::PathBuf;
use bitcoin::Network as BitcoinNetwork;
use crate::error::AppError;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct CliArgs {
    /// トランザクション情報を記述したJSONファイルへのパス
    #[clap(short, long, value_parser)]
    pub input_file: PathBuf,

    /// 生成されたraw transaction hexを保存するファイルへのパス
    #[clap(short, long, value_parser)]
    pub output_file: PathBuf,

    /// 使用するネットワーク ("bitcoin", "testnet", "regtest")
    #[clap(short, long, value_parser, default_value = "testnet")]
    pub network: String,
}

pub fn parse_network(network_str: &str) -> Result<BitcoinNetwork, AppError> {
    match network_str.to_lowercase().as_str() {
        "bitcoin" | "mainnet" => Ok(BitcoinNetwork::Bitcoin),
        "testnet" => Ok(BitcoinNetwork::Testnet),
        "regtest" => Ok(BitcoinNetwork::Regtest),
        s => Err(AppError::InputValidation(format!("無効なネットワークが指定されました: {}", s))),
    }
}