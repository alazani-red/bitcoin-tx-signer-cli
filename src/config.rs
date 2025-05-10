use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct InputConfig {
    pub network: String, // "bitcoin", "testnet", "regtest"
    pub utxos: Vec<UtxoInput>,
    pub outputs: Vec<TransactionOutputDef>,
    pub fee_rate_sats_per_vb: u64,
    pub change_address: String,
    #[serde(default)]
    pub default_sequence: Option<u32>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UtxoInput {
    pub txid: String,
    pub vout: u32,
    pub script_pubkey_hex: String,
    pub value_sats: u64,
    pub private_key_wif: String,
    #[serde(default)]
    pub sequence: Option<u32>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransactionOutputDef {
    pub address: String,
    pub value_sats: u64,
}