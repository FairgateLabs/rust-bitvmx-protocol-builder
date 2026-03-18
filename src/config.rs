use bitvmx_bitcoin_rpc::rpc_config::RpcConfig;
use key_manager::config::KeyManagerConfig;
use serde::Deserialize;
use storage_backend::storage_config::StorageConfig;
use tracing::{info};

use crate::errors::ConfigError;

#[derive(Debug, Deserialize)]
pub struct ProtocolBuilderConfig {
    pub protocol_amount: u64,
    pub speedup_amount: u64,
    pub locked_amount: u64,
    pub locked_blocks: u16,
    pub ecdsa_sighash_type: String,
    pub taproot_sighash_type: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub rpc: RpcConfig,
    pub builder: ProtocolBuilderConfig,
    pub key_manager: KeyManagerConfig,
    pub key_storage: StorageConfig,
}

impl Config {
    pub fn new(config: Option<String>) -> Result<Config, ConfigError> {
        match config {
            Some(config) => {
                info!("Using configuration: {}", config);
                Ok(bitvmx_settings::settings::load_config_file::<Config>(
                    Some(config),
                )?)
            }
            None => Ok(bitvmx_settings::settings::load::<Config>()?),
        }
    }
}
