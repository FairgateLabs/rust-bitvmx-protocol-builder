use config as settings;
use key_manager::config::{KeyManagerConfig, StorageConfig};
use serde::Deserialize;
use tracing::warn;
use std::env;

use crate::errors::ConfigError;

static DEFAULT_ENV: &str = "development";
static CONFIG_PATH: &str = "config";

#[derive(Debug, Deserialize)]
pub struct TemplateBuilderConfig {
    pub protocol_amount: u64,
    pub speedup_from_key: String,
    pub speedup_to_key: String,
    pub speedup_amount: u64,
    pub timelock_from_key: String,
    pub timelock_to_key: String,
    pub timelock_renew_key: String,
    pub locked_amount: u64,
    pub locked_blocks: u16,
    pub ecdsa_sighash_type: String,
    pub taproot_sighash_type: String,
    pub graph_path: String,
}

#[derive(Debug, Deserialize)]
pub struct RpcConfig {
    pub network: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub wallet: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)] // enforce strict field compliance
pub struct Config {
    pub rpc: RpcConfig,
    pub template_builder: TemplateBuilderConfig,
    pub key_manager: KeyManagerConfig,
    pub storage: StorageConfig,
}

impl Config {
    pub fn new() -> Result<Config, ConfigError> {
        let env = Config::get_env();
        Config::parse_config(env)
    }

    fn get_env() -> String {
        env::var("BITVMX_ENV")
            .unwrap_or_else(|_| {
                let default_env = DEFAULT_ENV.to_string();
                warn!("BITVMX_ENV not set. Using default environment: {}", default_env);
                default_env
            }
        )
    }

    fn parse_config(env: String) -> Result<Config, ConfigError> {
        let config_path = format!("{}/{}.json", CONFIG_PATH, env);

        let settings = settings::Config::builder()
            .add_source(config::File::with_name(&config_path))
            .build()
            .map_err(ConfigError::ConfigFileError)?;

        settings.try_deserialize::<Config>()
            .map_err(ConfigError::ConfigFileError)
    }
}
