use anyhow::{Ok, Result};

use bitcoin::{hashes::Hash, Network, ScriptBuf};
use clap::{Parser, Subcommand};
use key_manager::{key_manager::KeyManager, keystorage::database::DatabaseKeyStore};
use tracing::info;

use std::env;
use bitcoin::secp256k1::rand::{self, RngCore};
use crate::{builder::TemplateBuilder, config::Config, params::DefaultParams};

pub struct Cli {
    config: Config,
}

#[derive(Parser)]
#[command(about = "Template Builder CLI", long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Menu {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    AddStartTemplate,
}

impl Cli {
    pub fn new() -> Result<Self> {
        let config = Config::new()?;
        Ok(Self {
            config,
        })
    }

    pub fn run(&self) -> Result<()> {
        let menu = Menu::parse();

        match &menu.command {
            Commands::AddStartTemplate => {
                self.add_start_template()?;
            }
        }

        Ok(())
    }

    // 
    // Commands
    //
    fn add_start_template(&self) -> Result<()>{
        let defaults = DefaultParams::try_from(&self.config)?;
        let mut builder = TemplateBuilder::new(defaults)?;
        let mut key_manager = self.key_manager()?;
        
        // TODO test values, replace for real values from command line params.
        let pk = key_manager.derive_keypair(0)?;
        let wpkh = pk.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);
        let txid= Hash::all_zeros();
        let vout = 0;
        let amount = 100000;

        builder.add_start("A", txid, vout, amount, script_pubkey)?;

        info!("New start template created.");

        Ok(())
    }
    
    fn key_manager(&self) -> Result<KeyManager<DatabaseKeyStore>> {
        let network = self.config.key_manager.network.parse::<Network>()?;

        let key_derivation_path = self.config.key_manager.key_derivation_path.as_str(); 
        let key_derivation_seed: [u8; 32] = self.config.key_manager.key_derivation_seed.as_bytes().try_into()?;
        let winternitz_seed = self.config.key_manager.winternitz_seed.as_bytes().try_into()?;

        let keystore_path = self.config.storage.path.as_str();
        let keystore_password = self.config.storage.password.as_bytes().to_vec();

        let database_keystore = DatabaseKeyStore::new(keystore_path, keystore_password, network)?;
        let key_manager = KeyManager::new(
            network,
            key_derivation_path,
            key_derivation_seed,
            winternitz_seed,
            database_keystore,
        )?;
    
        Ok(key_manager)
    }
}

fn temp_storage_path() -> String {
    let dir = env::temp_dir();

    let storage_path = dir.join(format!("secure_storage_{}.db", random_u32()));
    storage_path.to_str().expect("Failed to get path to temp file").to_string()
}

fn random_u32() -> u32 {
    rand::thread_rng().next_u32()
}


