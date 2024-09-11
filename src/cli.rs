use std::str::FromStr;

use anyhow::{Ok, Result};

use bitcoin::{hashes::Hash, EcdsaSighashType, Network, PublicKey, ScriptBuf, TapSighashType};
use clap::{Parser, Subcommand};
use key_manager::{key_manager::KeyManager, keystorage::database::DatabaseKeyStore};
use tracing::info;

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
        let defaults = self.get_defaults_from_config()?;
        
        let mut key_manager = self.key_manager()?;

        // TODO test values, replace for real values from command line params.
        let pk = key_manager.derive_keypair(0)?;
        let wpkh = pk.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);
        let txid= Hash::all_zeros();
        let vout = 0;
        let amount = 100000;

        let mut builder = TemplateBuilder::new(defaults)?;

        builder.add_start("A", txid, vout, amount, script_pubkey)?;

        info!("New start template created.");

        Ok(())
    }

    fn get_defaults_from_config(&self) -> Result<DefaultParams, anyhow::Error> {
        let protocol_amount = self.config.template_builder.protocol_amount;
        let speedup_from_key = PublicKey::from_str(self.config.template_builder.speedup_from_key.as_str())?;
        let speedup_to_key = PublicKey::from_str(self.config.template_builder.speedup_to_key.as_str())?;
        let speedup_amount = self.config.template_builder.speedup_amount;
        let timelock_blocks = self.config.template_builder.timelock_blocks;
        let timelock_from_key = PublicKey::from_str(self.config.template_builder.timelock_from_key.as_str())?;
        let timelock_to_key = PublicKey::from_str(self.config.template_builder.timelock_to_key.as_str())?;
        let locked_amount = self.config.template_builder.locked_amount;
        let ecdsa_sighash_type = EcdsaSighashType::from_str(self.config.template_builder.ecdsa_sighash_type.as_str())?;
        let taproot_sighash_type = TapSighashType::from_str(self.config.template_builder.taproot_sighash_type.as_str())?;
       
        let defaults = DefaultParams::new(
            protocol_amount, 
            &speedup_from_key, 
            &speedup_to_key, 
            speedup_amount, 
            timelock_blocks, 
            &timelock_from_key, 
            &timelock_to_key, 
            locked_amount, 
            ecdsa_sighash_type,
            taproot_sighash_type,
        )?;
        Ok(defaults)
    }
    
    fn key_manager(&self) -> Result<KeyManager<DatabaseKeyStore>> {
        let network = self.config.key_manager.network.parse::<Network>()?;

        let key_derivation_path = self.config.key_manager.key_derivation_path.as_str(); 
        let key_derivation_seed = self.config.key_manager.key_derivation_seed.as_bytes().try_into()?;
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

