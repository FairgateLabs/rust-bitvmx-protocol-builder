use std::str::FromStr;

use anyhow::{Ok, Result};

use bitcoin::{PublicKey, TapSighashType};
use clap::{Parser, Subcommand};
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
    NewTemplateBuilder,
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
            Commands::NewTemplateBuilder => {
                self.create_builder()?;
            }
        }

        Ok(())
    }

    // 
    // Commands
    //
    fn create_builder(&self) -> Result<()>{
        let protocol_amount = self.config.template_builder.protocol_amount;
        let speedup_from_key = PublicKey::from_str(self.config.template_builder.speedup_from_key.as_str())?;
        let speedup_to_key = PublicKey::from_str(self.config.template_builder.speedup_to_key.as_str())?;
        let speedup_amount = self.config.template_builder.speedup_amount;
        let timelock_blocks = self.config.template_builder.timelock_blocks;
        let timelock_from_key = PublicKey::from_str(self.config.template_builder.timelock_from_key.as_str())?;
        let timelock_to_key = PublicKey::from_str(self.config.template_builder.timelock_to_key.as_str())?;
        let locked_amount = self.config.template_builder.locked_amount;
        let sighash_type = TapSighashType::from_str(self.config.template_builder.sighash_type.as_str())?;
    
        let defaults = DefaultParams::new(
            protocol_amount, 
            &speedup_from_key, 
            &speedup_to_key, 
            speedup_amount, 
            timelock_blocks, 
            &timelock_from_key, 
            &timelock_to_key, 
            locked_amount, 
            sighash_type
        )?;

        let mut builder = TemplateBuilder::new(defaults)?;

        builder.add_start(
            "A", 
        )?;

        info!("New template builder created.");

        Ok(())
    }

    // fn key_manager(network: Network) -> Result<KeyManager<DatabaseKeyStore>> {
    //     let keystore_path = Self::temp_storage_path();
    //     let keystore_password = b"secret password".to_vec(); 
    //     let key_derivation_path: &str = "m/101/1/0/0/";
    //     let key_derivation_seed = Self::random_bytes();
    //     let winternitz_seed = Self::random_bytes();

    //     let database_keystore = DatabaseKeyStore::new(keystore_path, keystore_password, network)?;
    //     let key_manager = KeyManager::new(
    //         network,
    //         key_derivation_path,
    //         key_derivation_seed,
    //         winternitz_seed,
    //         database_keystore,
    //     )?;
    
    //     Ok(key_manager)
    // }

    // fn random_bytes() -> [u8; 32] {
    //     let mut seed = [0u8; 32];
    //     secp256k1::rand::thread_rng().fill_bytes(&mut seed);
    //     seed
    // }

    // fn random_u32() -> u32 {
    //     secp256k1::rand::thread_rng().next_u32()
    // }

    // fn temp_storage_path() -> String {
    //     let dir = env::temp_dir();

    //     let storage_path = dir.join(format!("secure_storage_{}.db", Self::random_u32()));
    //     storage_path.to_str().expect("Failed to get path to temp file").to_string()
    // }
}

