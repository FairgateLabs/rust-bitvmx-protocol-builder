use std::path::PathBuf;

use anyhow::{Ok, Result};

use bitcoin::{hashes::Hash, Network, ScriptBuf};
use clap::{Parser, Subcommand};
use key_manager::{key_manager::KeyManager, keystorage::database::DatabaseKeyStore, winternitz::WinternitzType};
use storage_backend::storage::Storage;
use tracing::info;

use crate::{builder::TemplateBuilder, config::Config, params::DefaultParams, scripts};

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
    AddStartTemplate{
        #[clap(short, long, help = "Name of the template")]
        name: String,
        
        #[clap(short, long, help = "Amount in satoshis")]
        amount: u64,

        #[clap(short, long, help = "")]
        index: u32,

        #[clap(short, long, help = "")]
        vout: u32,
    },

    AddConnectionTemplate{
        #[clap(short, long, help = "Name of the node you are connecting from")]
        from: String,

        #[clap(short, long, help = "Name of the node you are connecting to")]
        to: String,

        #[clap(short, long, help = "Path to store the spending scripts", default_value = "spending_scripts.db")]
        storage_path: PathBuf,
    },

    AddRoundsTemplate{
        #[clap(short, long, help = "Name of the node you are connecting from")]
        from: String,

        #[clap(short, long, help = "Name of the node you are connecting to")]
        to: String,

        #[clap(short, long, help = "")]
        rounds: u32,

        #[clap(short, long, help = "Path to store the spending scripts you are connecting from")]
        storage_path_from: PathBuf,

        #[clap(short, long, help = "Path to store the spending scripts you are connecting to")]
        storage_path_to: PathBuf,
    },

    CreateSpendingScripts{
        #[clap(short, long, help = "Number of spending scripts to create")]
        count: u32,

        #[clap(short, long, help = "Path to store the spending scripts", default_value = "spending_scripts.db")]
        storage_path: PathBuf,
    },

    EndTransactionTemplate{
        #[clap(short, long, help = "Name of the template")]
        name: String,

        #[clap(short, long, help = "Amount in satoshis")]
        amount: u64,

        #[clap(short, long, help = "Path to store the spending scripts", default_value = "spending_scripts.db")]
        storage_path: PathBuf,
    },

    FinalizeAndBuildTemplate,
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
            Commands::AddStartTemplate{name, amount, index, vout} => {
                self.add_start_template(name, *amount, *index, *vout)?;
            }
            Commands::AddConnectionTemplate{from, to, storage_path} => {
                self.add_connection_template(from, to, storage_path)?;
            }
            Commands::AddRoundsTemplate{from, to, rounds, storage_path_from, storage_path_to} => {
                self.add_rounds_template(from, to, *rounds, storage_path_from, storage_path_to)?;
            }
            Commands::CreateSpendingScripts{count, storage_path} => {
                self.create_spending_scripts(*count, storage_path)?;
            }
            Commands::EndTransactionTemplate{name, amount, storage_path} => {
                self.end_transaction_template(name, *amount, storage_path)?;
            }
            Commands::FinalizeAndBuildTemplate => {
                self.finalize_and_build_template()?;
            }
        }

        Ok(())
    }

    // 
    // Commands
    //
    fn add_start_template(&self, name: &str, amount: u64, index: u32, vout: u32) -> Result<()>{
        let defaults = DefaultParams::try_from(&self.config)?;
        let mut builder = TemplateBuilder::new(defaults)?;
        let mut key_manager = self.key_manager()?;
        
        // TODO test values, replace for real values from command line params.
        let pk = key_manager.derive_keypair(index)?;
        let wpkh = pk.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);
        let txid= Hash::all_zeros();

        builder.add_start(name, txid, vout, amount, script_pubkey)?;

        info!("New start template created.");

        Ok(())
    }

    fn add_connection_template(&self, from: &str, to: &str, storage_path: &PathBuf) -> Result<()> {
        let defaults = DefaultParams::try_from(&self.config)?;
        let mut builder = TemplateBuilder::new(defaults)?;
        let mut spending_scripts_vec = Vec::new();

        let storage = Storage::new_with_path(storage_path)?;
        let spending_scripts = storage.partial_compare("script_")?;
        for (_, script) in spending_scripts {
            let script: scripts::ScriptWithParams = serde_json::from_str(&script)?;
            spending_scripts_vec.push(script);
        }

        builder.add_connection(from, to, &spending_scripts_vec)?;

        info!("A connection from template {} to template {} has been created.", from, to);

        Ok(())
    }

    fn add_rounds_template(&self, from: &str, to: &str, rounds: u32, storage_path_from: &PathBuf, storage_path_to: &PathBuf) -> Result<()> {
        let defaults = DefaultParams::try_from(&self.config)?;
        let mut builder = TemplateBuilder::new(defaults)?;
        let spending_scripts_from = obtain_spending_scripts_from_storage(storage_path_from)?;
        let spending_scripts_to = obtain_spending_scripts_from_storage(storage_path_to)?;

        let (rounds_from, rounds_to) = builder.add_rounds( rounds, from, to, &spending_scripts_from, &spending_scripts_to)?;

        info!("A template from '{}' to '{}' with {} rounds has been created.", rounds_from, rounds_to, rounds);

        Ok(())
    }

    fn create_spending_scripts(&self, count: u32, storage_path: &PathBuf) -> Result<()> {
        let mut key_manager = self.key_manager()?;
        let storage = Storage::new_with_path(storage_path)?;

        for i in 0..count {
            let pk = key_manager.derive_winternitz(4, WinternitzType::SHA256, i)?;
            let name = &format!("script_{}", i);
            let script = scripts::verify_single_value(name, &pk);
            storage.write(name, &serde_json::to_string(&script)?)?;
        }
        
        info!("{} spending scripts created and saved in {}.", count, storage_path.display());

        Ok(())
    }

    fn end_transaction_template(&self,name: &str, amount: u64, storage_path: &PathBuf) -> Result<()> {
        let defaults = DefaultParams::try_from(&self.config)?;
        let mut builder = TemplateBuilder::new(defaults)?;
        
        let spending_scripts = obtain_spending_scripts_from_storage(storage_path)?;

        builder.end(name, amount, &spending_scripts)?;

        info!("End transaction template created.");

        Ok(())
    }

    fn finalize_and_build_template(&self) -> Result<()> {
        let defaults = DefaultParams::try_from(&self.config)?;
        let mut builder = TemplateBuilder::new(defaults)?;
        let templates = builder.finalize_and_build()?;

        info!("Templates built: {:?}", templates);

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

fn obtain_spending_scripts_from_storage(storage_path: &PathBuf) -> Result<Vec<scripts::ScriptWithParams>, anyhow::Error> {
    let mut spending_scripts_vec = Vec::new();
    let storage = Storage::open(storage_path)?;
    let spending_scripts = storage.partial_compare("script_")?;
    for (_, script) in spending_scripts {
        let script: scripts::ScriptWithParams = serde_json::from_str(&script)?;
        spending_scripts_vec.push(script);
    }
    Ok(spending_scripts_vec)
}


