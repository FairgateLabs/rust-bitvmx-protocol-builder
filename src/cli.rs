use anyhow::{Ok, Result};

use bitcoin::{hashes::Hash, Amount, EcdsaSighashType, PublicKey, ScriptBuf};
use clap::{Parser, Subcommand};
use tracing::info;

use crate::{builder::Builder, config::Config, graph::{OutputSpendingType, SighashType}, scripts::ScriptWithKeys};

pub struct Cli {
    pub config: Config,
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
        // TODO test values, replace for real values from command line params.
        let sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let pubkey_bytes = hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd").expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ScriptWithKeys::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_spending_type = OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let mut builder = Builder::new("single_connection"); 
        let protocol = builder.connect_with_external_transaction(txid, output_index, output_spending_type, "start", &sighash_type)?
            .build()?;

        info!("New protocol {0} created.", protocol.get_name());

        Ok(())
    }
}
