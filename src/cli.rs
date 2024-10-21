use std::path::PathBuf;

use anyhow::{Ok, Result};

use bitcoin::{hashes::Hash, secp256k1, Amount, EcdsaSighashType, PublicKey, ScriptBuf, TapSighashType, XOnlyPublicKey};
use clap::{Parser, Subcommand};

use crate::{builder::ProtocolBuilder, config::Config, graph::{OutputSpendingType, SighashType}, scripts::ProtocolScript, unspendable::unspendable_key};

pub struct Cli {
    config: Config,
}

#[derive(Parser)]
#[command(about = "Template Builder CLI", long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Menu {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, help = "Name of the protocol")]
    protocol_name: String,

    #[arg(short, long, help = "Path to the graph storage file")]
    graph_storage_path: PathBuf,

}

#[derive(Subcommand)]
enum Commands {
    Build,

    ConnectWithExternalTransaction{
        #[arg(short, long, help = "Node to connect to")]
        to: String,
    },

    AddP2WpkhOutput{
        #[arg(short, long, help = "Name of the Transaction")]
        transaction_name: String,
        
        #[arg(short, long, help = "Value of the output in satoshis")]
        value: u64,
    },

    AddSpeedupOutput{
        #[arg(short, long, help = "Name of the Transaction")]
        transaction_name: String,
        
        #[arg(short, long, help = "Value of the output in satoshis")]
        value: u64,
    },

    AddTaprootScriptSpendConnection{
        #[arg(short, long, help = "Node to connect from")]
        from: String, 

        #[arg(short, long, help = "Value of the output in satoshis")]
        value: u64,

        #[arg(short, long, help = "Node to connect to")]
        to: String,
    },

    AddTimelockConnection{
        #[arg(short, long, help = "Node to connect from")]
        from: String,

        #[arg(short, long, help = "Value of the output in satoshis")] 
        value: u64, 

        #[arg(short, long, help = "Node to connect to")]
        to: String,

        #[arg(short, long, help = "Number of blocks to wait before spending the output")]
        blocks: u16,
    },

    ConnectRounds{
        #[arg(short, long, help = "Number of rounds to connect")]
        rounds: u32,

        #[arg(short, long, help = "Node to connect from")]
        from: String,

        #[arg(short, long, help = "Node to connect to")]
        to: String,

        #[arg(short, long, help = "Value of the output in satoshis")]
        value: u64,
    }
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
            Commands::Build => {
                self.build(&menu.protocol_name, menu.graph_storage_path)?;
            }
            Commands::ConnectWithExternalTransaction{to} => {
                self.connect_with_external_transaction(&menu.protocol_name, menu.graph_storage_path, to)?;
            }
            Commands::AddP2WpkhOutput{transaction_name,value} => {
                self.add_p2wpkh_output(&menu.protocol_name, menu.graph_storage_path, transaction_name, *value)?;
            }
            Commands::AddSpeedupOutput{transaction_name,value} => {
                self.add_speedup_output(&menu.protocol_name, menu.graph_storage_path, transaction_name, *value)?;
            }
            Commands::AddTaprootScriptSpendConnection{from, value, to} => {
                self.add_taproot_script_spend_connection(&menu.protocol_name, menu.graph_storage_path, from, *value, to)?;
            }
            Commands::AddTimelockConnection{from, value, to, blocks} => {
                self.add_timelock_connection(&menu.protocol_name, menu.graph_storage_path, from, *value, to, *blocks)?;
            }
            Commands::ConnectRounds{rounds, from, to, value} => {
                self.connect_rounds(&menu.protocol_name, menu.graph_storage_path, *rounds, from, to, *value)?;
            }
        }

        Ok(())
    }

    fn build(&self, protocol_name: &str, graph_storage_path: PathBuf) -> Result<()> {
        let mut builder = ProtocolBuilder::new(protocol_name, graph_storage_path)?;
        builder.build()?;
        Ok(())
    }

    fn connect_with_external_transaction(&self, protocol_name: &str, graph_storage_path: PathBuf, to: &str) -> Result<()> {
        let mut builder = ProtocolBuilder::new(protocol_name, graph_storage_path)?;
        let txid = Hash::all_zeros();
        let value = 1000;
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let output_index = 0;
        let pubkey_bytes = hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd").expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_spending_type = OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

        builder.connect_with_external_transaction(txid,output_index, output_spending_type, to, &ecdsa_sighash_type)?;
        Ok(())
    }

    fn add_p2wpkh_output(&self, protocol_name: &str, graph_storage_path: PathBuf, transaction_name: &str, value: u64) -> Result<()> {
        let mut builder = ProtocolBuilder::new(protocol_name, graph_storage_path)?;
        let pubkey_bytes = hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd").expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        builder.add_p2wpkh_output(transaction_name, value, &public_key)?;
        Ok(())
    }

    fn add_speedup_output(&self, protocol_name: &str, graph_storage_path: PathBuf, transaction_name: &str, value: u64) -> Result<()> {
        let mut builder = ProtocolBuilder::new(protocol_name, graph_storage_path)?;
        let pubkey_bytes = hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd").expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        builder.add_speedup_output(transaction_name, value,&public_key)?;
        Ok(())
    }

    fn add_taproot_script_spend_connection(&self, protocol_name: &str, graph_storage_path: PathBuf, from: &str, value: u64, to: &str) -> Result<()> {
        let mut builder = ProtocolBuilder::new(protocol_name, graph_storage_path)?;
        let mut rng = secp256k1::rand::thread_rng();
        let internal_key = XOnlyPublicKey::from(unspendable_key(&mut rng)?);
        let pubkey_bytes = hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd").expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key);
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        builder.add_taproot_script_spend_connection("protocol", from, value, &internal_key, &[script.clone()], to, &sighash_type)?;
        Ok(())
    }

    fn add_timelock_connection(&self, protocol_name: &str, graph_storage_path: PathBuf, from: &str, value: u64, to: &str, blocks: u16) -> Result<()> {
        let mut builder = ProtocolBuilder::new(protocol_name, graph_storage_path)?;
        let mut rng = secp256k1::rand::thread_rng();
        let internal_key = XOnlyPublicKey::from(unspendable_key(&mut rng)?);
        let pubkey_bytes = hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd").expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let expired_from = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key);
        let renew_from = ProtocolScript::new(ScriptBuf::from(vec![0x01]), &public_key);
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        builder.add_timelock_connection( from, value, &internal_key, &expired_from, &renew_from, to, blocks, &sighash_type)?;
        Ok(())
    }

    fn connect_rounds(&self, protocol_name: &str, graph_storage_path: PathBuf, rounds: u32, from: &str, to: &str, value: u64) -> Result<()> {
        let mut builder = ProtocolBuilder::new(protocol_name, graph_storage_path)?;
        let pubkey_bytes = hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd").expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key);
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        builder.connect_rounds("rounds", rounds, from, to, value, &[script.clone()], &[script.clone()], &sighash_type)?;
        Ok(())
    }
}
