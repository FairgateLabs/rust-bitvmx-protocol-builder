use std::{path::PathBuf, rc::Rc};

use anyhow::{Ok, Result};

use bitcoin::{
    hashes::Hash, secp256k1, Amount, EcdsaSighashType, PublicKey, ScriptBuf, TapSighashType,
    XOnlyPublicKey,
};
use clap::{Parser, Subcommand};
use key_manager::{
    create_database_key_store_from_config, create_key_manager_from_config, key_manager::KeyManager,
    keystorage::database::DatabaseKeyStore,
};
use storage_backend::storage::Storage;
use tracing::info;

use crate::{
    builder::ProtocolBuilder,
    config::Config,
    graph::{input::SighashType, output::OutputSpendingType},
    scripts::ProtocolScript,
    unspendable::unspendable_key,
};

pub struct Cli {
    pub config: Config,
}

#[derive(Parser)]
#[command(about = "Protocol Builder CLI", long_about = None)]
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

    BuildAndSign,

    ConnectWithExternalTransaction {
        #[arg(short, long, help = "Node to connect to")]
        to: String,

        #[arg(short, long, help = "Value of the output in satoshis")]
        value: u64,

        #[arg(short, long, help = "Key to be used in the script")]
        public_key: String,
    },

    AddP2WpkhOutput {
        #[arg(short, long, help = "Name of the Transaction")]
        transaction_name: String,

        #[arg(short, long, help = "Value of the output in satoshis")]
        value: u64,

        #[arg(short, long, help = "Key to be used in the script")]
        public_key: String,
    },

    AddSpeedupOutput {
        #[arg(short, long, help = "Name of the Transaction")]
        transaction_name: String,

        #[arg(short, long, help = "Value of the output in satoshis")]
        value: u64,

        #[arg(short, long, help = "Key to be used in the script")]
        public_key: String,
    },

    AddTaprootScriptSpendConnection {
        #[arg(short, long, help = "Node to connect from")]
        from: String,

        #[arg(short, long, help = "Value of the output in satoshis")]
        value: u64,

        #[arg(short, long, help = "Node to connect to")]
        to: String,

        #[arg(short, long, help = "Key to be used in the script")]
        public_key: String,
    },

    AddTimelockConnection {
        #[arg(short, long, help = "Node to connect from")]
        from: String,

        #[arg(short, long, help = "Value of the output in satoshis")]
        value: u64,

        #[arg(short, long, help = "Node to connect to")]
        to: String,

        #[arg(
            short,
            long,
            help = "Number of blocks to wait before spending the output"
        )]
        blocks: u16,

        #[arg(short, long, help = "Key to be used in the script")]
        public_key: String,
    },

    ConnectRounds {
        #[arg(short, long, help = "Number of rounds to connect")]
        rounds: u32,

        #[arg(short, long, help = "Node to connect from")]
        from: String,

        #[arg(short, long, help = "Node to connect to")]
        to: String,

        #[arg(short, long, help = "Value of the output in satoshis")]
        value: u64,

        #[arg(short, long, help = "Key to be used in the script")]
        public_key: String,
    },
}

impl Cli {
    pub fn new() -> Result<Self> {
        let config = Config::new()?;
        Ok(Self { config })
    }

    pub fn run(&self) -> Result<()> {
        let menu = Menu::parse();

        match &menu.command {
            Commands::Build => {
                self.build(&menu.protocol_name, menu.graph_storage_path)?;
            }
            Commands::BuildAndSign => {
                self.build_and_sign(&menu.protocol_name, menu.graph_storage_path)?;
            }
            Commands::ConnectWithExternalTransaction {
                to,
                value,
                public_key,
            } => {
                self.connect_with_external_transaction(
                    &menu.protocol_name,
                    menu.graph_storage_path,
                    to,
                    *value,
                    public_key,
                )?;
            }
            Commands::AddP2WpkhOutput {
                transaction_name,
                value,
                public_key,
            } => {
                self.add_p2wpkh_output(
                    &menu.protocol_name,
                    menu.graph_storage_path,
                    transaction_name,
                    *value,
                    public_key,
                )?;
            }
            Commands::AddSpeedupOutput {
                transaction_name,
                value,
                public_key,
            } => {
                self.add_speedup_output(
                    &menu.protocol_name,
                    menu.graph_storage_path,
                    transaction_name,
                    *value,
                    public_key,
                )?;
            }
            Commands::AddTaprootScriptSpendConnection {
                from,
                value,
                to,
                public_key,
            } => {
                self.add_taproot_script_spend_connection(
                    &menu.protocol_name,
                    menu.graph_storage_path,
                    from,
                    *value,
                    to,
                    public_key,
                )?;
            }
            Commands::AddTimelockConnection {
                from,
                value,
                to,
                blocks,
                public_key,
            } => {
                self.add_timelock_connection(
                    &menu.protocol_name,
                    menu.graph_storage_path,
                    from,
                    *value,
                    to,
                    *blocks,
                    public_key,
                )?;
            }
            Commands::ConnectRounds {
                rounds,
                from,
                to,
                value,
                public_key,
            } => {
                self.connect_rounds(
                    &menu.protocol_name,
                    menu.graph_storage_path,
                    *rounds,
                    from,
                    to,
                    *value,
                    public_key,
                )?;
            }
        }

        Ok(())
    }

    fn build(&self, protocol_name: &str, graph_storage_path: PathBuf) -> Result<()> {
        let storage = Rc::new(Storage::new_with_path(&graph_storage_path)?);
        let mut builder = ProtocolBuilder::new(protocol_name, storage)?;
        let key_manager = Rc::new(self.key_manager()?);
        builder.build(protocol_name, &key_manager)?;

        info!("Protocol {} built", protocol_name);
        Ok(())
    }

    fn build_and_sign(&self, protocol_name: &str, graph_storage_path: PathBuf) -> Result<()> {
        let storage = Rc::new(Storage::new_with_path(&graph_storage_path)?);
        let mut builder = ProtocolBuilder::new(protocol_name, storage)?;
        let key_manager = Rc::new(self.key_manager()?);
        builder.build_and_sign(&key_manager)?;

        info!("Protocol {} built and signed", protocol_name);

        Ok(())
    }

    fn connect_with_external_transaction(
        &self,
        protocol_name: &str,
        graph_storage_path: PathBuf,
        to: &str,
        value: u64,
        data: &str,
    ) -> Result<()> {
        let storage = Rc::new(Storage::new_with_path(&graph_storage_path)?);
        let mut builder = ProtocolBuilder::new(protocol_name, storage)?;
        let txid = Hash::all_zeros();
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let output_index = 0;
        let pubkey_bytes = hex::decode(data).expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_spending_type =
            OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

        builder.connect_with_external_transaction(
            txid,
            output_index,
            output_spending_type,
            to,
            &ecdsa_sighash_type,
        )?;

        info!(
            "Connected Protocol {} with external transaction '{}'",
            protocol_name, to
        );
        Ok(())
    }

    fn add_p2wpkh_output(
        &self,
        protocol_name: &str,
        graph_storage_path: PathBuf,
        transaction_name: &str,
        value: u64,
        data: &str,
    ) -> Result<()> {
        let storage = Rc::new(Storage::new_with_path(&graph_storage_path)?);
        let mut builder = ProtocolBuilder::new(protocol_name, storage)?;
        let pubkey_bytes = hex::decode(data).expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        builder.add_p2wpkh_output(transaction_name, value, &public_key)?;

        info!("Added P2WPKH output to Protocol {}", protocol_name);
        Ok(())
    }

    fn add_speedup_output(
        &self,
        protocol_name: &str,
        graph_storage_path: PathBuf,
        transaction_name: &str,
        value: u64,
        data: &str,
    ) -> Result<()> {
        let storage = Rc::new(Storage::new_with_path(&graph_storage_path)?);
        let mut builder = ProtocolBuilder::new(protocol_name, storage)?;
        let pubkey_bytes = hex::decode(data).expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        builder.add_speedup_output(transaction_name, value, &public_key)?;

        info!("Added Speedup output to Protocol {}", protocol_name);
        Ok(())
    }

    fn add_taproot_script_spend_connection(
        &self,
        protocol_name: &str,
        graph_storage_path: PathBuf,
        from: &str,
        value: u64,
        to: &str,
        data: &str,
    ) -> Result<()> {
        let storage = Rc::new(Storage::new_with_path(&graph_storage_path)?);
        let mut builder = ProtocolBuilder::new(protocol_name, storage)?;
        let mut rng = secp256k1::rand::thread_rng();
        let internal_key = XOnlyPublicKey::from(unspendable_key(&mut rng)?);
        let pubkey_bytes = hex::decode(data).expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key);
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        builder.add_taproot_script_spend_connection(
            "protocol",
            from,
            value,
            &internal_key,
            &[script.clone()],
            to,
            &sighash_type,
        )?;

        info!(
            "Added Taproot script spend connection to Protocol {}",
            protocol_name
        );
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn add_timelock_connection(
        &self,
        protocol_name: &str,
        graph_storage_path: PathBuf,
        from: &str,
        value: u64,
        to: &str,
        blocks: u16,
        data: &str,
    ) -> Result<()> {
        let storage = Rc::new(Storage::new_with_path(&graph_storage_path)?);
        let mut builder = ProtocolBuilder::new(protocol_name, storage)?;
        let mut rng = secp256k1::rand::thread_rng();
        let internal_key = XOnlyPublicKey::from(unspendable_key(&mut rng)?);
        let pubkey_bytes = hex::decode(data).expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let expired_from = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key);
        let renew_from = ProtocolScript::new(ScriptBuf::from(vec![0x01]), &public_key);
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        builder.add_timelock_connection(
            from,
            value,
            &internal_key,
            &expired_from,
            &renew_from,
            to,
            blocks,
            &sighash_type,
        )?;

        info!("Added Timelock connection to Protocol {}", protocol_name);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn connect_rounds(
        &self,
        protocol_name: &str,
        graph_storage_path: PathBuf,
        rounds: u32,
        from: &str,
        to: &str,
        value: u64,
        data: &str,
    ) -> Result<()> {
        let storage = Rc::new(Storage::new_with_path(&graph_storage_path)?);
        let mut builder = ProtocolBuilder::new(protocol_name, storage)?;
        let pubkey_bytes = hex::decode(data).expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key);
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        builder.connect_rounds(
            "rounds",
            rounds,
            from,
            to,
            value,
            &XOnlyPublicKey::from(public_key),
            &[script.clone()],
            &[script.clone()],
            &sighash_type,
        )?;

        info!(
            "Connected rounds from '{}' to '{}' in Protocol {}",
            from, to, protocol_name
        );
        Ok(())
    }

    fn key_manager(&self) -> Result<KeyManager<DatabaseKeyStore>> {
        let keystore = create_database_key_store_from_config(
            &self.config.key_storage,
            &self.config.key_manager.network,
        )?;

        // TODO read from config
        let path = PathBuf::from("/tmp/store".to_string());
        let store = Rc::new(Storage::new_with_path(&path).unwrap());

        Ok(create_key_manager_from_config(
            &self.config.key_manager,
            keystore,
            store,
        )?)
    }
}
