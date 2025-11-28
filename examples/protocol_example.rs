use std::{rc::Rc, str::FromStr};

use anyhow::Result;
use bitcoin::{Network, PublicKey, Txid};
use key_manager::{key_manager::KeyManager, key_store::KeyStore, winternitz::WinternitzType};
use protocol_builder::{
    builder::{Protocol, ProtocolBuilder},
    graph::graph::GraphOptions,
    scripts::{self, SignMode},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::OutputType,
    },
};
use storage_backend::{storage::Storage, storage_config::StorageConfig};

fn protocol_example(key_manager: Rc<KeyManager>) -> Result<Protocol> {
    let mut protocol = Protocol::new("protocol-demo");
    let builder = ProtocolBuilder {};

    // Keys used along the flow.
    let internal_key: PublicKey = key_manager.derive_keypair(0)?; // Taproot internal key (x-only)
    let exit_key: PublicKey = key_manager.derive_keypair(1)?; // Final recipient
    let external_key: PublicKey = key_manager.derive_keypair(2)?; // Matches the on-chain UTXO
    let participant_key_1: PublicKey = key_manager.derive_keypair(3)?; // Participant key to create MuSig2 aggregate key
    let participant_key_2: PublicKey = key_manager.derive_keypair(4)?; // Participant key to create MuSig2 aggregate key
    let participant_key_3: PublicKey = key_manager.derive_keypair(5)?; // Participant key to create MuSig2 aggregate key

    let aggregated_key = key_manager.new_musig2_session(
        [participant_key_1, participant_key_2, participant_key_3].to_vec(),
        participant_key_1,
    )?;

    // Winternitz key for the one-time authentication branch.
    let winternitz_key = key_manager.derive_winternitz(32, WinternitzType::SHA256, 0)?;

    // Taproot leaves showcasing each sign mode using the helper scripts.
    let skip_leaf = scripts::timelock(
        144,
        &internal_key,
        SignMode::Skip, // CSV-only branch that the builder skips signing
    );

    let single_leaf = scripts::verify_winternitz_signature(
        &internal_key,
        &winternitz_key,
        SignMode::Single, // one-time Winternitz authentication signed by the internal key
    )?;

    let aggregate_leaf = scripts::check_signature(
        &aggregated_key,
        SignMode::Aggregate, // aggregated MuSig2 enforcement branch
    );

    let taproot_leaves = vec![
        skip_leaf.clone(),
        single_leaf.clone(),
        aggregate_leaf.clone(),
    ];
    let taproot_sighash = SighashType::taproot_all();

    // 1. Anchor to an external P2WPKH UTXO already on-chain.
    let external_txid =
        Txid::from_str("9f19b05dc4b58b1e736b9f9fd49f8fb751fab6595e7f6b8b7fda19af2d3404f8")?;
    builder.add_external_connection(
        &mut protocol,
        "external_funding",
        external_txid,
        OutputSpec::Auto(OutputType::segwit_key(120_000, &external_key)?),
        "taproot_key_tx",
        InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
    )?;

    // 2. Build a Taproot output that will be spent via key path only.
    builder.add_taproot_connection(
        &mut protocol,
        "key_path_handoff",
        "taproot_key_tx",
        90_000,
        &internal_key,
        &taproot_leaves,
        &SpendMode::KeyOnly {
            key_path_sign: SignMode::Single,
        },
        "taproot_script_tx",
        &taproot_sighash,
    )?;

    // 3. The next transaction uses the script paths defined above.
    builder.add_taproot_connection(
        &mut protocol,
        "script_fanout",
        "taproot_script_tx",
        60_000,
        &internal_key,
        &taproot_leaves,
        &SpendMode::Scripts {
            leaves: vec![0, 1, 2],
        },
        "segwit_exit_tx",
        &taproot_sighash,
    )?;

    // 4. Attach a standard P2WPKH branch that pays a user and is later spent.
    builder.add_p2wpkh_connection(
        &mut protocol,
        "user_payout",
        "taproot_script_tx",
        25_000,
        &exit_key,
        "p2wpkh_spend_tx",
        &SighashType::ecdsa_all(),
    )?;

    // Final transaction sends aggregated funds to the recipient.
    builder.add_p2wpkh_output(&mut protocol, "segwit_exit_tx", 55_000, &exit_key)?;

    protocol.compute_minimum_output_values()?;
    Ok(protocol.build(&key_manager, "protocol-demo")?)
}

fn key_manager() -> Result<Rc<KeyManager>> {
    let storage_path = temp_storage();
    let store_path = "/tmp/key_manager_storage".to_string();

    let config_storage = StorageConfig::new(storage_path.clone(), None);
    let config_store = StorageConfig::new(store_path.clone(), Some("secret password_123__ABC".to_string()));

    let storage = Rc::new(Storage::new(&config_storage).unwrap());
    let keys_storage = Rc::new(Storage::new(&config_store).unwrap());
    let keystore = KeyStore::new(keys_storage);

    let key_derivation_seed = random_bytes();
    let winternitz_seed = random_bytes();

    let key_manager = KeyManager::new(
        Network::Regtest,
        "m/101/1/0/0/",
        Some(key_derivation_seed),
        Some(winternitz_seed),
        keystore,
        storage,
    )?;

    Ok(Rc::new(key_manager))
}

fn temp_storage() -> String {
    let dir = std::env::temp_dir();
    let mut rng = bitcoin::secp256k1::rand::thread_rng();
    let index = bitcoin::key::rand::RngCore::next_u32(&mut rng);
    dir.join(format!("storage_{}.db", index))
        .to_str()
        .unwrap()
        .to_string()
}

fn random_bytes() -> [u8; 32] {
    let mut seed = [0u8; 32];
    bitcoin::key::rand::RngCore::fill_bytes(&mut bitcoin::secp256k1::rand::thread_rng(), &mut seed);
    seed
}

fn main() -> Result<()> {
    // Initialize the key manager with a random mnemonic for demonstration purposes.
    let key_manager = key_manager()?;

    // Build the example protocol.
    let protocol = protocol_example(key_manager)?;

    // Print the resulting protocol graph as text and Graphviz dot format.
    println!("{}", protocol.visualize(GraphOptions::EdgeArrows)?);
    Ok(())
}
