use anyhow::Error;
use bitcoin::{
    key::rand::RngCore,
    secp256k1::{self},
    Network,
};
use key_manager::{
    errors::ConfigError, key_manager::KeyManager, keystorage::database::DatabaseKeyStore,
};
use std::{env, path::PathBuf, rc::Rc};
use storage_backend::storage::Storage;

use crate::graph::input::SighashType;

pub fn temp_storage() -> PathBuf {
    let dir = env::temp_dir();
    let mut rng = secp256k1::rand::thread_rng();
    let index = rng.next_u32();
    dir.join(format!("storage_{}.db", index))
}

pub fn new_key_manager() -> Result<Rc<KeyManager<DatabaseKeyStore>>, Error> {
    let network = Network::Regtest;
    let key_derivation_path = "m/101/1/0/0/";
    let keystore_path = "/tmp/storage.db";
    let keystore_password = "secret_password".as_bytes().to_vec();
    let path = PathBuf::from(format!("/tmp/store"));
    let store = Rc::new(Storage::new_with_path(&path).unwrap());

    let bytes =
        hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
    let key_derivation_seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidKeyDerivationSeed)?;

    let bytes =
        hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
    let winternitz_seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidWinternitzSeed)?;

    let database_keystore = DatabaseKeyStore::new(keystore_path, keystore_password, network)?;
    let key_manager = KeyManager::new(
        network,
        key_derivation_path,
        key_derivation_seed,
        winternitz_seed,
        database_keystore,
        store,
    )?;

    Ok(Rc::new(key_manager))
}

pub fn ecdsa_sighash_type() -> SighashType {
    SighashType::ecdsa_all()
}

pub fn taproot_sighash_type() -> SighashType {
    SighashType::taproot_all()
}