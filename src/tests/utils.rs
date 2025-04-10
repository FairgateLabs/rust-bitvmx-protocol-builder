use anyhow::Error;
use bitcoin::{
    key::rand::RngCore,
    secp256k1::{self},
    Network,
};
use key_manager::{
    errors::ConfigError, key_manager::KeyManager, keystorage::database::DatabaseKeyStore,
};
use std::{env, fs, path::PathBuf, rc::Rc};
use storage_backend::storage::Storage;

use crate::types::input::SighashType;

pub fn new_key_manager(
    keystore_path: PathBuf,
    musig2_path: PathBuf,
) -> Result<Rc<KeyManager<DatabaseKeyStore>>, Error> {
    let network = Network::Regtest;
    let key_derivation_path = "m/101/1/0/0/";
    let keystore_password = "secret_password".as_bytes().to_vec();
    let store = Rc::new(Storage::new_with_path(&musig2_path).unwrap());

    let bytes = hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
    let key_derivation_seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidKeyDerivationSeed)?;

    let bytes = hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
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

pub fn clear_test_directories() {
    let temp_base = env::temp_dir();
    let root_dir = temp_base.join("key_manager");

    if root_dir.exists() {
        let _ = fs::remove_dir_all(&root_dir);
    }
}

pub fn ecdsa_sighash_type() -> SighashType {
    SighashType::ecdsa_all()
}

pub fn taproot_sighash_type() -> SighashType {
    SighashType::taproot_all()
}
pub struct TemporaryDir {
    pub path: PathBuf,
}

impl TemporaryDir {
    /// Create a new test directory structure
    pub fn new(test_prefix: &str) -> Self {
        let temp_base = env::temp_dir();
        let mut rng = secp256k1::rand::thread_rng();
        let random_id = rng.next_u32();
        let temp_path = temp_base.join(format!("{}_{}", test_prefix, random_id));
        fs::create_dir_all(&temp_path).expect("Failed to create temp directory");

        Self { path: temp_path }
    }

    /// Get a path inside the test subdir
    pub fn path(&self, relative: &str) -> PathBuf {
        self.path.join(relative)
    }
}

// Optional: clean up the temporary directory when done (after all tests)
impl Drop for TemporaryDir {
    fn drop(&mut self) {
        // Clean up the entire root dir, including all test subdirs
        if self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
