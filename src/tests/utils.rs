use anyhow::Error;
use bitcoin::{
    key::rand::RngCore,
    secp256k1::{self},
    Network,
};
use key_manager::{errors::ConfigError, key_manager::KeyManager, key_store::KeyStore};
use std::{env, fs, path::PathBuf, rc::Rc};
use storage_backend::{storage::Storage, storage_config::StorageConfig};

use crate::types::input::SighashType;

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

pub struct TestContext {
    test_dir: TemporaryDir,
    key_manager: Rc<KeyManager>,
    _network: Network,
}

impl TestContext {
    pub fn new(test_context_path_prefix: &str) -> Result<Self, Error> {
        let network = Network::Regtest;
        let test_dir = TemporaryDir::new(test_context_path_prefix);
        let key_manager = new_key_manager(network, test_context_path_prefix)?;

        Ok(Self {
            test_dir,
            key_manager,
            _network: network,
        })
    }

    pub fn ecdsa_sighash_type(&self) -> SighashType {
        SighashType::ecdsa_all()
    }

    pub fn tr_sighash_type(&self) -> SighashType {
        SighashType::taproot_all()
    }

    pub fn key_manager(&self) -> &Rc<KeyManager> {
        &self.key_manager
    }

    pub fn new_storage(&self, name: &str) -> Storage {
        let path = self.test_dir.path(name).to_str().unwrap().to_string();
        let config = StorageConfig::new(path, None);
        Storage::new(&config).unwrap()
    }
}

pub fn new_key_manager(network: Network, path_prefix: &str) -> Result<Rc<KeyManager>, Error> {
    let test_dir = TemporaryDir::new(path_prefix);
    let keystore_path = test_dir.path("keystore");
    let musig2_path = test_dir.path("musig2data");

    let key_derivation_path = "m/101/1/0/0/";
    let keystore_password = "secret_password".to_string();
    let config = StorageConfig::new(musig2_path.to_str().unwrap().to_string(), None);
    let store: Rc<Storage> = Rc::new(Storage::new(&config).unwrap());

    let bytes = hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
    let key_derivation_seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidKeyDerivationSeed)?;

    let bytes = hex::decode("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")?;
    let winternitz_seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidWinternitzSeed)?;

    let config = StorageConfig::new(
        keystore_path.to_str().unwrap().to_string(),
        Some(keystore_password),
    );
    let storage_keystore = Rc::new(Storage::new(&config)?);
    let database_keystore = KeyStore::new(storage_keystore);
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
