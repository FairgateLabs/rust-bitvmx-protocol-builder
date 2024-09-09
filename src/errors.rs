use bitcoin::{key::UncompressedPublicKeyError, sighash::TaprootError, taproot::TaprootBuilderError};
use key_manager::errors::KeyManagerError;
use storage_backend::error::StorageError;
use thiserror::Error;

use config as settings;

#[derive(Error, Debug)]
pub enum TemplateBuilderError {
    #[error("Failed to build template")]
    FailedToBuildTemplate(#[from] TemplateError),

    #[error("Template `{0}` not found")]
    MissingTemplate(String),

    #[error("Template `{0}` already exists")]
    TemplateAlreadyExists(String),

    #[error("Cannot end `{0}` template twice")]
    TemplateAlreadyEnded(String),

    #[error("Cannot add a connection to the ended template `{0}`")]
    TemplateEnded(String),

    #[error("Failed to build graph")]
    GraphBuildingError,

    #[error("Speedup public key is invalid")]
    InvalidKeyForSpeedupScript(#[from] ScriptError),

    #[error("Failed to sign template")]
    SigningError(#[from] KeyManagerError),

    #[error("Invalid configuration")]
    ConfigurationError(#[from] ConfigError),
    
    #[error("Call `finalize` before building templates")]
    NotFinalized,
}

#[derive(Error, Debug)]
pub enum TemplateError {
    #[error("Failed to build unspendable internal key")]
    UnspendableInternalKeyError(#[from] UnspendableKeyError),

    #[error("Failed to build taptree for given spending conditions")]
    TapTreeError(#[from] TaprootBuilderError),

    #[error("Failed to finalize taptree for given spending conditions")]
    TapTreeFinalizeError,

    #[error("Failed to hash template")]
    SighasherError(#[from] TaprootError),

    #[error("Input {0} is missing")]
    MissingInput(usize),

    #[error("Spending path for input {0} is missing")]
    MissingSpendingPath(usize),

    #[error("Invalid spending path for input {0}")]
    InvalidSpendingPath(usize),
}

#[derive(Error, Debug)]
pub enum UnspendableKeyError {
    #[error("Failed to build NUMS (unspendable) public key")]
    FailedToBuildUnspendableKey{
        reason: String
    },

    #[error("Failed to decode hex value")]
    HexDecodeError,
}

#[derive(Error, Debug)]
pub enum GraphError {
    #[error("The graph should be a DAG, cycles are not allowed")]
    GraphCycleDetected,
    #[error("Node not found")]
    NodeNotFound,
    #[error("Error while trying to access storage")]
    StorageError(StorageError),

}

#[derive(Error, Debug)]
pub enum ScriptError {
    #[error("Segwit public keys must always be compressed")]
    InvalidPublicKeyForSegwit(#[from] UncompressedPublicKeyError),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Error while trying to build configuration")]
    ConfigFileError(#[from] settings::ConfigError),

    #[error("Speedup public key is invalid")]
    InvalidKeyForSpeedupScript(#[from] ScriptError),
}


