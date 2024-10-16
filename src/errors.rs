use bitcoin::{key::{ParsePublicKeyError, UncompressedPublicKeyError}, sighash::{P2wpkhError, SighashTypeParseError, TaprootError}, taproot::TaprootBuilderError, transaction};
use key_manager::errors::KeyManagerError;
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
    GraphBuildingError(#[from] GraphError),

    #[error("Speedup public key is invalid")]
    InvalidKeyForSpeedupScript(#[from] ScriptError),

    #[error("Failed to sign template")]
    SigningError(#[from] KeyManagerError),

    #[error("Invalid configuration")]
    ConfigurationError(#[from] ConfigError),
    
    #[error("Call `finalize` before building templates")]
    NotFinalized,

    #[error("Failed to compute sighash in TemplateBuilder")]
    KeyManagerError(#[from] P2wpkhError),

    #[error("Cannot create zero rounds")]
    InvalidZeroRounds,

    #[error("Spending scripts cannot be empty")]
    EmptySpendingScripts,

    #[error("Template name is empty")]
    MissingTemplateName,
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
    TaprootSighashError(#[from] TaprootError),

    #[error("Failed to hash template")]
    P2WPKHSighashError(#[from] P2wpkhError),

    #[error("Failed to hash template")]
    P2WSHSighashError(#[from] transaction::InputsIndexError),

    #[error("Input {0} is missing")]
    MissingInput(usize),

    #[error("Spending path for input {0} is missing")]
    MissingSpendingPath(usize),

    #[error("Signature of spending path for input {0} is missing")]
    MissingSignature(usize),

    #[error("Signature verifying key of spending path for input {0} is missing")]
    MissingSignatureVerifyingKey(usize),

    #[error("Invalid spending path for input {0}")]
    InvalidSpendingPath(usize),

    #[error("Invalid input type for input {0}")]
    InvalidInputType(usize),

    #[error("Invalid script params for input {0}")]
    InvalidScriptParams(usize),

    #[error("Invalid locktime {0}")]
    InvalidLockTime(u16),

    #[error("Missing signature veryfing key for input {0}")]
    MissingPublicKey(usize),
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

    #[error("Transaction with name {0} missing in graph")]
    MissingTransaction(String),

    #[error("Connection missing in graph")]
    MissingConnection,

    #[error("Spending type does not match with sighash type")]
    InvalidSpendingTypeForSighashType,

    #[error("Missing output spending information for ")]
    MissingOutputSpendingTypeForInputSpendingInfo(String),

    #[error("Error while trying to deserialize data")]
    DeserializationError(#[from] serde_json::Error),

    #[error("Error while trying acessing the data")]
    DataError(#[from] storage_backend::error::StorageError),

    #[error("Error while trying to open storage")]
    StorageError(storage_backend::error::StorageError),
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

    #[error("Public key in config is invalid")]
    InvalidPublicKey(#[from] ParsePublicKeyError),

    #[error("SighashType in config is invalid")]
    InvalidSighashType(#[from] SighashTypeParseError),
}

#[derive(Error, Debug)]
pub enum ProtocolBuilderError {
    #[error("Transaction with name {0} missing in protocol {1}")]
    MissingTransaction(String, String),

    #[error("Transaction with name {0} does not contained ouput with index {1}")]
    MissingOutput(String, u32),

    #[error("Transaction with name {0} does not contained input with index {1}")]
    MissingInput(String, u32),

    #[error("Missing protocol")]
    MissingProtocol,

    #[error("Failed to hash transaction")]
    TaprootSighashError(#[from] TaprootError),

    #[error("Failed to hash transaction")]
    P2WPKHSighashError(#[from] P2wpkhError),

    #[error("Failed to hash transaction")]
    P2WSHSighashError(#[from] transaction::InputsIndexError),

    // #[error("Missing spend info for input of type {0}")]
    // MissingSpendInfoForInputType(String),

    // #[error("Spend info is not needed for input of type {0}")]
    // UnnecessarySpendInfoForInputType(String),

    #[error("Failed to build graph")]
    GraphBuildingError(#[from] GraphError),

    #[error("Failed to build taptree for given spending conditions")]
    TapTreeError(#[from] TaprootBuilderError),

    #[error("Failed to finalize taptree for given spending conditions")]
    TapTreeFinalizeError,

    #[error("Failed to build unspendable internal key")]
    UnspendableInternalKeyError(#[from] UnspendableKeyError),

    #[error("Invalid SighashType")]
    InvalidSighashType,

    #[error("Invalid spending type for sighash type")]
    InvalidSpendingTypeForSighashType,

    #[error("Invalid spending script for input {0}")]
    InvalidSpendingScript(usize),

    #[error("Missing taproot leaf for input {0}")]
    MissingTaprootLeaf(usize),

    #[error("Cannot create zero rounds")]
    InvalidZeroRounds,

    #[error("Transaction name is empty")]
    MissingTransactionName,

    #[error("Connection name is empty")]
    MissingConnectionName,

    #[error("Spending scripts cannot be empty")]
    EmptySpendingScripts,
}

