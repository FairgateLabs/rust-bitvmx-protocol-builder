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
