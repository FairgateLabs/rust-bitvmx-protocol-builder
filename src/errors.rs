use bitcoin::{
    key::{ParsePublicKeyError, UncompressedPublicKeyError},
    script::PushBytesError,
    secp256k1::scalar::OutOfRangeError,
    sighash::{P2wpkhError, SighashTypeParseError, TaprootError},
    taproot::TaprootBuilderError,
    transaction,
};
use key_manager::{
    errors::{KeyManagerError, WinternitzError},
    musig2::errors::Musig2SignerError,
};
use thiserror::Error;

use config as settings;

use crate::types::output::SpendMode;

#[derive(Error, Debug)]
pub enum UnspendableKeyError {
    #[error("Failed to build NUMS (unspendable) public key")]
    FailedToBuildUnspendableKey { reason: String },

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

    #[error("Signature missing in graph")]
    MissingSignature,

    #[error("Output type does not match with sighash type")]
    InvalidOutputTypeForSighashType,

    #[error("Missing output type information for {0}")]
    MissingOutputTypeForInput(String),

    #[error("Missing input information in transaction {0} for input {1}")]
    MissingInputInfo(String, usize),

    #[error("Invalid signature type in transaction {0} for input {1}. Expected {2}, got {3}")]
    InvalidSignatureType(String, usize, String, String),

    #[error("Invalid signature index: {0}")]
    InvalidSignatureIndex(usize),

    #[error("Transaction with txid {0} not found in graph")]
    TransactionNotFound(String),

    #[error("Transaction with name {0} already exists in graph")]
    TransactionAlreadyExists(String),

    #[error("Transaction name cannot be empty")]
    EmptyTransactionName,
}

#[derive(Error, Debug)]
pub enum ScriptError {
    #[error("Segwit public keys must always be compressed")]
    InvalidPublicKeyForSegwit(#[from] UncompressedPublicKeyError),

    #[error("Failed to finalize taptree for given spending conditions")]
    TapTreeFinalizeError,

    #[error("Failed to build taptree for given spending conditions")]
    TapTreeError(#[from] TaprootBuilderError),

    #[error("Missing extra data error in Winternitz Public Key")]
    MissingExtraDataError(#[from] WinternitzError),

    #[error("Script name cannot be empty")]
    EmptyScriptName,
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
    MissingOutput(String, usize),

    #[error("Transaction with name {0} does not contained input with index {1}")]
    MissingInput(String, usize),

    #[error(
        "Transaction with name {0} does not contained message to sign for input with index {1}"
    )]
    MissingMessage(String, u32),

    #[error("Missing protocol")]
    MissingProtocol,

    #[error("Failed to hash transaction")]
    TaprootSighashError(#[from] TaprootError),

    #[error("Failed to hash transaction")]
    P2WPKHSighashError(#[from] P2wpkhError),

    #[error("Failed to hash transaction")]
    P2WSHSighashError(#[from] transaction::InputsIndexError),

    #[error("Failed to build graph")]
    GraphBuildingError(#[from] GraphError),

    #[error("Failed to build unspendable internal key")]
    UnspendableInternalKeyError(#[from] UnspendableKeyError),

    #[error("Invalid SighashType for transaction {0} and input {1}. Expected {2}, got {3}")]
    InvalidSighashType(String, usize, String, String),

    #[error("Invalid output type for sighash type")]
    InvalidOutputTypeForSighashType,

    #[error("Invalid spending args type. Expected {0}, got {1}")]
    InvalidInputArgsType(String, String),

    #[error("Invalid spending script for input {0}")]
    InvalidLeaf(usize),

    #[error("Missing taproot leaf {0} for input {1}")]
    MissingTaprootLeaf(usize, usize),

    #[error("Cannot create zero rounds")]
    InvalidZeroRounds,

    #[error("Transaction name is empty")]
    MissingTransactionName,

    #[error("Connection name is empty")]
    MissingConnectionName,

    #[error("Scripts cannot be empty")]
    EmptyScripts,

    #[error("Missing verifiying key for input {0}")]
    MissingVerifyingKey(usize),

    #[error("Failed to tweak public key")]
    TweakError(#[from] bitcoin::secp256k1::Error),

    #[error("Failed to sign transaction")]
    SignatureError(#[from] KeyManagerError),

    #[error("Failed to build protocol scripts")]
    ScriptError(#[from] ScriptError),

    #[error("Error while trying acessing the data")]
    DataError(#[from] storage_backend::error::StorageError),

    #[error("Error while trying to open storage")]
    StorageError(storage_backend::error::StorageError),

    #[error("Invalid signature type")]
    InvalidSignatureType,

    #[error("Signature not found")]
    MissingSignature,

    #[error("Protocol not built")]
    ProtocolNotBuilt,

    #[error("Failed to push data in op_return script")]
    OpReturnDataError(#[from] PushBytesError),

    #[error("Failed to generate signature for key spend path in taproot output with taptree. Transaction: {0}, input index: {1}")]
    KeySpendSignatureGenerationFailed(String, usize),

    #[error("Failed to generate signature for script spend path in taproot output. Transaction: {0}, input index: {1}, script index: {2}")]
    ScriptSpendSignatureGenerationFailed(String, usize, usize),

    #[error("Failed to get script for transaction {0}, input index {1} and script index {2}. Ouput must be TaprootScript or SegwitScript but it is {3}")]
    CannotGetScriptForOutputType(String, u32, u32, String),

    #[error("Failed to generate nonce for MuSig2 signature aggregation")]
    MuSig2NonceGenerationError(#[from] Musig2SignerError),

    #[error("Insufficient funds for transaction, cannot cover fees. Total amount: {0}, Fees: {1}")]
    InsufficientFunds(u64, u64),

    #[error("Only {0} outputs can be signed with {0} sighash type. Output type is {1}")]
    InvalidOutputType(String, String),

    #[error("Failed to tweak public key, scalar out of range")]
    TweakScalarOutOfRange(#[from] OutOfRangeError),

    #[error("Failed to tweak public key, invalid tweak length. Expected 32 bytes, got {0} bytes")]
    InvalidTweakLength(usize),

    #[error("Invalid spend mode. Expected {0}, got {1}")]
    InvalidSpendMode(String, SpendMode),
}

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Bad argument: {msg}")]
    BadArgument { msg: String },

    #[error("Unexpected error: {0}")]
    UnexpectedError(String),

    #[error("Invalid network: {0}")]
    InvalidNetwork(String),

    #[error("Invalid Hex String: {0}")]
    InvalidHexString(String),
}
