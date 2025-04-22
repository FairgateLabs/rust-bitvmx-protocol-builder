use bitcoin::{secp256k1::Message, EcdsaSighashType, PublicKey, ScriptBuf, TapSighashType};
use key_manager::winternitz::WinternitzSignature;
use serde::{Deserialize, Serialize};

use crate::errors::{GraphError, ProtocolBuilderError};

use super::OutputType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signature {
    Ecdsa(bitcoin::ecdsa::Signature),
    Taproot(bitcoin::taproot::Signature),
}

#[derive(Clone, Debug)]
pub struct InputSignatures {
    signatures: Vec<Option<Signature>>,
}

impl InputSignatures {
    pub fn new(signatures: Vec<Option<Signature>>) -> Self {
        InputSignatures { signatures }
    }

    pub fn get_taproot_signature(
        &self,
        index: usize,
    ) -> Result<Option<bitcoin::taproot::Signature>, ProtocolBuilderError> {
        match self.signatures.get(index) {
            Some(Some(Signature::Ecdsa(_))) => Err(ProtocolBuilderError::InvalidSignatureType),
            Some(Some(Signature::Taproot(signature))) => Ok(Some(*signature)),
            Some(None) => Ok(None),
            None => Err(ProtocolBuilderError::MissingSignature),
        }
    }

    pub fn get_ecdsa_signature(
        &self,
        index: usize,
    ) -> Result<Option<bitcoin::ecdsa::Signature>, ProtocolBuilderError> {
        match self.signatures.get(index) {
            Some(Some(Signature::Ecdsa(signature))) => Ok(Some(*signature)),
            Some(Some(Signature::Taproot(_))) => Err(ProtocolBuilderError::InvalidSignatureType),
            Some(None) => Ok(None),
            None => Err(ProtocolBuilderError::MissingSignature),
        }
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Option<Signature>> {
        self.signatures.iter()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SighashType {
    Taproot(TapSighashType),
    Ecdsa(EcdsaSighashType),
}

impl SighashType {
    pub fn taproot_all() -> SighashType {
        SighashType::Taproot(TapSighashType::All)
    }

    pub fn ecdsa_all() -> SighashType {
        SighashType::Ecdsa(EcdsaSighashType::All)
    }
}

#[derive(Clone, Debug)]
pub enum LeafSpec {
    Index(usize),
    Script(ScriptBuf),
}

#[derive(Clone, Debug)]
pub enum InputArgs {
    TaprootKey { args: Vec<Vec<u8>> },
    TaprootScript { args: Vec<Vec<u8>>, leaf: LeafSpec },
    Segwit { args: Vec<Vec<u8>> },
}

impl InputArgs {
    pub fn new_taproot_script_args(leaf: LeafSpec) -> Self {
        Self::TaprootScript { args: vec![], leaf }
    }

    pub fn new_taproot_key_args() -> Self {
        Self::TaprootKey { args: vec![] }
    }

    pub fn new_segwit_args() -> Self {
        Self::Segwit { args: vec![] }
    }

    pub fn push_slice(&mut self, args: &[u8]) -> &mut Self {
        match self {
            Self::TaprootKey { args: taproot_args } => taproot_args.push(args.to_vec()),
            Self::TaprootScript {
                args: taproot_args, ..
            } => taproot_args.push(args.to_vec()),
            Self::Segwit { args: segwit_args } => segwit_args.push(args.to_vec()),
        }

        self
    }

    pub fn push_taproot_signature(
        &mut self,
        taproot_signature: bitcoin::taproot::Signature,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        match self {
            Self::TaprootKey { .. } => self.push_slice(&taproot_signature.serialize()),
            Self::TaprootScript { .. } => self.push_slice(&taproot_signature.serialize()),
            _ => return Err(ProtocolBuilderError::InvalidSignatureType),
        };

        Ok(self)
    }

    pub fn push_ecdsa_signature(
        &mut self,
        ecdsa_signature: bitcoin::ecdsa::Signature,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        match self {
            Self::Segwit { .. } => self.push_slice(&ecdsa_signature.serialize()),
            _ => return Err(ProtocolBuilderError::InvalidSignatureType),
        };

        Ok(self)
    }

    pub fn push_winternitz_signature(
        &mut self,
        winternitz_signature: WinternitzSignature,
    ) -> &mut Self {
        let hashes = winternitz_signature.to_hashes();
        let digits = winternitz_signature.checksummed_message_digits();

        for (hash, digit) in hashes.iter().zip(digits.iter()) {
            let digit = if *digit == 0 {
                [].to_vec()
            } else {
                [*digit].to_vec()
            };

            self.push_slice(hash);
            self.push_slice(&digit);
        }

        self
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Vec<u8>> {
        match self {
            Self::TaprootKey { args } => args.iter(),
            Self::TaprootScript { args, .. } => args.iter(),
            Self::Segwit { args } => args.iter(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputInfo {
    output_type: Option<OutputType>,
    sighash_type: SighashType,
    hashed_messages: Vec<Option<Vec<u8>>>,
    signatures: Vec<Option<Signature>>,
}

impl InputInfo {
    pub(crate) fn new(sighash_type: &SighashType) -> Self {
        Self {
            output_type: None,
            sighash_type: sighash_type.clone(),
            hashed_messages: vec![],
            signatures: vec![],
        }
    }

    pub(crate) fn set_hashed_messages(&mut self, messages: Vec<Option<Message>>) {
        self.hashed_messages = messages
            .iter()
            .map(|msg| msg.as_ref().map(|m| m.as_ref().to_vec()).or(None))
            .collect();
    }

    pub(crate) fn set_output_type(&mut self, output_type: OutputType) -> Result<(), GraphError> {
        match self.sighash_type {
            SighashType::Taproot(_) => match output_type {
                OutputType::TaprootKey { .. } => {}
                OutputType::TaprootScript { .. } => {}
                _ => Err(GraphError::InvalidOutputTypeForSighashType)?,
            },
            SighashType::Ecdsa(_) => match output_type {
                OutputType::SegwitPublicKey { .. } => {}
                OutputType::SegwitScript { .. } => {}
                OutputType::SegwitUnspendable { .. } => {}
                _ => Err(GraphError::InvalidOutputTypeForSighashType)?,
            },
        }

        self.output_type = Some(output_type);
        Ok(())
    }

    pub fn set_signatures(&mut self, signatures: Vec<Option<Signature>>) {
        self.signatures = signatures;
    }

    pub fn sighash_type(&self) -> &SighashType {
        &self.sighash_type
    }

    pub fn hashed_messages(&self) -> Vec<Option<Message>> {
        self.hashed_messages
            .iter()
            .map(|msg| {
                msg.as_ref().and_then(|m| {
                    if m.is_empty() {
                        None
                    } else {
                        Some(Message::from_digest_slice(m).expect("Invalid message size"))
                    }
                })
            })
            .collect()
    }

    pub fn input_keys(&self) -> Vec<PublicKey> {
        match &self.output_type {
            Some(OutputType::TaprootKey { internal_key, .. }) => vec![*internal_key],
            Some(OutputType::TaprootScript { leaves, .. }) => leaves
                .iter()
                .map(|script| script.get_verifying_key())
                .collect(),
            Some(OutputType::SegwitPublicKey { public_key, .. }) => vec![*public_key],
            Some(OutputType::SegwitScript { script, .. }) => {
                vec![script.get_verifying_key()]
            }
            Some(OutputType::SegwitUnspendable { .. }) => vec![],
            None => vec![],
        }
    }

    pub fn output_type(&self) -> Result<&OutputType, GraphError> {
        self.output_type
            .as_ref()
            .ok_or(GraphError::MissingOutputTypeForInput(format!(
                "{:?}",
                self.sighash_type
            )))
    }

    pub fn signatures(&self) -> &Vec<Option<Signature>> {
        &self.signatures
    }

    pub fn get_signature(&self, index: usize) -> Result<&Option<Signature>, GraphError> {
        self.signatures
            .get(index)
            .ok_or(GraphError::MissingSignature)
    }
}
