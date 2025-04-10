use bitcoin::{secp256k1::Message, EcdsaSighashType, PublicKey, TapSighashType};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use crate::{
    errors::{GraphError, ProtocolBuilderError},
    graph::output::OutputType,
};

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

#[derive(Debug, Clone)]
pub struct InputSpendingInfo {
    spending_type: Option<OutputType>,
    sighash_type: SighashType,
    hashed_messages: Vec<Option<Message>>,
    signatures: Vec<Option<Signature>>,
}

impl Serialize for InputSpendingInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut messages: Vec<Vec<u8>> = vec![];
        for message in &self.hashed_messages {
            match message {
                Some(msg) => messages.push(msg.as_ref().to_vec()),
                None => messages.push(vec![]),
            }
        }
        let mut state = serializer.serialize_struct("InputSpendingInfo", 4)?;
        state.serialize_field("spending_type", &self.spending_type)?;
        state.serialize_field("sighash_type", &self.sighash_type)?;
        state.serialize_field("hashed_messages", &messages)?;
        state.serialize_field("signatures", &self.signatures)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for InputSpendingInfo {
    fn deserialize<D>(deserializer: D) -> Result<InputSpendingInfo, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            SpendingType,
            SighashType,
            HashedMessages,
            Signatures,
        }

        struct InputSpendingInfoVisitor;

        impl<'de> serde::de::Visitor<'de> for InputSpendingInfoVisitor {
            type Value = InputSpendingInfo;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct InputSpendingInfo")
            }

            fn visit_map<V>(self, mut map: V) -> Result<InputSpendingInfo, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut spending_type: Option<OutputType> = None;
                let mut sighash_type: Option<SighashType> = None;
                let mut hashed_messages: Option<Vec<[u8; 32]>> = None;
                let mut signatures: Option<Vec<Option<Signature>>> = None;

                while let Some(key_field) = map.next_key()? {
                    match key_field {
                        Field::SighashType => {
                            if sighash_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("sighash_type"));
                            }
                            sighash_type = Some(map.next_value()?);
                        }
                        Field::HashedMessages => {
                            if hashed_messages.is_some() {
                                return Err(serde::de::Error::duplicate_field("hashed_messages"));
                            }
                            hashed_messages = Some(map.next_value()?);
                        }
                        Field::SpendingType => {
                            if spending_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("spending_type"));
                            }
                            spending_type = Some(map.next_value()?);
                        }
                        Field::Signatures => {
                            if signatures.is_some() {
                                return Err(serde::de::Error::duplicate_field("input_keys"));
                            }
                            signatures = Some(map.next_value()?);
                        }
                    }
                }
                Ok(InputSpendingInfo {
                    sighash_type: sighash_type
                        .ok_or_else(|| serde::de::Error::missing_field("sighash_type"))?,
                    hashed_messages: {
                        let mut messages = vec![];
                        for message in hashed_messages
                            .ok_or_else(|| serde::de::Error::missing_field("hashed_messages"))?
                        {
                            if message.len() != 32 {
                                return Err(serde::de::Error::custom(
                                    "hashed_messages must be 32 bytes",
                                ));
                            }
                            if message.is_empty() {
                                messages.push(None);
                                continue;
                            }

                            messages.push(Some(
                                Message::from_digest_slice(&message)
                                    .map_err(|e| serde::de::Error::custom(e.to_string()))?,
                            ));
                        }
                        messages
                    },
                    spending_type,
                    signatures: signatures
                        .ok_or_else(|| serde::de::Error::missing_field("signatures"))?,
                })
            }
        }

        deserializer.deserialize_struct(
            "InputSpendingInfo",
            &["sighash_type", "hashed_messages", "spending_type"],
            InputSpendingInfoVisitor,
        )
    }
}

impl InputSpendingInfo {
    pub(crate) fn new(sighash_type: &SighashType) -> Self {
        Self {
            spending_type: None,
            sighash_type: sighash_type.clone(),
            hashed_messages: vec![],
            signatures: vec![],
        }
    }

    pub(crate) fn set_hashed_messages(&mut self, messages: Vec<Option<Message>>) {
        self.hashed_messages = messages;
    }

    pub(crate) fn set_spending_type(
        &mut self,
        spending_type: OutputType,
    ) -> Result<(), GraphError> {
        match self.sighash_type {
            SighashType::Taproot(_) => match spending_type {
                OutputType::TaprootTweakedKey { .. } => {}
                OutputType::TaprootUntweakedKey { .. } => {}
                OutputType::TaprootScriptUnspendableKey { .. } => {}
                OutputType::TaprootScriptAndKey { .. } => {}
                _ => Err(GraphError::InvalidSpendingTypeForSighashType)?,
            },
            SighashType::Ecdsa(_) => match spending_type {
                OutputType::SegwitPublicKey { .. } => {}
                OutputType::SegwitScript { .. } => {}
                _ => Err(GraphError::InvalidSpendingTypeForSighashType)?,
            },
        }

        self.spending_type = Some(spending_type);
        Ok(())
    }

    pub fn set_signatures(&mut self, signatures: Vec<Option<Signature>>) {
        self.signatures = signatures;
    }

    pub fn sighash_type(&self) -> &SighashType {
        &self.sighash_type
    }

    pub fn hashed_messages(&self) -> &Vec<Option<Message>> {
        &self.hashed_messages
    }

    pub fn input_keys(&self) -> Vec<PublicKey> {
        match &self.spending_type {
            Some(OutputType::TaprootTweakedKey { key, .. }) => vec![*key],
            Some(OutputType::TaprootUntweakedKey { key, .. }) => vec![*key],
            Some(OutputType::TaprootScriptUnspendableKey {
                spending_scripts, ..
            }) => spending_scripts
                .iter()
                .map(|script| script.get_verifying_key())
                .collect(),
            Some(OutputType::TaprootScriptAndKey {
                spending_scripts, ..
            }) => spending_scripts
                .iter()
                .map(|script| script.get_verifying_key())
                .collect(),
            Some(OutputType::SegwitPublicKey { public_key, .. }) => vec![*public_key],
            Some(OutputType::SegwitScript { script, .. }) => {
                vec![script.get_verifying_key()]
            }
            Some(OutputType::SegwitUnspendable {}) => vec![],
            None => vec![],
        }
    }

    pub fn spending_type(&self) -> Result<&OutputType, GraphError> {
        self.spending_type.as_ref().ok_or(
            GraphError::MissingOutputSpendingTypeForInputSpendingInfo(format!(
                "{:?}",
                self.sighash_type
            )),
        )
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

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::key::rand;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::{taproot, EcdsaSighashType, TapSighashType};

    #[test]
    fn test_empty_signatures() {
        let empty_sigs = InputSignatures::new(vec![]);
        assert!(empty_sigs.get_taproot_signature(0).is_err());
        assert!(empty_sigs.get_ecdsa_signature(0).is_err());
    }

    #[test]
    fn test_taproot_signature() {
        let _msg = Message::from_digest_slice(&[0; 32]).unwrap();
        let tap_sig = taproot::Signature::from_slice(&[1; 64]).unwrap();
        let sigs = InputSignatures::new(vec![Some(Signature::Taproot(tap_sig))]);

        assert!(sigs.get_taproot_signature(0).is_ok());
        assert!(sigs.get_ecdsa_signature(0).is_err());
        assert!(sigs.get_taproot_signature(1).is_err());
    }

    #[test]
    fn test_ecdsa_signature() {
        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&[0; 32]).unwrap();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let ecdsa_sig = secp.sign_ecdsa(&msg, &secret_key);
        let sigs = InputSignatures::new(vec![Some(Signature::Ecdsa(
            bitcoin::ecdsa::Signature::sighash_all(ecdsa_sig),
        ))]);

        assert!(sigs.get_ecdsa_signature(0).is_ok());
        assert!(sigs.get_taproot_signature(0).is_err());
    }

    #[test]
    fn test_iterator() {
        let tap_sig = taproot::Signature::from_slice(&[1; 64]).unwrap();
        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&[0; 32]).unwrap();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let ecdsa_sig = secp.sign_ecdsa(&msg, &secret_key);
        let sigs = InputSignatures::new(vec![
            Some(Signature::Taproot(tap_sig)),
            Some(Signature::Ecdsa(bitcoin::ecdsa::Signature::sighash_all(
                ecdsa_sig,
            ))),
        ]);

        assert_eq!(sigs.iter().count(), 2);
    }

    #[test]
    fn test_sighash_types() {
        let tap_sighash = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash = SighashType::Ecdsa(EcdsaSighashType::All);

        match tap_sighash {
            SighashType::Taproot(_) => {}
            _ => panic!("Expected Taproot sighash type"),
        }

        match ecdsa_sighash {
            SighashType::Ecdsa(_) => {}
            _ => panic!("Expected ECDSA sighash type"),
        }
    }
}
