use bitcoin::{secp256k1::Message, EcdsaSighashType, PublicKey, TapSighashType};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use crate::{
    errors::{GraphError, ProtocolBuilderError},
    graph::output::OutputSpendingType,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signature {
    Ecdsa(bitcoin::ecdsa::Signature),
    Taproot(bitcoin::taproot::Signature),
}

#[derive(Clone, Debug)]
pub struct InputSignatures {
    signatures: Vec<Signature>,
}

impl InputSignatures {
    pub fn new(signatures: Vec<Signature>) -> Self {
        InputSignatures { signatures }
    }

    pub fn get_taproot_signature(
        &self,
        index: usize,
    ) -> Result<bitcoin::taproot::Signature, ProtocolBuilderError> {
        match self.signatures.get(index) {
            Some(Signature::Ecdsa(_)) => Err(ProtocolBuilderError::InvalidSignatureType),
            Some(Signature::Taproot(signature)) => Ok(*signature),
            None => Err(ProtocolBuilderError::MissingSignature),
        }
    }

    pub fn get_ecdsa_signature(
        &self,
        index: usize,
    ) -> Result<bitcoin::ecdsa::Signature, ProtocolBuilderError> {
        match self.signatures.get(index) {
            Some(Signature::Ecdsa(signature)) => Ok(*signature),
            Some(Signature::Taproot(_)) => Err(ProtocolBuilderError::InvalidSignatureType),
            None => Err(ProtocolBuilderError::MissingSignature),
        }
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Signature> {
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
    spending_type: Option<OutputSpendingType>,
    sighash_type: SighashType,
    hashed_messages: Vec<Message>,
    signatures: Vec<Signature>,
}

impl Serialize for InputSpendingInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut messages: Vec<&[u8; 32]> = vec![];
        for message in &self.hashed_messages {
            messages.push(message.as_ref());
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
                let mut spending_type: Option<OutputSpendingType> = None;
                let mut sighash_type: Option<SighashType> = None;
                let mut hashed_messages: Option<Vec<[u8; 32]>> = None;
                let mut signatures: Option<Vec<Signature>> = None;

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
                            messages.push(
                                Message::from_digest_slice(&message)
                                    .map_err(|e| serde::de::Error::custom(e.to_string()))?,
                            );
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

    pub(crate) fn set_hashed_messages(&mut self, messages: Vec<Message>) {
        self.hashed_messages = messages;
    }

    pub(crate) fn set_spending_type(
        &mut self,
        spending_type: OutputSpendingType,
    ) -> Result<(), GraphError> {
        match self.sighash_type {
            SighashType::Taproot(_) => match spending_type {
                OutputSpendingType::TaprootTweakedKey { .. } => {}
                OutputSpendingType::TaprootUntweakedKey { .. } => {}
                OutputSpendingType::TaprootScript { .. } => {}
                _ => Err(GraphError::InvalidSpendingTypeForSighashType)?,
            },
            SighashType::Ecdsa(_) => match spending_type {
                OutputSpendingType::SegwitPublicKey { .. } => {}
                OutputSpendingType::SegwitScript { .. } => {}
                _ => Err(GraphError::InvalidSpendingTypeForSighashType)?,
            },
        }

        self.spending_type = Some(spending_type);
        Ok(())
    }

    pub fn set_signatures(&mut self, signatures: Vec<Signature>) {
        self.signatures = signatures;
    }

    pub fn sighash_type(&self) -> &SighashType {
        &self.sighash_type
    }

    pub fn hashed_messages(&self) -> &Vec<Message> {
        &self.hashed_messages
    }

    pub fn input_keys(&self) -> Vec<PublicKey> {
        match &self.spending_type {
            Some(OutputSpendingType::TaprootTweakedKey { key, .. }) => vec![*key],
            Some(OutputSpendingType::TaprootUntweakedKey { key }) => vec![*key],
            Some(OutputSpendingType::TaprootScript {
                spending_scripts, ..
            }) => spending_scripts
                .iter()
                .map(|script| script.get_verifying_key())
                .collect(),
            Some(OutputSpendingType::SegwitPublicKey { public_key, .. }) => vec![*public_key],
            Some(OutputSpendingType::SegwitScript { script, .. }) => {
                vec![script.get_verifying_key()]
            }
            Some(OutputSpendingType::SegwitUnspendable {}) => vec![],
            None => vec![],
        }
    }

    pub fn spending_type(&self) -> Result<&OutputSpendingType, GraphError> {
        self.spending_type.as_ref().ok_or(
            GraphError::MissingOutputSpendingTypeForInputSpendingInfo(format!(
                "{:?}",
                self.sighash_type
            )),
        )
    }

    pub fn signatures(&self) -> &Vec<Signature> {
        &self.signatures
    }

    pub fn get_signature(&self, index: usize) -> Result<&Signature, GraphError> {
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
        let sigs = InputSignatures::new(vec![Signature::Taproot(tap_sig)]);

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
        let sigs = InputSignatures::new(vec![Signature::Ecdsa(
            bitcoin::ecdsa::Signature::sighash_all(ecdsa_sig),
        )]);

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
            Signature::Taproot(tap_sig),
            Signature::Ecdsa(bitcoin::ecdsa::Signature::sighash_all(ecdsa_sig)),
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
