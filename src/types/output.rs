use bitcoin::{
    key::{TweakedPublicKey, UntweakedPublicKey},
    secp256k1::{self, Message, Scalar},
    sighash::{self, SighashCache},
    taproot::{LeafVersion, TaprootSpendInfo},
    Amount, EcdsaSighashType, PublicKey, ScriptBuf, TapLeafHash, TapSighashType, TapTweakHash,
    Transaction, TxOut, Txid, WScriptHash, XOnlyPublicKey,
};
use key_manager::{
    key_manager::KeyManager, keystorage::keystore::KeyStore, verifier::SignatureVerifier,
};
use serde::{Deserialize, Serialize};

use crate::{
    errors::ProtocolBuilderError,
    graph::graph::MessageId,
    scripts::{self, ProtocolScript},
    types::input::Signature,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub amount: u64,
    pub pub_key: PublicKey,
}

impl Utxo {
    pub fn new(txid: Txid, vout: u32, amount: u64, pub_key: &PublicKey) -> Self {
        Utxo {
            txid,
            vout,
            amount,
            pub_key: *pub_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputType {
    TaprootKey {
        value: Amount,
        internal_key: PublicKey,
        tweak: Option<Vec<u8>>,
        script_pubkey: ScriptBuf,
        prevouts: Vec<TxOut>,
    },
    TaprootScript {
        value: Amount,
        internal_key: PublicKey,
        script_pubkey: ScriptBuf,
        leaves: Vec<ProtocolScript>,
        with_key_path: bool,
        prevouts: Vec<TxOut>,
    },
    SegwitPublicKey {
        value: Amount,
        script_pubkey: ScriptBuf,
        public_key: PublicKey,
    },
    SegwitScript {
        value: Amount,
        script_pubkey: ScriptBuf,
        script: ProtocolScript,
    },
    SegwitUnspendable {
        value: Amount,
        script_pubkey: ScriptBuf,
    },
}

impl OutputType {
    pub fn tr_key(
        value: u64,
        internal_key: &PublicKey,
        tweak: Option<&Scalar>,
        prevouts: Vec<TxOut>,
    ) -> Result<Self, ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();
        let untweaked_key: UntweakedPublicKey = XOnlyPublicKey::from(*internal_key);

        let script_pubkey = match tweak {
            Some(t) => {
                let (output_key, tweaked_parity) = untweaked_key.add_tweak(&secp, t)?;

                if !untweaked_key.tweak_add_check(&secp, &output_key, tweaked_parity, *t) {
                    return Err(ProtocolBuilderError::TweakError(
                        bitcoin::secp256k1::Error::InvalidTweak,
                    ));
                }

                ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(output_key))
            }
            None => ScriptBuf::new_p2tr(&secp, untweaked_key, None),
        };

        Ok(OutputType::TaprootKey {
            value: Amount::from_sat(value),
            internal_key: *internal_key,
            tweak: tweak.map(|t| t.to_be_bytes().to_vec()),
            script_pubkey,
            prevouts,
        })
    }

    pub fn tr_script(
        value: u64,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        with_key_path: bool,
        prevouts: Vec<TxOut>,
    ) -> Result<Self, ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();
        let spend_info = Self::compute_spend_info(internal_key, leaves)?;

        let script_pubkey =
            ScriptBuf::new_p2tr(&secp, spend_info.internal_key(), spend_info.merkle_root());

        Ok(OutputType::TaprootScript {
            value: Amount::from_sat(value),
            internal_key: *internal_key,
            script_pubkey,
            leaves: leaves.to_vec(),
            with_key_path,
            prevouts,
        })
    }

    pub fn segwit_key(value: u64, public_key: &PublicKey) -> Result<Self, ProtocolBuilderError> {
        let witness_public_key_hash = public_key.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&witness_public_key_hash);

        Ok(OutputType::SegwitPublicKey {
            value: Amount::from_sat(value),
            public_key: *public_key,
            script_pubkey,
        })
    }

    pub fn segwit_script(
        value: u64,
        script: &ProtocolScript,
    ) -> Result<Self, ProtocolBuilderError> {
        let script_pubkey = ScriptBuf::new_p2wsh(&WScriptHash::from(script.get_script().clone()));

        Ok(OutputType::SegwitScript {
            value: Amount::from_sat(value),
            script_pubkey,
            script: script.clone(),
        })
    }

    pub fn segwit_unspendable(script_pubkey: ScriptBuf) -> Result<Self, ProtocolBuilderError> {
        Ok(OutputType::SegwitUnspendable {
            value: Amount::from_sat(0),
            script_pubkey,
        })
    }

    pub fn get_name(&self) -> &'static str {
        match self {
            OutputType::TaprootKey { .. } => "TaprootKey",
            OutputType::TaprootScript { .. } => "TaprootScript",
            OutputType::SegwitPublicKey { .. } => "SegwitPublicKey",
            OutputType::SegwitScript { .. } => "SegwitScript",
            OutputType::SegwitUnspendable { .. } => "SegwitUnspendable",
        }
    }

    pub fn get_value(&self) -> Amount {
        match self {
            OutputType::TaprootKey { value, .. }
            | OutputType::TaprootScript { value, .. }
            | OutputType::SegwitPublicKey { value, .. }
            | OutputType::SegwitScript { value, .. }
            | OutputType::SegwitUnspendable { value, .. } => *value,
        }
    }

    pub fn get_script_pubkey(&self) -> &ScriptBuf {
        match self {
            OutputType::TaprootKey { script_pubkey, .. }
            | OutputType::TaprootScript { script_pubkey, .. }
            | OutputType::SegwitPublicKey { script_pubkey, .. }
            | OutputType::SegwitScript { script_pubkey, .. }
            | OutputType::SegwitUnspendable { script_pubkey, .. } => script_pubkey,
        }
    }

    pub fn has_prevouts(&self) -> bool {
        match self {
            OutputType::TaprootKey { prevouts, .. } => !prevouts.is_empty(),
            OutputType::TaprootScript { prevouts, .. } => !prevouts.is_empty(),
            _ => false,
        }
    }

    pub fn get_prevouts(&self) -> Vec<TxOut> {
        match self {
            OutputType::TaprootKey { prevouts, .. } => prevouts.clone(),
            OutputType::TaprootScript { prevouts, .. } => prevouts.clone(),
            _ => vec![],
        }
    }

    pub fn get_taproot_spend_info(&self) -> Result<Option<TaprootSpendInfo>, ProtocolBuilderError> {
        match self {
            OutputType::TaprootScript {
                leaves,
                internal_key,
                ..
            } => Ok(Some(Self::compute_spend_info(
                internal_key,
                leaves,
            )?)),
            _ => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compute_taproot_sighash<K: KeyStore>(
        &self,
        transaction: &Transaction,
        transaction_name: &str,
        input_index: usize,
        prevouts: Vec<TxOut>,
        tap_sighash_type: &TapSighashType,
        musig2: bool,
        key_manager: &KeyManager<K>,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        let messages = match self {
            OutputType::TaprootKey {
                ref internal_key, ..
            } => {
                let mut hasher = SighashCache::new(transaction);

                let hashed_message = Message::from(hasher.taproot_key_spend_signature_hash(
                    input_index,
                    &sighash::Prevouts::All(&prevouts),
                    *tap_sighash_type,
                )?);

                if musig2 {
                    key_manager.generate_nonce(
                        MessageId::new_string_id(transaction_name, input_index as u32, 0).as_str(),
                        hashed_message.as_ref().to_vec(),
                        internal_key,
                        None,
                    )?;
                };

                vec![Some(hashed_message)]
            }
            OutputType::TaprootScript {
                internal_key,
                leaves,
                with_key_path,
                ..
            } => {
                let mut hasher = SighashCache::new(transaction);

                let mut hashed_messages = vec![];
                for (script_index, leaf) in leaves.iter().enumerate() {
                    if leaf.skip_signing() {
                        hashed_messages.push(None);
                        continue;
                    }

                    let hashed_message =
                        Message::from(hasher.taproot_script_spend_signature_hash(
                            input_index,
                            &sighash::Prevouts::All(&prevouts),
                            TapLeafHash::from_script(
                                leaf.get_script(),
                                LeafVersion::TapScript,
                            ),
                            *tap_sighash_type,
                        )?);

                    if musig2 {
                        key_manager.generate_nonce(
                            MessageId::new_string_id(
                                transaction_name,
                                input_index as u32,
                                script_index as u32,
                            )
                            .as_str(),
                            hashed_message.as_ref().to_vec(),
                            &leaf.get_verifying_key(),
                            None,
                        )?;
                    };

                    hashed_messages.push(Some(hashed_message));
                }

                if *with_key_path {
                    // Compute a sighash for the key spend path.
                    let key_spend_hashed_message =
                        Message::from(hasher.taproot_key_spend_signature_hash(
                            input_index,
                            &sighash::Prevouts::All(&prevouts),
                            *tap_sighash_type,
                        )?);

                    if musig2 {
                        let spend_info = Self::compute_spend_info(internal_key, leaves)?;

                        let tweak = TapTweakHash::from_key_and_tweak(
                            XOnlyPublicKey::from(*internal_key),
                            spend_info.merkle_root(),
                        )
                        .to_scalar();
                        let musig2_tweak =
                            musig2::secp256k1::Scalar::from_be_bytes(tweak.to_be_bytes()).unwrap();

                        key_manager.generate_nonce(
                            MessageId::new_string_id(
                                transaction_name,
                                input_index as u32,
                                leaves.len() as u32,
                            )
                            .as_str(),
                            key_spend_hashed_message.as_ref().to_vec(),
                            internal_key,
                            Some(musig2_tweak),
                        )?;
                    }

                    hashed_messages.push(Some(key_spend_hashed_message));
                };

                hashed_messages
            }
            _ => {
                return Err(ProtocolBuilderError::InvalidOutputType(
                    "Taproot".to_string(),
                    self.get_name().to_string(),
                ));
            }
        };

        Ok(messages)
    }

    pub fn compute_ecdsa_sighash(
        &self,
        transaction: &Transaction,
        _transaction_name: &str,
        input_index: usize,
        ecdsa_sighash_type: &EcdsaSighashType,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        let messages = match self {
            OutputType::SegwitPublicKey {
                value, public_key, ..
            } => {
                let wpkh = public_key.wpubkey_hash().expect("key is compressed");
                let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

                let mut sighasher = SighashCache::new(transaction);

                vec![Some(Message::from(sighasher.p2wpkh_signature_hash(
                    input_index,
                    &script_pubkey,
                    *value,
                    *ecdsa_sighash_type,
                )?))]
            }
            OutputType::SegwitScript { value, script, .. } => {
                if script.skip_signing() {
                    vec![None]
                } else {
                    let script_hash = WScriptHash::from(script.get_script().clone());
                    let script_pubkey = ScriptBuf::new_p2wsh(&script_hash);

                    let mut sighasher = SighashCache::new(transaction);

                    let hashed_message = Message::from(sighasher.p2wsh_signature_hash(
                        input_index,
                        &script_pubkey,
                        *value,
                        *ecdsa_sighash_type,
                    )?);

                    vec![Some(hashed_message)]
                }
            }
            OutputType::SegwitUnspendable { .. } => {
                vec![None]
            }
            _ => {
                return Err(ProtocolBuilderError::InvalidOutputType(
                    "Segwit".to_string(),
                    self.get_name().to_string(),
                ));
            }
        };

        Ok(messages)
    }

    pub fn compute_taproot_signature<K: KeyStore>(
        &self,
        transaction_name: &str,
        input_index: usize,
        hashed_messages: &[Option<Message>],
        tap_sighash_type: &TapSighashType,
        musig2: bool,
        key_manager: &KeyManager<K>,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        let messages = match self {
            OutputType::TaprootKey {
                internal_key,
                tweak,
                ..
            } => {
                assert!(
                    hashed_messages.len() == 1,
                    "Expected only one message to sign"
                );
                if hashed_messages[0].is_none() {
                    return Ok(vec![None]);
                }

                let schnorr_signature = if musig2 {
                    let message_id =
                        MessageId::new_string_id(transaction_name, input_index as u32, 0);
                    key_manager.get_aggregated_signature(internal_key, &message_id)?
                } else {
                    let hashed_message = hashed_messages[0].as_ref().unwrap();
                    let (schnorr_signature, _) =
                        match tweak {
                            Some(t) => key_manager.sign_schnorr_message_with_tweak(
                                hashed_message,
                                internal_key,
                                &Scalar::from_be_bytes(t.as_slice().try_into().map_err(|_| {
                                    ProtocolBuilderError::InvalidTweakLength(t.len())
                                })?)?,
                            )?,
                            None => key_manager.sign_schnorr_message_with_tap_tweak(
                                hashed_message,
                                internal_key,
                                None,
                            )?,
                        };
                    schnorr_signature
                };

                let signature = Signature::Taproot(bitcoin::taproot::Signature {
                    signature: schnorr_signature,
                    sighash_type: *tap_sighash_type,
                });

                vec![Some(signature)]
            }
            OutputType::TaprootScript {
                internal_key,
                leaves,
                with_key_path,
                ..
            } => {
                assert!(
                    hashed_messages.len() == leaves.len() + 1,
                    "Expected one message for each script and one for the key spend path"
                );

                let mut signatures = vec![];
                for (index, leaf) in leaves.iter().enumerate() {
                    if leaf.skip_signing() {
                        signatures.push(None);
                        continue;
                    }

                    let schnorr_signature = if musig2 {
                        let message_id = MessageId::new_string_id(
                            transaction_name,
                            input_index as u32,
                            index as u32,
                        );
                        key_manager.get_aggregated_signature(&leaf.get_verifying_key(), &message_id)?
                    } else {
                        key_manager.sign_schnorr_message(
                            &hashed_messages[index].unwrap(),
                            &leaf.get_verifying_key(),
                        )?
                    };

                    let signature = Some(Signature::Taproot(bitcoin::taproot::Signature {
                        signature: schnorr_signature,
                        sighash_type: *tap_sighash_type,
                    }));

                    signatures.push(signature);
                }

                if *with_key_path {
                    // Compute a signature for the key spend path.
                    let key_spend_hashed_message = hashed_messages.last().unwrap().unwrap();
                    hashed_messages[leaves.len()].as_ref().unwrap();

                    let schnorr_signature = if musig2 {
                        let message_id = MessageId::new_string_id(
                            transaction_name,
                            input_index as u32,
                            leaves.len() as u32,
                        );

                        key_manager.get_aggregated_signature(internal_key, &message_id)?
                    } else {
                        let spend_info = Self::compute_spend_info(internal_key, leaves)?;

                        let (schnorr_signature, output_key) = key_manager
                            .sign_schnorr_message_with_tap_tweak(
                                &key_spend_hashed_message,
                                internal_key,
                                spend_info.merkle_root(),
                            )?;

                        // Verify the signature.
                        if !SignatureVerifier::new().verify_schnorr_signature(
                            &schnorr_signature,
                            &key_spend_hashed_message,
                            output_key,
                        ) {
                            return Err(ProtocolBuilderError::KeySpendSignatureGenerationFailed);
                        }

                        schnorr_signature
                    };

                    let signature = Some(Signature::Taproot(bitcoin::taproot::Signature {
                        signature: schnorr_signature,
                        sighash_type: *tap_sighash_type,
                    }));

                    signatures.push(signature);
                };

                signatures
            }
            _ => {
                return Err(ProtocolBuilderError::InvalidOutputType(
                    "Taproot".to_string(),
                    self.get_name().to_string(),
                ));
            }
        };

        Ok(messages)
    }

    pub fn compute_ecdsa_signature<K: KeyStore>(
        &self,
        _transaction_name: &str,
        _input_index: usize,
        hashed_messages: &[Option<Message>],
        ecdsa_sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager<K>,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        let signatures = match self {
            OutputType::SegwitPublicKey { public_key, .. } => {
                assert!(
                    hashed_messages.len() == 1,
                    "Expected only one message to sign"
                );
                assert!(hashed_messages[0].is_some(), "Expected a message to sign");

                let ecdsa_signature =
                    key_manager.sign_ecdsa_message(&hashed_messages[0].unwrap(), public_key)?;
                let signature = Signature::Ecdsa(bitcoin::ecdsa::Signature {
                    signature: ecdsa_signature,
                    sighash_type: *ecdsa_sighash_type,
                });

                vec![Some(signature)]
            }
            OutputType::SegwitScript { script, .. } => {
                assert!(
                    hashed_messages.len() == 1,
                    "Expected only one message to sign"
                );

                if script.skip_signing() {
                    vec![None]
                } else {
                    let ecdsa_signature = key_manager.sign_ecdsa_message(
                        &hashed_messages[0].unwrap(),
                        &script.get_verifying_key(),
                    )?;
                    let signature = Signature::Ecdsa(bitcoin::ecdsa::Signature {
                        signature: ecdsa_signature,
                        sighash_type: *ecdsa_sighash_type,
                    });

                    vec![Some(signature)]
                }
            }
            OutputType::SegwitUnspendable { .. } => {
                vec![None]
            }
            _ => {
                return Err(ProtocolBuilderError::InvalidOutputType(
                    "Segwit".to_string(),
                    self.get_name().to_string(),
                ));
            }
        };

        Ok(signatures)
    }

    fn compute_spend_info(
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
    ) -> Result<TaprootSpendInfo, ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();
        let spend_info = scripts::build_taproot_spend_info(
            &secp,
            &XOnlyPublicKey::from(*internal_key),
            leaves,
        )?;
        Ok(spend_info)
    }
}
