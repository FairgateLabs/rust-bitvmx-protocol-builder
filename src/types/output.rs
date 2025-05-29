use std::fmt;

use bitcoin::{
    secp256k1::{self, Message},
    sighash::{self, SighashCache},
    taproot::{LeafVersion, TaprootSpendInfo},
    Amount, EcdsaSighashType, PublicKey, ScriptBuf, TapLeafHash, TapSighashType, TapTweakHash,
    Transaction, TxOut, Txid, WScriptHash, XOnlyPublicKey,
};
use key_manager::{key_manager::KeyManager, verifier::SignatureVerifier};
use serde::{Deserialize, Serialize};

use crate::{
    errors::ProtocolBuilderError,
    scripts::{self, ProtocolScript, SignMode},
    types::input::Signature,
};

use super::input::SpendMode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageId {
    transaction: String,
    input_index: u32,
    script_index: u32,
}

impl MessageId {
    pub fn new(transaction: String, input_index: u32, script_index: u32) -> Self {
        MessageId {
            transaction,
            input_index,
            script_index,
        }
    }

    pub fn new_string_id(transaction: &str, input_index: u32, script_index: u32) -> String {
        format!("tx:{}_ix:{}_sx:{}", transaction, input_index, script_index)
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tx:{}_ix:{}_sx:{}",
            self.transaction, self.input_index, self.script_index
        )
    }
}

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
    Taproot {
        value: Amount,
        internal_key: PublicKey,
        script_pubkey: ScriptBuf,
        leaves: Vec<ProtocolScript>,
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
    pub fn taproot(
        value: u64,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
    ) -> Result<Self, ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();
        let spend_info = Self::compute_spend_info(internal_key, leaves)?;

        let script_pubkey =
            ScriptBuf::new_p2tr(&secp, spend_info.internal_key(), spend_info.merkle_root());

        Ok(OutputType::Taproot {
            value: Amount::from_sat(value),
            internal_key: *internal_key,
            script_pubkey,
            leaves: leaves.to_vec(),
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
            OutputType::Taproot { .. } => "TaprootScript",
            OutputType::SegwitPublicKey { .. } => "SegwitPublicKey",
            OutputType::SegwitScript { .. } => "SegwitScript",
            OutputType::SegwitUnspendable { .. } => "SegwitUnspendable",
        }
    }

    pub fn get_value(&self) -> Amount {
        match self {
            OutputType::Taproot { value, .. }
            | OutputType::SegwitPublicKey { value, .. }
            | OutputType::SegwitScript { value, .. }
            | OutputType::SegwitUnspendable { value, .. } => *value,
        }
    }

    pub fn get_script_pubkey(&self) -> &ScriptBuf {
        match self {
            OutputType::Taproot { script_pubkey, .. }
            | OutputType::SegwitPublicKey { script_pubkey, .. }
            | OutputType::SegwitScript { script_pubkey, .. }
            | OutputType::SegwitUnspendable { script_pubkey, .. } => script_pubkey,
        }
    }

    pub fn get_taproot_spend_info(&self) -> Result<Option<TaprootSpendInfo>, ProtocolBuilderError> {
        match self {
            OutputType::Taproot {
                leaves,
                internal_key,
                ..
            } => Ok(Some(Self::compute_spend_info(internal_key, leaves)?)),
            _ => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compute_taproot_sighash(
        &self,
        transaction: &Transaction,
        transaction_name: &str,
        input_index: usize,
        prevouts: &[TxOut],
        spend_mode: &SpendMode,
        tap_sighash_type: &TapSighashType,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        let messages = match self {
            OutputType::Taproot {
                internal_key,
                leaves,
                ..
            } => self.taproot_sighash(
                transaction,
                transaction_name,
                input_index,
                prevouts,
                tap_sighash_type,
                internal_key,
                leaves,
                spend_mode,
                key_manager,
                id,
            )?,
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
            } => self.ecdsa_key_sighash(
                transaction,
                input_index,
                ecdsa_sighash_type,
                value,
                public_key,
            )?,
            OutputType::SegwitScript { value, script, .. } => self.ecdsa_script_sighash(
                transaction,
                input_index,
                ecdsa_sighash_type,
                value,
                script,
            )?,
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

    #[allow(clippy::too_many_arguments)]
    pub fn compute_taproot_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
        hashed_messages: &[Option<Message>],
        spend_mode: &SpendMode,
        tap_sighash_type: &TapSighashType,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        let signatures = match self {
            OutputType::Taproot {
                internal_key,
                leaves,
                ..
            } => self.taproot_signature(
                transaction_name,
                input_index,
                hashed_messages,
                tap_sighash_type,
                internal_key,
                leaves,
                spend_mode,
                key_manager,
                id,
            )?,
            _ => {
                return Err(ProtocolBuilderError::InvalidOutputType(
                    "Taproot".to_string(),
                    self.get_name().to_string(),
                ));
            }
        };

        Ok(signatures)
    }

    pub fn compute_ecdsa_signature(
        &self,
        _transaction_name: &str,
        _input_index: usize,
        hashed_messages: &[Option<Message>],
        ecdsa_sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        let signatures = match self {
            OutputType::SegwitPublicKey { public_key, .. } => self.ecdsa_key_signature(
                hashed_messages,
                ecdsa_sighash_type,
                key_manager,
                public_key,
            )?,
            OutputType::SegwitScript { script, .. } => self.ecdsa_script_signature(
                hashed_messages,
                ecdsa_sighash_type,
                key_manager,
                script,
            )?,
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
        let spend_info =
            scripts::build_taproot_spend_info(&secp, &XOnlyPublicKey::from(*internal_key), leaves)?;
        Ok(spend_info)
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_sighash(
        &self,
        transaction: &Transaction,
        transaction_name: &str,
        input_index: usize,
        prevouts: &[TxOut],
        tap_sighash_type: &TapSighashType,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        spend_mode: &SpendMode,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        let (key_path, scripts_path, key_path_sign_mode, selected_leaves) =
            spend_mode_params(leaves, spend_mode)?;

        // Initialize the vector of hashed messages with None for all paths.
        let mut hashed_messages: Vec<Option<Message>> = vec![None; leaves.len() + 1];

        if key_path {
            let hashed_message = self.taproot_key_only_sighash(
                transaction,
                transaction_name,
                input_index,
                prevouts,
                tap_sighash_type,
                &key_path_sign_mode.unwrap(),
                internal_key,
                leaves,
                key_manager,
                id,
            )?;

            // Push the key path hash to the end of the vector.
            let last_index = hashed_messages.len() - 1;
            hashed_messages[last_index] = hashed_message;
        };

        if scripts_path {
            // Script path hashes
            for (leaf_index, leaf) in selected_leaves.as_ref().unwrap().iter() {
                let hashed_message = self.taproot_script_only_sighash(
                    transaction,
                    transaction_name,
                    input_index,
                    prevouts,
                    tap_sighash_type,
                    leaf,
                    *leaf_index,
                    key_manager,
                    id,
                )?;

                // Push the script path hash to the correct position in the vector.
                hashed_messages[*leaf_index] = hashed_message;
            }
        };

        Ok(hashed_messages)
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_script_only_sighash(
        &self,
        transaction: &Transaction,
        transaction_name: &str,
        input_index: usize,
        prevouts: &[TxOut],
        tap_sighash_type: &TapSighashType,
        leaf: &ProtocolScript,
        leaf_index: usize,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Option<Message>, ProtocolBuilderError> {
        let mut hasher = SighashCache::new(transaction);

        let hashed_message = Message::from(hasher.taproot_script_spend_signature_hash(
            input_index,
            &sighash::Prevouts::All(prevouts),
            TapLeafHash::from_script(leaf.get_script(), LeafVersion::TapScript),
            *tap_sighash_type,
        )?);

        if leaf.aggregate_signing() && leaf.get_verifying_key().is_some() {
            key_manager.generate_nonce(
                MessageId::new_string_id(transaction_name, input_index as u32, leaf_index as u32)
                    .as_str(),
                hashed_message.as_ref().to_vec(),
                &leaf.get_verifying_key().unwrap(),
                id,
                None,
            )?;
        };

        Ok(Some(hashed_message))
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_key_only_sighash(
        &self,
        transaction: &Transaction,
        transaction_name: &str,
        input_index: usize,
        prevouts: &[TxOut],
        tap_sighash_type: &TapSighashType,
        key_path_sign_mode: &SignMode,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Option<Message>, ProtocolBuilderError> {
        let mut hasher = SighashCache::new(transaction);

        // Compute a sighash for the key spend path.
        let key_path_hashed_message = Message::from(hasher.taproot_key_spend_signature_hash(
            input_index,
            &sighash::Prevouts::All(prevouts),
            *tap_sighash_type,
        )?);

        if *key_path_sign_mode == SignMode::Aggregate {
            let spend_info = Self::compute_spend_info(internal_key, leaves)?;

            let tweak = TapTweakHash::from_key_and_tweak(
                XOnlyPublicKey::from(*internal_key),
                spend_info.merkle_root(),
            )
            .to_scalar();
            let musig2_tweak =
                musig2::secp256k1::Scalar::from_be_bytes(tweak.to_be_bytes()).unwrap();

            key_manager.generate_nonce(
                MessageId::new_string_id(transaction_name, input_index as u32, leaves.len() as u32)
                    .as_str(),
                key_path_hashed_message.as_ref().to_vec(),
                internal_key,
                id,
                Some(musig2_tweak),
            )?;
        }

        Ok(Some(key_path_hashed_message))
    }

    fn ecdsa_key_sighash(
        &self,
        transaction: &Transaction,
        input_index: usize,
        ecdsa_sighash_type: &EcdsaSighashType,
        value: &Amount,
        public_key: &PublicKey,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        let wpkh = public_key.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        let mut sighasher = SighashCache::new(transaction);

        Ok(vec![Some(Message::from(sighasher.p2wpkh_signature_hash(
            input_index,
            &script_pubkey,
            *value,
            *ecdsa_sighash_type,
        )?))])
    }

    fn ecdsa_script_sighash(
        &self,
        transaction: &Transaction,
        input_index: usize,
        ecdsa_sighash_type: &EcdsaSighashType,
        value: &Amount,
        script: &ProtocolScript,
    ) -> Result<Vec<Option<Message>>, ProtocolBuilderError> {
        let script_hash = WScriptHash::from(script.get_script().clone());
        let script_pubkey = ScriptBuf::new_p2wsh(&script_hash);

        let mut sighasher = SighashCache::new(transaction);

        let hashed_message = Message::from(sighasher.p2wsh_signature_hash(
            input_index,
            &script_pubkey,
            *value,
            *ecdsa_sighash_type,
        )?);

        Ok(vec![Some(hashed_message)])
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
        hashed_messages: &[Option<Message>],
        tap_sighash_type: &TapSighashType,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        spend_mode: &SpendMode,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        assert!(
            hashed_messages.len() == leaves.len() + 1,
            "Expected one message for each script and one for the key spend path"
        );

        let (key_path, scripts_path, key_path_sign_mode, selected_leaves) =
            spend_mode_params(leaves, spend_mode)?;

        // Initialize the vector of signatures with None for all paths.
        let mut signatures: Vec<Option<Signature>> = vec![None; leaves.len() + 1];

        if key_path {
            // Key path signature
            let signature = self.taproot_key_only_signature(
                transaction_name,
                input_index,
                hashed_messages,
                tap_sighash_type,
                &key_path_sign_mode.unwrap(),
                internal_key,
                leaves,
                key_manager,
                id,
            )?;

            // Push the key path signature to the end of the vector.
            let last_index = signatures.len() - 1;
            signatures[last_index] = signature;
        };

        if scripts_path {
            // Script path signatures
            for (leaf_index, leaf) in selected_leaves.as_ref().unwrap().iter() {
                let signature = self.taproot_script_only_signature(
                    transaction_name,
                    input_index,
                    hashed_messages,
                    tap_sighash_type,
                    leaf,
                    *leaf_index,
                    key_manager,
                    id,
                )?;

                signatures[*leaf_index] = signature;
            }
        };

        Ok(signatures)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn taproot_script_only_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
        hashed_messages: &[Option<Message>],
        tap_sighash_type: &TapSighashType,
        leaf: &ProtocolScript,
        leaf_index: usize,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Option<Signature>, ProtocolBuilderError> {
        if leaf.skip_signing() {
            return Ok(None);
        };

        let schnorr_signature = if leaf.aggregate_signing() {
            let message_id =
                MessageId::new_string_id(transaction_name, input_index as u32, leaf_index as u32);
            key_manager.get_aggregated_signature(
                &leaf.get_verifying_key().unwrap(),
                id,
                &message_id,
            )?
        } else {
            let hashed_message = hashed_messages[leaf_index].unwrap();

            let schnorr_signature = key_manager
                .sign_schnorr_message(&hashed_message, &leaf.get_verifying_key().unwrap())?;

            // Verify the signature.
            if !SignatureVerifier::new().verify_schnorr_signature(
                &schnorr_signature,
                &hashed_message,
                leaf.get_verifying_key().unwrap(),
            ) {
                return Err(ProtocolBuilderError::ScriptSpendSignatureGenerationFailed(
                    transaction_name.to_string(),
                    input_index,
                    leaf_index,
                ));
            };

            schnorr_signature
        };

        Ok(Some(Signature::Taproot(bitcoin::taproot::Signature {
            signature: schnorr_signature,
            sighash_type: *tap_sighash_type,
        })))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn taproot_key_only_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
        hashed_messages: &[Option<Message>],
        tap_sighash_type: &TapSighashType,
        key_path_sign_mode: &SignMode,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<Option<Signature>, ProtocolBuilderError> {
        // Compute a signature for the key spend path.
        let key_path_hashed_message = hashed_messages.last().unwrap().unwrap();
        hashed_messages[leaves.len()].as_ref().unwrap();

        let schnorr_signature = if *key_path_sign_mode == SignMode::Aggregate {
            let message_id =
                MessageId::new_string_id(transaction_name, input_index as u32, leaves.len() as u32);

            key_manager.get_aggregated_signature(internal_key, id, &message_id)?
        } else {
            let spend_info = Self::compute_spend_info(internal_key, leaves)?;

            let (schnorr_signature, output_key) = key_manager.sign_schnorr_message_with_tap_tweak(
                &key_path_hashed_message,
                internal_key,
                spend_info.merkle_root(),
            )?;

            // Verify the signature.
            if !SignatureVerifier::new().verify_schnorr_signature(
                &schnorr_signature,
                &key_path_hashed_message,
                output_key,
            ) {
                return Err(ProtocolBuilderError::KeySpendSignatureGenerationFailed(
                    transaction_name.to_string(),
                    input_index,
                ));
            }

            schnorr_signature
        };

        Ok(Some(Signature::Taproot(bitcoin::taproot::Signature {
            signature: schnorr_signature,
            sighash_type: *tap_sighash_type,
        })))
    }

    pub fn ecdsa_key_signature(
        &self,
        hashed_messages: &[Option<Message>],
        ecdsa_sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager,
        public_key: &PublicKey,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
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
        Ok(vec![Some(signature)])
    }

    pub fn ecdsa_script_signature(
        &self,
        hashed_messages: &[Option<Message>],
        ecdsa_sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager,
        script: &ProtocolScript,
    ) -> Result<Vec<Option<Signature>>, ProtocolBuilderError> {
        assert!(
            hashed_messages.len() == 1,
            "Expected only one message to sign"
        );
        Ok(if script.skip_signing() {
            vec![None]
        } else {
            let ecdsa_signature = key_manager.sign_ecdsa_message(
                &hashed_messages[0].unwrap(),
                &script.get_verifying_key().unwrap(),
            )?;
            let signature = Signature::Ecdsa(bitcoin::ecdsa::Signature {
                signature: ecdsa_signature,
                sighash_type: *ecdsa_sighash_type,
            });

            vec![Some(signature)]
        })
    }
}

#[allow(clippy::type_complexity)]
fn spend_mode_params(
    leaves: &[ProtocolScript],
    spend_mode: &SpendMode,
) -> Result<
    (
        bool,
        bool,
        Option<SignMode>,
        Option<Vec<(usize, ProtocolScript)>>,
    ),
    ProtocolBuilderError,
> {
    let (key_path, scripts_path, key_path_sign_mode, selected_leaves) = match spend_mode {
        SpendMode::All {
            key_path_sign: key_path_sign_mode,
        } => (
            true,
            true,
            Some(key_path_sign_mode.clone()),
            Some(select_leaves(leaves, &[])),
        ),
        SpendMode::KeyOnly {
            key_path_sign: key_path_sign_mode,
        } => (true, false, Some(key_path_sign_mode.clone()), None),
        SpendMode::ScriptsOnly => (false, true, None, Some(select_leaves(leaves, &[]))),
        SpendMode::Scripts { leaves: indexes } => {
            (false, true, None, Some(select_leaves(leaves, indexes)))
        }
        SpendMode::Script { leaf } => (false, true, None, Some(select_leaves(leaves, &[*leaf]))),
        SpendMode::None => (false, false, None, None),
        SpendMode::Segwit => {
            return Err(ProtocolBuilderError::InvalidSpendMode(
                "Taproot".to_string(),
                spend_mode.clone(),
            ))
        }
    };
    Ok((key_path, scripts_path, key_path_sign_mode, selected_leaves))
}

fn select_leaves(leaves: &[ProtocolScript], indexes: &[usize]) -> Vec<(usize, ProtocolScript)> {
    if indexes.is_empty() {
        return leaves
            .iter()
            .cloned()
            .enumerate()
            .collect::<Vec<(usize, ProtocolScript)>>();
    };

    indexes
        .iter()
        .map(|&leaf_index| (leaf_index, leaves[leaf_index].clone()))
        .collect::<Vec<(usize, ProtocolScript)>>()
}
