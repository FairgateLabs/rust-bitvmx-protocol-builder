use bitcoin::{
    hashes::Hash,
    key::{Parity, TweakedPublicKey, UntweakedPublicKey},
    locktime,
    secp256k1::{self, Message, Scalar},
    sighash::{self, SighashCache},
    taproot::{LeafVersion, TaprootSpendInfo},
    transaction, Address, Amount, EcdsaSighashType, OutPoint, PublicKey, ScriptBuf, Sequence,
    TapLeafHash, TapNodeHash, TapSighashType, TapTweakHash, Transaction, TxIn, TxOut, Txid,
    WScriptHash, Witness, XOnlyPublicKey,
};
use key_manager::{
    key_manager::KeyManager, keystorage::keystore::KeyStore, verifier::SignatureVerifier,
    winternitz::WinternitzSignature,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, rc::Rc, vec};
use storage_backend::storage::Storage;

use crate::{
    errors::ProtocolBuilderError,
    graph::{
        graph::{MessageId, TransactionGraph},
        input::{InputSignatures, InputSpendingInfo, SighashType, Signature},
        output::OutputType,
    },
    scripts::{self, ProtocolScript},
    unspendable::unspendable_key,
};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Utxo {
    pub txname: String,
    pub txid: Txid,
    pub vout: u32,
    pub amount: u64,
    pub pub_key: PublicKey,
}

impl Utxo {
    pub fn new(txname: String, txid: Txid, vout: u32, amount: u64, pub_key: &PublicKey) -> Self {
        Utxo {
            txname,
            txid,
            vout,
            amount,
            pub_key: *pub_key,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SpendingArgs {
    args: Vec<Vec<u8>>,
    taproot_leaf: Option<ScriptBuf>,
}

impl SpendingArgs {
    pub fn new_taproot_args(taproot_leaf: &ScriptBuf) -> Self {
        SpendingArgs {
            args: vec![],
            taproot_leaf: Some(taproot_leaf.clone()),
        }
    }

    pub fn new_args() -> Self {
        SpendingArgs {
            args: vec![],
            taproot_leaf: None,
        }
    }

    pub fn push_slice(&mut self, args: &[u8]) -> &mut Self {
        self.args.push(args.to_vec());
        self
    }

    pub fn push_taproot_signature(
        &mut self,
        taproot_signature: bitcoin::taproot::Signature,
    ) -> &mut Self {
        self.push_slice(&taproot_signature.serialize());
        self
    }

    pub fn push_ecdsa_signature(
        &mut self,
        ecdsa_signature: bitcoin::ecdsa::Signature,
    ) -> &mut Self {
        self.push_slice(&ecdsa_signature.serialize());
        self
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

    pub fn get_taproot_leaf(&self) -> Option<ScriptBuf> {
        self.taproot_leaf.clone()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Vec<u8>> {
        self.args.iter()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Protocol {
    name: String,
    graph: TransactionGraph,
}

impl Protocol {
    pub fn new(name: &str) -> Self {
        Protocol {
            name: name.to_string(),
            graph: TransactionGraph::new(),
        }
    }

    pub fn load(name: &str, storage: Rc<Storage>) -> Result<Option<Self>, ProtocolBuilderError> {
        let protocol = match storage.read(name)? {
            Some(protocol) => protocol,
            None => return Ok(None),
        };
        let protocol: Protocol = serde_json::from_str(&protocol)?;
        Ok(Some(protocol))
    }

    pub fn save(&self, storage: Rc<Storage>) -> Result<(), ProtocolBuilderError> {
        storage.write(&self.name, &serde_json::to_string(self)?)?;
        Ok(())
    }

    pub fn add_taproot_tweaked_key_spend_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        internal_key: &PublicKey,
        tweak: &Scalar,
        prevouts: Vec<TxOut>,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();
        let untweaked_key: UntweakedPublicKey = XOnlyPublicKey::from(*internal_key);
        let (output_key, tweaked_parity) = untweaked_key.add_tweak(&secp, tweak)?;

        if !output_key.tweak_add_check(&secp, &output_key, tweaked_parity, *tweak) {
            return Err(ProtocolBuilderError::TweakError(
                bitcoin::secp256k1::Error::InvalidTweak,
            ));
        }

        let script_pubkey =
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(output_key));
        let value = Amount::from_sat(value);

        let spending_type =
            OutputType::new_taproot_tweaked_key_spend(internal_key, tweak, prevouts);
        self.add_transaction_output(transaction_name, value, script_pubkey, spending_type)?;

        Ok(self)
    }

    pub fn add_taproot_key_spend_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        internal_key: &PublicKey,
        prevouts: Vec<TxOut>,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();
        let untweaked_key: UntweakedPublicKey = XOnlyPublicKey::from(*internal_key);
        let script_pubkey = ScriptBuf::new_p2tr(&secp, untweaked_key, None);
        let value = Amount::from_sat(value);
        let spending_type = OutputType::new_taproot_key_spend(internal_key, prevouts);
        self.add_transaction_output(transaction_name, value, script_pubkey, spending_type)?;

        Ok(self)
    }

    /// This function is used to add a taproot script and key spend output to the transaction.
    pub fn add_taproot_script_spend_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        internal_key: &UntweakedPublicKey,
        spending_scripts: &[ProtocolScript],
    ) -> Result<&mut Self, ProtocolBuilderError> {
        Self::check_empty_scripts(spending_scripts)?;

        let secp = secp256k1::Secp256k1::new();
        let value = Amount::from_sat(value);
        let spend_info = scripts::build_taproot_spend_info(&secp, internal_key, spending_scripts)?;

        let script_pubkey =
            ScriptBuf::new_p2tr(&secp, spend_info.internal_key(), spend_info.merkle_root());

        let spending_type =
            OutputType::new_taproot_script_and_key_spend(spending_scripts, &spend_info, vec![]);
        self.add_transaction_output(transaction_name, value, script_pubkey, spending_type)?;

        Ok(self)
    }

    /// This function is used to add a taproot script spend output without the key spend path transaction.
    /// The internal key must be unspendable.
    pub fn add_taproot_script_unspendable_key_spend_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        internal_key: &UntweakedPublicKey,
        spending_scripts: &[ProtocolScript],
    ) -> Result<&mut Self, ProtocolBuilderError> {
        Self::check_empty_scripts(spending_scripts)?;

        let secp = secp256k1::Secp256k1::new();
        let value = Amount::from_sat(value);
        let spend_info = scripts::build_taproot_spend_info(&secp, internal_key, spending_scripts)?;

        let script_pubkey =
            ScriptBuf::new_p2tr(&secp, spend_info.internal_key(), spend_info.merkle_root());

        let spending_type = OutputType::new_taproot_script_unspendable_key_spend(
            spending_scripts,
            &spend_info,
            vec![],
        );
        self.add_transaction_output(transaction_name, value, script_pubkey, spending_type)?;

        Ok(self)
    }

    pub fn add_p2wpkh_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        public_key: &PublicKey,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        let witness_public_key_hash = public_key.wpubkey_hash().expect("key is compressed");
        let value = Amount::from_sat(value);
        let script_pubkey = ScriptBuf::new_p2wpkh(&witness_public_key_hash);

        let spending_type = OutputType::new_segwit_key_spend(public_key, value);
        self.add_transaction_output(transaction_name, value, script_pubkey, spending_type)?;

        Ok(self)
    }

    pub fn add_p2wsh_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        script: &ProtocolScript,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        let value = Amount::from_sat(value);
        let script_pubkey = ScriptBuf::new_p2wsh(&WScriptHash::from(script.get_script().clone()));

        let spending_type = OutputType::new_segwit_script_spend(script, value);
        self.add_transaction_output(transaction_name, value, script_pubkey, spending_type)?;
        Ok(self)
    }

    pub fn add_speedup_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        speedup_public_key: &PublicKey,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_p2wpkh_output(transaction_name, value, speedup_public_key)?;
        Ok(self)
    }

    pub fn add_timelock_output(
        &mut self,
        transaction: &str,
        value: u64,
        internal_key: &UntweakedPublicKey,
        expired_script: &ProtocolScript,
        renew_script: &ProtocolScript,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_taproot_script_spend_output(
            transaction,
            value,
            internal_key,
            &[expired_script.clone(), renew_script.clone()],
        )
    }

    pub fn add_op_return_output(
        &mut self,
        transaction_name: &str,
        data: Vec<u8>,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        let value = Amount::from_sat(0);
        let script_pubkey = scripts::op_return(data);

        let spending_type = OutputType::new_segwit_unspendable();
        self.add_transaction_output(transaction_name, value, script_pubkey, spending_type)?;

        Ok(self)
    }

    pub fn add_taproot_tweaked_key_spend_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_transaction_input(
            Hash::all_zeros(),
            previous_output,
            transaction_name,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            sighash_type,
        )?;
        Ok(self)
    }

    pub fn add_taproot_key_spend_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_transaction_input(
            Hash::all_zeros(),
            previous_output,
            transaction_name,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            sighash_type,
        )?;
        Ok(self)
    }

    pub fn add_taproot_script_spend_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_transaction_input(
            Hash::all_zeros(),
            previous_output,
            transaction_name,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            sighash_type,
        )?;
        Ok(self)
    }

    pub fn add_p2wpkh_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_transaction_input(
            Hash::all_zeros(),
            previous_output,
            transaction_name,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            sighash_type,
        )?;
        Ok(self)
    }

    pub fn add_p2wsh_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_transaction_input(
            Hash::all_zeros(),
            previous_output,
            transaction_name,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            sighash_type,
        )?;
        Ok(self)
    }

    pub fn add_timelock_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        blocks: u16,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        let sequence = match blocks {
            0 => Sequence::ENABLE_RBF_NO_LOCKTIME,
            _ => Sequence::from_height(blocks),
        };

        self.add_transaction_input(
            Hash::all_zeros(),
            previous_output,
            transaction_name,
            sequence,
            sighash_type,
        )?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_taproot_tweaked_key_spend_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        value: u64,
        internal_key: &PublicKey,
        tweak: &Scalar,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_taproot_tweaked_key_spend_output(from, value, internal_key, tweak, vec![])?;
        let output_index = (self.transaction(from)?.output.len() - 1) as u32;

        self.add_taproot_tweaked_key_spend_input(to, output_index, sighash_type)?;
        let input_index = (self.transaction(to)?.input.len() - 1) as u32;

        self.connect(connection_name, from, output_index, to, input_index)
    }

    pub fn add_taproot_key_spend_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        value: u64,
        internal_key: &PublicKey,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_taproot_key_spend_output(from, value, internal_key, vec![])?;
        let output_index = (self.transaction(from)?.output.len() - 1) as u32;

        self.add_taproot_key_spend_input(to, output_index, sighash_type)?;
        let input_index = (self.transaction(to)?.input.len() - 1) as u32;

        self.connect(connection_name, from, output_index, to, input_index)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_taproot_script_spend_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        value: u64,
        internal_key: &UntweakedPublicKey,
        spending_scripts: &[ProtocolScript],
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_taproot_script_spend_output(from, value, internal_key, spending_scripts)?;
        let output_index = (self.transaction(from)?.output.len() - 1) as u32;

        self.add_taproot_script_spend_input(to, output_index, sighash_type)?;
        let input_index = (self.transaction(to)?.input.len() - 1) as u32;

        self.connect(connection_name, from, output_index, to, input_index)
    }

    pub fn add_p2wpkh_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        value: u64,
        public_key: &PublicKey,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_p2wpkh_output(from, value, public_key)?;
        let output_index = (self.transaction(from)?.output.len() - 1) as u32;

        self.add_p2wpkh_input(to, output_index, sighash_type)?;
        let input_index = (self.transaction(to)?.input.len() - 1) as u32;

        self.connect(connection_name, from, output_index, to, input_index)
    }

    pub fn add_p2wsh_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        value: u64,
        script: &ProtocolScript,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_p2wsh_output(from, value, script)?;
        let output_index = (self.transaction(from)?.output.len() - 1) as u32;

        self.add_p2wsh_input(to, output_index, sighash_type)?;
        let input_index = (self.transaction(to)?.input.len() - 1) as u32;

        self.connect(connection_name, from, output_index, to, input_index)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_timelock_connection(
        &mut self,
        from: &str,
        value: u64,
        internal_key: &UntweakedPublicKey,
        expired_script: &ProtocolScript,
        renew_script: &ProtocolScript,
        to: &str,
        _expired_blocks: u16,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_timelock_output(from, value, internal_key, expired_script, renew_script)?;
        let output_index = (self.transaction(from)?.output.len() - 1) as u32;

        // This input consumes the renew_script output, no need to use the expired_blocks
        self.add_timelock_input(to, output_index, 0, sighash_type)?;
        let input_index = (self.transaction(to)?.input.len() - 1) as u32;

        self.connect("timelock", from, output_index, to, input_index)

        // TODO use expired_blocks to create a transaction that consumes the expired_script
    }

    pub fn connect_with_external_transaction(
        &mut self,
        txid: Txid,
        output_index: u32,
        output_spending_type: OutputType,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_transaction_input(
            txid,
            output_index,
            to,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            sighash_type,
        )?;
        self.graph
            .connect_with_external_transaction(output_spending_type, to)?;
        Ok(self)
    }

    pub fn connect(
        &mut self,
        connection_name: &str,
        from: &str,
        output_index: u32,
        to: &str,
        input_index: u32,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        Self::check_empty_connection_name(connection_name)?;
        Self::check_empty_transaction_name(from)?;
        Self::check_empty_transaction_name(to)?;

        let from_tx = self.transaction(from)?;
        let to_tx = self.transaction(to)?;

        if output_index >= from_tx.output.len() as u32 {
            return Err(ProtocolBuilderError::MissingOutput(
                from.to_string(),
                output_index,
            ));
        }

        if input_index >= to_tx.input.len() as u32 {
            return Err(ProtocolBuilderError::MissingInput(
                to.to_string(),
                input_index,
            ));
        }

        self.graph
            .connect(connection_name, from, output_index, to, input_index)?;

        Ok(self)
    }

    /// Creates a connection between two transactions for a given number of rounds creating the intermediate transactions to complete the DAG.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_rounds(
        &mut self,
        connection_name: &str,
        rounds: u32,
        from: &str,
        to: &str,
        value: u64,
        internal_key: &XOnlyPublicKey,
        spending_scripts_from: &[ProtocolScript],
        spending_scripts_to: &[ProtocolScript],
        sighash_type: &SighashType,
    ) -> Result<(String, String), ProtocolBuilderError> {
        Self::check_zero_rounds(rounds)?;
        // To create the names for the intermediate transactions in the rounds. We will use the following format: {name}_{round}.
        let mut from_round;
        let mut to_round;

        // In each round we will connect the from transaction to the to transaction and then the to transaction to the from transaction.
        // we need to do this because the transactions are connected in a DAG.
        for round in 0..rounds - 1 {
            // Create the new names for the intermediate transactions in the direct connection (from -> to).
            from_round = format!("{0}_{1}", from, round);
            to_round = format!("{0}_{1}", to, round);

            // Connection between the from and to transactions using the spending_scripts_from.
            self.add_taproot_script_spend_connection(
                connection_name,
                &from_round,
                value,
                internal_key,
                spending_scripts_from,
                &to_round,
                sighash_type,
            )?;

            // Create the new names for the intermediate transactions in the reverse connection (to -> from).
            from_round = format!("{0}_{1}", from, round + 1);
            to_round = format!("{0}_{1}", to, round);

            // Reverse connection between the to and from transactions using the spending_scripts_to.
            self.add_taproot_script_spend_connection(
                connection_name,
                &to_round,
                value,
                internal_key,
                spending_scripts_to,
                &from_round,
                sighash_type,
            )?;
        }

        // We don't need the last reverse connection, thus why we perform the last direct connection outside the loop.
        // Create the new names for the last direct connection (from -> to).
        from_round = format!("{0}_{1}", from, rounds - 1);
        to_round = format!("{0}_{1}", to, rounds - 1);

        // Last direct connection using spending_scripts_from.
        self.add_taproot_script_spend_connection(
            connection_name,
            &from_round,
            value,
            internal_key,
            spending_scripts_from,
            &to_round,
            sighash_type,
        )?;

        Ok((format!("{0}_{1}", from, 0), to_round))
    }

    pub fn build<K: KeyStore>(
        &mut self,
        key_manager: &Rc<KeyManager<K>>,
    ) -> Result<Self, ProtocolBuilderError> {
        self.update_transaction_ids()?;
        self.compute_sighashes(key_manager)?;
        Ok(self.clone())
    }

    pub fn sign<K: KeyStore>(
        &mut self,
        key_manager: &Rc<KeyManager<K>>,
    ) -> Result<Self, ProtocolBuilderError> {
        self.compute_signatures(key_manager)?;
        Ok(self.clone())
    }

    pub fn build_and_sign<K: KeyStore>(
        &mut self,
        key_manager: &Rc<KeyManager<K>>,
    ) -> Result<Self, ProtocolBuilderError> {
        self.update_transaction_ids()?;
        self.compute_sighashes_and_signatures(key_manager)?;
        Ok(self.clone())
    }

    pub fn update_input_signatures(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        signatures: Vec<Option<Signature>>,
    ) -> Result<(), ProtocolBuilderError> {
        self.graph
            .update_input_signatures(transaction_name, input_index, signatures)?;
        Ok(())
    }

    pub fn transaction_to_send(
        &self,
        transaction_name: &str,
        spending_args: &[SpendingArgs],
    ) -> Result<Transaction, ProtocolBuilderError> {
        let mut transaction = self.graph.get_transaction(transaction_name)?.clone();

        for (input_index, spending_condition) in self
            .graph
            .get_transaction_spending_info(transaction_name)?
            .iter()
            .enumerate()
        {
            let witness = self.get_witness_for_input(
                input_index,
                spending_condition,
                &spending_args[input_index],
            )?;
            transaction.input[input_index].witness = witness;
        }

        Ok(transaction)
    }

    pub fn speedup_transaction<K: KeyStore>(
        &self,
        transaction_to_speedup_utxo: Utxo,
        funding_transaction_utxo: Utxo,
        change_address: Address,
        speedup_fee: u64,
        key_manager: &KeyManager<K>,
    ) -> Result<Transaction, ProtocolBuilderError> {
        let transaction_to_speedup = self.transaction(&transaction_to_speedup_utxo.txname)?;
        let mut speedup_transaction = Protocol::transaction_template();

        // The speedup input to consume the speedup output of the transaction to speedup
        speedup_transaction.input.push(TxIn {
            previous_output: OutPoint {
                txid: transaction_to_speedup.compute_txid(),
                vout: transaction_to_speedup_utxo.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });

        // The speedup input to consume the funding output of the funding transaction
        speedup_transaction.input.push(TxIn {
            previous_output: OutPoint {
                txid: funding_transaction_utxo.txid,
                vout: funding_transaction_utxo.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });

        // The speedup output for the change
        let funding_amount = Amount::from_sat(funding_transaction_utxo.amount);
        let fees = Amount::from_sat(speedup_fee);
        let amount_to_send =
            funding_amount
                .checked_sub(fees)
                .ok_or(ProtocolBuilderError::InsufficientFunds(
                    funding_transaction_utxo.amount,
                    speedup_fee,
                ))?;

        let txout = TxOut {
            value: amount_to_send,
            script_pubkey: change_address.script_pubkey(),
        };

        speedup_transaction.output.push(txout);

        // Witness for the speedup input 0
        let witness_public_key_hash = transaction_to_speedup_utxo
            .pub_key
            .wpubkey_hash()
            .expect("key is compressed");
        let value = Amount::from_sat(transaction_to_speedup_utxo.amount);
        let script_pubkey = ScriptBuf::new_p2wpkh(&witness_public_key_hash);

        let mut sighasher = SighashCache::new(speedup_transaction.clone());

        let speedup_input_0_hash = Message::from(sighasher.p2wpkh_signature_hash(
            0,
            &script_pubkey,
            value,
            EcdsaSighashType::All,
        )?);

        let speedup_input_0_signature = bitcoin::ecdsa::Signature {
            signature: key_manager
                .sign_ecdsa_message(&speedup_input_0_hash, &transaction_to_speedup_utxo.pub_key)?,
            sighash_type: EcdsaSighashType::All,
        };

        let witness_input_0 = Witness::p2wpkh(
            &speedup_input_0_signature,
            &transaction_to_speedup_utxo.pub_key.inner,
        );

        // Witness for the funding input 1
        let witness_public_key_hash = funding_transaction_utxo
            .pub_key
            .wpubkey_hash()
            .expect("key is compressed");
        let value = Amount::from_sat(funding_transaction_utxo.amount);
        let script_pubkey = ScriptBuf::new_p2wpkh(&witness_public_key_hash);

        let funding_input_1_hash = Message::from(sighasher.p2wpkh_signature_hash(
            1,
            &script_pubkey,
            value,
            EcdsaSighashType::All,
        )?);

        let funding_input_1_signature = bitcoin::ecdsa::Signature {
            signature: key_manager
                .sign_ecdsa_message(&funding_input_1_hash, &funding_transaction_utxo.pub_key)?,
            sighash_type: EcdsaSighashType::All,
        };

        let witness_input_1 = Witness::p2wpkh(
            &funding_input_1_signature,
            &funding_transaction_utxo.pub_key.inner,
        );

        // Attach the witnesses to the transaction
        speedup_transaction.input[0].witness = witness_input_0;
        speedup_transaction.input[1].witness = witness_input_1;

        Ok(speedup_transaction)
    }

    pub fn next_transactions(
        &self,
        transaction_name: &str,
    ) -> Result<Vec<String>, ProtocolBuilderError> {
        let next_transactions = self
            .graph
            .get_dependencies(transaction_name)?
            .iter()
            .map(|(tx, _)| tx.clone())
            .collect();
        Ok(next_transactions)
    }

    pub fn spending_info(
        &self,
        transaction_name: &str,
    ) -> Result<Vec<InputSpendingInfo>, ProtocolBuilderError> {
        Ok(self.graph.get_transaction_spending_info(transaction_name)?)
    }

    pub fn spending_infos(
        &self,
    ) -> Result<HashMap<String, Vec<InputSpendingInfo>>, ProtocolBuilderError> {
        Ok(self.graph.get_transaction_spending_infos()?)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn transaction_names(&self) -> Vec<String> {
        self.graph.get_transaction_names()
    }

    pub fn get_transaction_ids(&self) -> Vec<Txid> {
        self.graph.get_transaction_ids()
    }

    pub fn transaction_with_id(&self, txid: Txid) -> Result<&Transaction, ProtocolBuilderError> {
        Ok(self.graph.get_transaction_with_id(txid)?)
    }

    pub fn transaction_name_by_id(&self, txid: Txid) -> Result<&String, ProtocolBuilderError> {
        Ok(self.graph.get_transaction_name_by_id(txid)?)
    }

    pub fn transaction_without_witness(
        &self,
        transaction_name: &str,
    ) -> Result<Transaction, ProtocolBuilderError> {
        let transaction = self.transaction(transaction_name)?.clone();
        Ok(transaction)
    }

    pub fn transaction(
        &self,
        transaction_name: &str,
    ) -> Result<&Transaction, ProtocolBuilderError> {
        Ok(self.graph.get_transaction(transaction_name)?)
    }

    pub fn signatures(
        &self,
    ) -> Result<HashMap<String, Vec<InputSignatures>>, ProtocolBuilderError> {
        Ok(self.graph.get_all_signatures()?)
    }

    pub fn input_ecdsa_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
    ) -> Result<Option<bitcoin::ecdsa::Signature>, ProtocolBuilderError> {
        let input_signature = self
            .graph
            .get_input_ecdsa_signature(transaction_name, input_index)?;
        Ok(input_signature)
    }

    pub fn input_taproot_script_spend_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
        leaf_index: usize,
    ) -> Result<Option<bitcoin::taproot::Signature>, ProtocolBuilderError> {
        let input_signature = self.graph.get_input_taproot_script_spend_signature(
            transaction_name,
            input_index,
            leaf_index,
        )?;
        Ok(input_signature)
    }

    pub fn input_taproot_key_spend_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
    ) -> Result<Option<bitcoin::taproot::Signature>, ProtocolBuilderError> {
        let input_signature = self
            .graph
            .get_input_taproot_key_spend_signature(transaction_name, input_index)?;
        Ok(input_signature)
    }

    pub fn get_script_to_spend(
        &self,
        transaction_name: &str,
        input_index: u32,
        script_index: u32,
    ) -> Result<ProtocolScript, ProtocolBuilderError> {
        let input_spending_info = self
            .graph
            .get_input_spending_info(transaction_name, input_index as usize)?;

        let script = match input_spending_info.spending_type()? {
            OutputType::TaprootScriptUnspendableKey {
                spending_scripts, ..
            } => spending_scripts[script_index as usize].clone(),
            OutputType::TaprootScriptAndKey {
                spending_scripts, ..
            } => spending_scripts[script_index as usize].clone(),
            // TODO complete this for all other spending types and remove the "Unknown output type".to_string() value in the error
            OutputType::SegwitScript { script, .. } => script.clone(),
            _ => {
                return Err(ProtocolBuilderError::InvalidSpendingTypeForScript(
                    transaction_name.to_string(),
                    input_index,
                    script_index,
                    "Unknown output type".to_string(),
                ))
            }
        };

        Ok(script)
    }

    pub fn visualize(&self) -> Result<String, ProtocolBuilderError> {
        Ok(self.graph.visualize()?)
    }

    fn add_transaction_output(
        &mut self,
        transaction_name: &str,
        value: Amount,
        script_pubkey: ScriptBuf,
        spending_type: OutputType,
    ) -> Result<(), ProtocolBuilderError> {
        Self::check_empty_transaction_name(transaction_name)?;

        let mut transaction = self.get_or_create_transaction(transaction_name)?;

        transaction.output.push(transaction::TxOut {
            value,
            script_pubkey,
        });

        self.graph
            .add_transaction_output(transaction_name, transaction, spending_type)?;

        Ok(())
    }

    fn add_transaction_input(
        &mut self,
        previous_txid: Txid,
        previous_output: u32,
        transaction_name: &str,
        sequence: Sequence,
        sighash_type: &SighashType,
    ) -> Result<(), ProtocolBuilderError> {
        Self::check_empty_transaction_name(transaction_name)?;

        let mut transaction = self.get_or_create_transaction(transaction_name)?;

        transaction.input.push(transaction::TxIn {
            previous_output: OutPoint {
                txid: previous_txid,
                vout: previous_output,
            },
            script_sig: ScriptBuf::default(),
            sequence,
            witness: Witness::default(),
        });

        self.graph
            .add_transaction_input(transaction_name, transaction, sighash_type)?;

        Ok(())
    }

    fn get_or_create_transaction(
        &mut self,
        transaction_name: &str,
    ) -> Result<Transaction, ProtocolBuilderError> {
        if !self.graph.contains_transaction(transaction_name) {
            let transaction = Protocol::transaction_template();
            self.graph.add_transaction(transaction_name, transaction)?;
        };

        Ok(self
            .graph
            .get_transaction(transaction_name)
            .unwrap()
            .clone())
    }

    fn transaction_template() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,            // Post BIP-68.
            lock_time: locktime::absolute::LockTime::ZERO, // Ignore the locktime.
            input: vec![],
            output: vec![],
        }
    }

    fn get_dependencies(
        &self,
        transaction_name: &str,
    ) -> Result<Vec<(String, u32)>, ProtocolBuilderError> {
        Ok(self.graph.get_dependencies(transaction_name)?)
    }

    /// Updates the txids of each transaction in the DAG in topological order.
    /// It will update the txid of the transaction and the txid of the connected inputs.
    fn update_transaction_ids(&mut self) -> Result<(), ProtocolBuilderError> {
        let sorted_transactions = self.graph.sort()?;

        for from in sorted_transactions {
            let transaction = self.transaction(&from)?;
            let txid = transaction.compute_txid();

            for (to, input_index) in self.get_dependencies(&from)? {
                let mut dependency = self.transaction(&to)?.clone();
                dependency.input[input_index as usize].previous_output.txid = txid;

                self.graph.update_transaction(&to, dependency)?;
            }
        }

        Ok(())
    }

    fn compute_sighashes<K: KeyStore>(
        &mut self,
        key_manager: &Rc<KeyManager<K>>,
    ) -> Result<(), ProtocolBuilderError> {
        let sorted_transactions = self.graph.sort()?;

        for transaction_name in sorted_transactions {
            let input_spending_info = self
                .graph
                .get_transaction_spending_info(&transaction_name)?;

            for (index, spending_info) in input_spending_info.iter().enumerate() {
                match spending_info.sighash_type() {
                    SighashType::Taproot(tap_sighash_type) => {
                        match spending_info.spending_type()? {
                            OutputType::TaprootTweakedKey { key, prevouts, .. } => {
                                self.taproot_key_spend_sighash(
                                    &transaction_name,
                                    index,
                                    key,
                                    tap_sighash_type,
                                    prevouts,
                                    key_manager,
                                )?;
                            }
                            OutputType::TaprootUntweakedKey { key, prevouts } => {
                                self.taproot_key_spend_sighash(
                                    &transaction_name,
                                    index,
                                    key,
                                    tap_sighash_type,
                                    prevouts,
                                    key_manager,
                                )?;
                            }
                            OutputType::TaprootScriptUnspendableKey {
                                ref spending_scripts,
                                ref spend_info,
                                ref internal_key,
                                ref prevouts,
                            } => {
                                self.taproot_script_spend_sighash(
                                    &transaction_name,
                                    index,
                                    internal_key,
                                    spend_info.merkle_root(),
                                    spending_scripts,
                                    tap_sighash_type,
                                    prevouts,
                                    key_manager,
                                    false,
                                )?;
                            }
                            OutputType::TaprootScriptAndKey {
                                ref spending_scripts,
                                ref spend_info,
                                ref internal_key,
                                ref prevouts,
                            } => {
                                self.taproot_script_spend_sighash(
                                    &transaction_name,
                                    index,
                                    internal_key,
                                    spend_info.merkle_root(),
                                    spending_scripts,
                                    tap_sighash_type,
                                    prevouts,
                                    key_manager,
                                    true,
                                )?;
                            }
                            _ => {
                                return Err(ProtocolBuilderError::InvalidSpendingTypeForSighashType)
                            }
                        };
                    }
                    SighashType::Ecdsa(ecdsa_sighash_type) => {
                        match spending_info.spending_type()? {
                            OutputType::SegwitPublicKey { public_key, value } => {
                                self.segwit_key_spend_sighash(
                                    &transaction_name,
                                    index,
                                    public_key,
                                    value,
                                    ecdsa_sighash_type,
                                )?;
                            }
                            OutputType::SegwitScript { ref script, value } => {
                                self.segwit_script_spend_sighash(
                                    &transaction_name,
                                    index,
                                    script,
                                    value,
                                    ecdsa_sighash_type,
                                )?;
                            }
                            OutputType::SegwitUnspendable {} => {}
                            _ => {
                                return Err(ProtocolBuilderError::InvalidSpendingTypeForSighashType)
                            }
                        };
                    }
                };
            }
        }

        Ok(())
    }

    fn compute_signatures<K: KeyStore>(
        &mut self,
        key_manager: &KeyManager<K>,
    ) -> Result<(), ProtocolBuilderError> {
        let sorted_transactions = self.graph.sort()?;

        for transaction_name in sorted_transactions {
            let input_spending_info = self
                .graph
                .get_transaction_spending_info(&transaction_name)?;

            for (index, spending_info) in input_spending_info.iter().enumerate() {
                match spending_info.sighash_type() {
                    SighashType::Taproot(tap_sighash_type) => {
                        match spending_info.spending_type()? {
                            OutputType::TaprootTweakedKey { key, tweak, .. } => {
                                self.taproot_key_spend_signature(
                                    &transaction_name,
                                    index,
                                    tap_sighash_type,
                                    key_manager,
                                    key,
                                    Some(tweak),
                                )?;
                            }
                            OutputType::TaprootUntweakedKey { key, .. } => {
                                self.taproot_key_spend_signature(
                                    &transaction_name,
                                    index,
                                    tap_sighash_type,
                                    key_manager,
                                    key,
                                    None,
                                )?;
                            }
                            OutputType::TaprootScriptUnspendableKey {
                                ref spending_scripts,
                                internal_key,
                                ..
                            } => {
                                self.taproot_script_spend_signature(
                                    &transaction_name,
                                    index,
                                    spending_scripts,
                                    tap_sighash_type,
                                    internal_key,
                                    key_manager,
                                    false,
                                )?;
                            }
                            OutputType::TaprootScriptAndKey {
                                ref spending_scripts,
                                internal_key,
                                ..
                            } => {
                                self.taproot_script_spend_signature(
                                    &transaction_name,
                                    index,
                                    spending_scripts,
                                    tap_sighash_type,
                                    internal_key,
                                    key_manager,
                                    true,
                                )?;
                            }
                            _ => {
                                return Err(ProtocolBuilderError::InvalidSpendingTypeForSighashType)
                            }
                        };
                    }
                    SighashType::Ecdsa(ecdsa_sighash_type) => {
                        match spending_info.spending_type()? {
                            OutputType::SegwitPublicKey { public_key, .. } => {
                                self.segwit_key_spend_signature(
                                    &transaction_name,
                                    index,
                                    public_key,
                                    ecdsa_sighash_type,
                                    key_manager,
                                )?;
                            }
                            OutputType::SegwitScript { ref script, .. } => {
                                self.segwit_script_spend_signature(
                                    &transaction_name,
                                    index,
                                    script,
                                    ecdsa_sighash_type,
                                    key_manager,
                                )?;
                            }
                            OutputType::SegwitUnspendable {} => {}
                            _ => {
                                return Err(ProtocolBuilderError::InvalidSpendingTypeForSighashType)
                            }
                        };
                    }
                };
            }
        }

        Ok(())
    }

    fn compute_sighashes_and_signatures<K: KeyStore>(
        &mut self,
        key_manager: &KeyManager<K>,
    ) -> Result<(), ProtocolBuilderError> {
        let sorted_transactions = self.graph.sort()?;

        for transaction_name in sorted_transactions {
            let input_spending_info = self
                .graph
                .get_transaction_spending_info(&transaction_name)?;

            for (index, spending_info) in input_spending_info.iter().enumerate() {
                match spending_info.sighash_type() {
                    SighashType::Taproot(tap_sighash_type) => {
                        match spending_info.spending_type()? {
                            OutputType::TaprootTweakedKey {
                                key,
                                tweak,
                                prevouts,
                            } => {
                                self.taproot_key_spend_sighash_and_signature(
                                    &transaction_name,
                                    index,
                                    key,
                                    Some(tweak),
                                    prevouts,
                                    tap_sighash_type,
                                    key_manager,
                                )?;
                            }
                            OutputType::TaprootUntweakedKey { key, prevouts } => {
                                self.taproot_key_spend_sighash_and_signature(
                                    &transaction_name,
                                    index,
                                    key,
                                    None,
                                    prevouts,
                                    tap_sighash_type,
                                    key_manager,
                                )?;
                            }
                            OutputType::TaprootScriptUnspendableKey {
                                ref spending_scripts,
                                ref internal_key,
                                ref spend_info,
                                ref prevouts,
                            } => {
                                self.taproot_script_spend_sighash_and_signature(
                                    &transaction_name,
                                    index,
                                    internal_key,
                                    spend_info.merkle_root(),
                                    spending_scripts,
                                    prevouts,
                                    tap_sighash_type,
                                    key_manager,
                                    false,
                                )?;
                            }
                            OutputType::TaprootScriptAndKey {
                                ref spending_scripts,
                                ref internal_key,
                                ref spend_info,
                                ref prevouts,
                            } => {
                                self.taproot_script_spend_sighash_and_signature(
                                    &transaction_name,
                                    index,
                                    internal_key,
                                    spend_info.merkle_root(),
                                    spending_scripts,
                                    prevouts,
                                    tap_sighash_type,
                                    key_manager,
                                    true,
                                )?;
                            }
                            _ => {
                                return Err(ProtocolBuilderError::InvalidSpendingTypeForSighashType)
                            }
                        };
                    }
                    SighashType::Ecdsa(ecdsa_sighash_type) => {
                        match spending_info.spending_type()? {
                            OutputType::SegwitPublicKey { public_key, value } => {
                                self.segwit_key_spend_sighash_and_signature(
                                    &transaction_name,
                                    index,
                                    public_key,
                                    value,
                                    ecdsa_sighash_type,
                                    key_manager,
                                )?;
                            }
                            OutputType::SegwitScript { ref script, value } => {
                                self.segwit_script_spend_sighash_and_signature(
                                    &transaction_name,
                                    index,
                                    script,
                                    value,
                                    ecdsa_sighash_type,
                                    key_manager,
                                )?;
                            }
                            OutputType::SegwitUnspendable {} => {}
                            _ => {
                                return Err(ProtocolBuilderError::InvalidSpendingTypeForSighashType)
                            }
                        };
                    }
                };
            }
        }

        Ok(())
    }

    fn get_witness_for_input(
        &self,
        input_index: usize,
        spending_condition: &InputSpendingInfo,
        spending_args: &SpendingArgs,
    ) -> Result<Witness, ProtocolBuilderError> {
        let witness = match spending_condition.sighash_type() {
            SighashType::Taproot(..) => match spending_condition.spending_type()? {
                OutputType::TaprootTweakedKey { .. } => {
                    self.taproot_key_spend_witness(spending_args)?
                }
                OutputType::TaprootUntweakedKey { .. } => {
                    self.taproot_key_spend_witness(spending_args)?
                }
                OutputType::TaprootScriptUnspendableKey { ref spend_info, .. } => {
                    match spending_args.get_taproot_leaf() {
                        Some(taproot_leaf) => self.taproot_script_spend_witness(
                            input_index,
                            &taproot_leaf,
                            spend_info,
                            spending_args,
                        )?,
                        None => return Err(ProtocolBuilderError::MissingTaprootLeaf(input_index)),
                    }
                }
                OutputType::TaprootScriptAndKey { ref spend_info, .. } => {
                    // This could be a script spend or a key spend. Check if taproot_leaf is present to determine.
                    match spending_args.get_taproot_leaf() {
                        Some(taproot_leaf) => self.taproot_script_spend_witness(
                            input_index,
                            &taproot_leaf,
                            spend_info,
                            spending_args,
                        )?,
                        None => self.taproot_key_spend_witness(spending_args)?,
                    }
                }
                _ => return Err(ProtocolBuilderError::InvalidSpendingTypeForSighashType),
            },
            SighashType::Ecdsa(..) => match spending_condition.spending_type()? {
                OutputType::SegwitPublicKey { public_key, .. } => {
                    self.segwit_key_spend_witness(public_key, spending_args)?
                }
                OutputType::SegwitScript { ref script, .. } => {
                    self.segwit_script_spend_witness(script, spending_args)?
                }
                OutputType::SegwitUnspendable {} => {
                    // Create an empty witness for unspendable outputs
                    Witness::new()
                }
                _ => return Err(ProtocolBuilderError::InvalidSpendingTypeForSighashType),
            },
        };

        Ok(witness)
    }

    pub fn create_unspendable_key() -> Result<UntweakedPublicKey, ProtocolBuilderError> {
        let mut rng = secp256k1::rand::thread_rng();
        let key = XOnlyPublicKey::from(unspendable_key(&mut rng)?);
        Ok(key)
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_key_spend_sighash<K: KeyStore>(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        key: &PublicKey,
        sighash_type: &TapSighashType,
        prevouts: &[TxOut],
        key_manager: &Rc<KeyManager<K>>,
    ) -> Result<(), ProtocolBuilderError> {
        let transaction = self.transaction(transaction_name)?.clone();

        let prevouts = if prevouts.is_empty() {
            self.graph.get_prevouts(transaction_name)?
        } else {
            prevouts.to_vec()
        };

        let mut sighasher = SighashCache::new(transaction);

        let hashed_message = Message::from(sighasher.taproot_key_spend_signature_hash(
            input_index,
            &sighash::Prevouts::All(&prevouts),
            *sighash_type,
        )?);

        key_manager.generate_nonce(
            MessageId::new_string_id(transaction_name, input_index as u32, 0).as_str(),
            hashed_message.as_ref().to_vec(),
            key,
            None,
        )?;

        self.graph.update_hashed_messages(
            transaction_name,
            input_index as u32,
            vec![Some(hashed_message)],
        )?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_script_spend_sighash<K: KeyStore>(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        internal_key: &XOnlyPublicKey,
        merkle_root: Option<TapNodeHash>,
        spending_scripts: &[ProtocolScript],
        sighash_type: &TapSighashType,
        prevouts: &[TxOut],
        key_manager: &Rc<KeyManager<K>>,
        compute_key_path: bool,
    ) -> Result<(), ProtocolBuilderError> {
        let transaction = self.transaction(transaction_name)?.clone();
        let prevouts = if prevouts.is_empty() {
            self.graph.get_prevouts(transaction_name)?
        } else {
            prevouts.to_vec()
        };

        let full_public_key: PublicKey = internal_key.public_key(Parity::Even).into();

        let mut sighasher = SighashCache::new(transaction);

        let mut hashed_messages = vec![];
        for (script_index, spending_script) in spending_scripts.iter().enumerate() {
            if spending_script.skip_signing() {
                hashed_messages.push(None);
                continue;
            }

            let hashed_message = Message::from(sighasher.taproot_script_spend_signature_hash(
                input_index,
                &sighash::Prevouts::All(&prevouts),
                TapLeafHash::from_script(spending_script.get_script(), LeafVersion::TapScript),
                *sighash_type,
            )?);

            key_manager.generate_nonce(
                MessageId::new_string_id(transaction_name, input_index as u32, script_index as u32)
                    .as_str(),
                hashed_message.as_ref().to_vec(),
                &full_public_key,
                None,
            )?;

            hashed_messages.push(Some(hashed_message));
        }

        if compute_key_path {
            // Compute and push a message hash for the key spend signature.
            let key_spend_hashed_message =
                Message::from(sighasher.taproot_key_spend_signature_hash(
                    input_index,
                    &sighash::Prevouts::All(&prevouts),
                    *sighash_type,
                )?);

            let tweak = TapTweakHash::from_key_and_tweak(*internal_key, merkle_root).to_scalar();
            let musig2_tweak =
                musig2::secp256k1::Scalar::from_be_bytes(tweak.to_be_bytes()).unwrap();

            key_manager.generate_nonce(
                MessageId::new_string_id(
                    transaction_name,
                    input_index as u32,
                    spending_scripts.len() as u32,
                )
                .as_str(),
                key_spend_hashed_message.as_ref().to_vec(),
                &full_public_key,
                Some(musig2_tweak),
            )?;

            hashed_messages.push(Some(key_spend_hashed_message));
        };

        self.graph.update_hashed_messages(
            transaction_name,
            input_index as u32,
            hashed_messages,
        )?;

        Ok(())
    }

    fn segwit_key_spend_sighash(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        public_key: &PublicKey,
        value: &Amount,
        sighash_type: &EcdsaSighashType,
    ) -> Result<(), ProtocolBuilderError> {
        let transaction = self.transaction(transaction_name)?.clone();
        let wpkh = public_key.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        let mut sighasher = SighashCache::new(transaction);

        let hashed_message = Message::from(sighasher.p2wpkh_signature_hash(
            input_index,
            &script_pubkey,
            *value,
            *sighash_type,
        )?);

        self.graph.update_hashed_messages(
            transaction_name,
            input_index as u32,
            vec![Some(hashed_message)],
        )?;
        Ok(())
    }

    fn segwit_script_spend_sighash(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        script: &ProtocolScript,
        value: &Amount,
        sighash_type: &EcdsaSighashType,
    ) -> Result<(), ProtocolBuilderError> {
        let hashed_messages = if script.skip_signing() {
            vec![None]
        } else {
            let transaction = self.transaction(transaction_name)?.clone();
            let script_hash = WScriptHash::from(script.get_script().clone());
            let script_pubkey = ScriptBuf::new_p2wsh(&script_hash);

            let mut sighasher = SighashCache::new(transaction);

            let hashed_message = Message::from(sighasher.p2wsh_signature_hash(
                input_index,
                &script_pubkey,
                *value,
                *sighash_type,
            )?);

            vec![Some(hashed_message)]
        };

        self.graph
            .update_hashed_messages(transaction_name, input_index as u32, hashed_messages)?;
        Ok(())
    }

    fn taproot_key_spend_signature<K: KeyStore>(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        sighash_type: &TapSighashType,
        key_manager: &KeyManager<K>,
        aggregated_key: &PublicKey,
        _tweak: Option<&Scalar>,
    ) -> Result<(), ProtocolBuilderError> {
        let hashed_messages = self.graph.get_transaction_spending_info(transaction_name)?
            [input_index]
            .hashed_messages()
            .clone();
        //warn!("key spend signature: {:?}", aggregated_key);
        // There must be only one hashed message for the key spend path
        assert!(hashed_messages.len() == 1);

        let message_id = MessageId::new_string_id(transaction_name, input_index as u32, 0);
        let schnorr_signature =
            key_manager.get_aggregated_signature(aggregated_key, &message_id)?;

        let signature = Signature::Taproot(bitcoin::taproot::Signature {
            signature: schnorr_signature,
            sighash_type: *sighash_type,
        });

        self.graph.update_input_signatures(
            transaction_name,
            input_index as u32,
            vec![Some(signature)],
        )?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_script_spend_signature<K: KeyStore>(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        spending_scripts: &[ProtocolScript],
        sighash_type: &TapSighashType,
        internal_key: &XOnlyPublicKey,
        key_manager: &KeyManager<K>,
        compute_key_path: bool,
    ) -> Result<(), ProtocolBuilderError> {
        let mut signatures = vec![];
        let hashed_messages = self.graph.get_transaction_spending_info(transaction_name)?
            [input_index]
            .hashed_messages()
            .clone();
        //warn!("taproot script spend signature: {:?}", internal_key);
        // There must be an extra hashed message for the key spend path.
        assert!(spending_scripts.len() + 1 == hashed_messages.len());

        let full_public_key: PublicKey = internal_key.public_key(Parity::Even).into();
        for (index, script) in spending_scripts.iter().enumerate() {
            if script.skip_signing() {
                signatures.push(None);
                continue;
            }

            let message_id =
                MessageId::new_string_id(transaction_name, input_index as u32, index as u32);
            let schnorr_signature =
                key_manager.get_aggregated_signature(&full_public_key, &message_id)?;

            let signature = Signature::Taproot(bitcoin::taproot::Signature {
                signature: schnorr_signature,
                sighash_type: *sighash_type,
            });

            signatures.push(Some(signature));
        }

        if compute_key_path {
            // Compute and push the key spend signature.
            let message_id = MessageId::new_string_id(
                transaction_name,
                input_index as u32,
                spending_scripts.len() as u32,
            );
            let schnorr_signature =
                key_manager.get_aggregated_signature(&full_public_key, &message_id)?;
            let key_spend_signature = Signature::Taproot(bitcoin::taproot::Signature {
                signature: schnorr_signature,
                sighash_type: *sighash_type,
            });

            signatures.push(Some(key_spend_signature));
        }

        // Update signatures for the input
        self.graph
            .update_input_signatures(transaction_name, input_index as u32, signatures)?;

        Ok(())
    }

    fn segwit_key_spend_signature<K: KeyStore>(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        public_key: &PublicKey,
        sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager<K>,
    ) -> Result<(), ProtocolBuilderError> {
        let hashed_messages = self.graph.get_transaction_spending_info(transaction_name)?
            [input_index]
            .hashed_messages()
            .clone();

        // There must be only one hashed message for the key spend path
        assert!(hashed_messages.len() == 1);

        let message = match hashed_messages[0] {
            Some(ref message) => message,
            None => {
                return Err(ProtocolBuilderError::MissingMessage(
                    transaction_name.to_string(),
                    input_index as u32,
                ))
            }
        };

        let ecdsa_signature = key_manager.sign_ecdsa_message(message, public_key)?;
        let signature = Signature::Ecdsa(bitcoin::ecdsa::Signature {
            signature: ecdsa_signature,
            sighash_type: *sighash_type,
        });

        self.graph.update_input_signatures(
            transaction_name,
            input_index as u32,
            vec![Some(signature)],
        )?;
        Ok(())
    }

    fn segwit_script_spend_signature<K: KeyStore>(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        script: &ProtocolScript,
        sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager<K>,
    ) -> Result<(), ProtocolBuilderError> {
        let signatures = if script.skip_signing() {
            vec![None]
        } else {
            let hashed_messages = self.graph.get_transaction_spending_info(transaction_name)?
                [input_index]
                .hashed_messages()
                .clone();

            // There must be only one hashed message for the script spend path
            assert!(hashed_messages.len() == 1);

            let message = match hashed_messages[0] {
                Some(ref message) => message,
                None => {
                    return Err(ProtocolBuilderError::MissingMessage(
                        transaction_name.to_string(),
                        input_index as u32,
                    ))
                }
            };

            let ecdsa_signature =
                key_manager.sign_ecdsa_message(message, &script.get_verifying_key())?;
            vec![Some(Signature::Ecdsa(bitcoin::ecdsa::Signature {
                signature: ecdsa_signature,
                sighash_type: *sighash_type,
            }))]
        };

        self.graph
            .update_input_signatures(transaction_name, input_index as u32, signatures)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_key_spend_sighash_and_signature<K: KeyStore>(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        key: &PublicKey,
        tweak: Option<&Scalar>,
        prevouts: &[TxOut],
        sighash_type: &TapSighashType,
        key_manager: &KeyManager<K>,
    ) -> Result<(), ProtocolBuilderError> {
        let transaction = self.transaction(transaction_name)?.clone();

        let prevouts = if prevouts.is_empty() {
            self.graph.get_prevouts(transaction_name)?
        } else {
            prevouts.to_vec()
        };

        let mut sighasher = SighashCache::new(transaction);

        let hashed_message = Message::from(sighasher.taproot_key_spend_signature_hash(
            input_index,
            &sighash::Prevouts::All(&prevouts),
            *sighash_type,
        )?);

        let (schnorr_signature, _) = match tweak {
            Some(t) => key_manager.sign_schnorr_message_with_tweak(&hashed_message, key, t)?,
            None => key_manager.sign_schnorr_message_with_tap_tweak(&hashed_message, key, None)?,
        };

        let signature = Signature::Taproot(bitcoin::taproot::Signature {
            signature: schnorr_signature,
            sighash_type: *sighash_type,
        });

        self.graph.update_hashed_messages(
            transaction_name,
            input_index as u32,
            vec![Some(hashed_message)],
        )?;
        self.graph.update_input_signatures(
            transaction_name,
            input_index as u32,
            vec![Some(signature)],
        )?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn taproot_script_spend_sighash_and_signature<K: KeyStore>(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        internal_key: &XOnlyPublicKey,
        merkle_root: Option<TapNodeHash>,
        spending_scripts: &Vec<ProtocolScript>,
        prevouts: &[TxOut],
        sighash_type: &TapSighashType,
        key_manager: &KeyManager<K>,
        compute_key_path: bool,
    ) -> Result<(), ProtocolBuilderError> {
        let transaction = self.transaction(transaction_name)?.clone();
        let prevouts = if prevouts.is_empty() {
            self.graph.get_prevouts(transaction_name)?
        } else {
            prevouts.to_vec()
        };

        let mut sighasher = SighashCache::new(transaction);

        let mut hashed_messages = vec![];
        let mut signatures = vec![];
        for spending_script in spending_scripts {
            if spending_script.skip_signing() {
                hashed_messages.push(None);
                signatures.push(None);
                continue;
            }

            let hashed_message = Message::from(sighasher.taproot_script_spend_signature_hash(
                input_index,
                &sighash::Prevouts::All(&prevouts),
                TapLeafHash::from_script(spending_script.get_script(), LeafVersion::TapScript),
                *sighash_type,
            )?);

            let schnorr_signature = key_manager
                .sign_schnorr_message(&hashed_message, &spending_script.get_verifying_key())?;
            let signature = Signature::Taproot(bitcoin::taproot::Signature {
                signature: schnorr_signature,
                sighash_type: *sighash_type,
            });

            hashed_messages.push(Some(hashed_message));
            signatures.push(Some(signature));
        }

        if compute_key_path {
            // Compute a sighash and its signature for the key spend path.

            // Reconstruct the bitcoin::PublicKey from the XOnlyPublicKey to sign the message using the KeyManager.
            // Taproot internal keys always have an Even parity.
            let full_public_key: PublicKey = internal_key.public_key(Parity::Even).into();

            // Compute and push a message hash for the key spend signature.
            let key_spend_hashed_message =
                Message::from(sighasher.taproot_key_spend_signature_hash(
                    input_index,
                    &sighash::Prevouts::All(&prevouts),
                    *sighash_type,
                )?);

            hashed_messages.push(Some(key_spend_hashed_message));

            // Compute and push the key spend signature.
            let (schnorr_signature, output_key) = key_manager.sign_schnorr_message_with_tap_tweak(
                &key_spend_hashed_message,
                &full_public_key,
                merkle_root,
            )?;

            let key_spend_signature = Signature::Taproot(bitcoin::taproot::Signature {
                signature: schnorr_signature,
                sighash_type: *sighash_type,
            });

            // Verify the signature:
            if !SignatureVerifier::new().verify_schnorr_signature(
                &schnorr_signature,
                &key_spend_hashed_message,
                output_key,
            ) {
                return Err(ProtocolBuilderError::KeySpendSignatureGenerationFailed);
            }

            signatures.push(Some(key_spend_signature));
        };

        // Update hashes and signatures for the input
        self.graph.update_hashed_messages(
            transaction_name,
            input_index as u32,
            hashed_messages,
        )?;
        
        self.graph
            .update_input_signatures(transaction_name, input_index as u32, signatures)?;

        Ok(())
    }

    fn segwit_key_spend_sighash_and_signature<K: KeyStore>(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        public_key: &PublicKey,
        value: &Amount,
        sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager<K>,
    ) -> Result<(), ProtocolBuilderError> {
        let transaction = self.transaction(transaction_name)?.clone();
        let wpkh = public_key.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        let mut sighasher = SighashCache::new(transaction);

        let hashed_message = Message::from(sighasher.p2wpkh_signature_hash(
            input_index,
            &script_pubkey,
            *value,
            *sighash_type,
        )?);

        let ecdsa_signature = key_manager.sign_ecdsa_message(&hashed_message, public_key)?;
        let signature = Signature::Ecdsa(bitcoin::ecdsa::Signature {
            signature: ecdsa_signature,
            sighash_type: *sighash_type,
        });

        self.graph.update_hashed_messages(
            transaction_name,
            input_index as u32,
            vec![Some(hashed_message)],
        )?;
        self.graph.update_input_signatures(
            transaction_name,
            input_index as u32,
            vec![Some(signature)],
        )?;
        Ok(())
    }

    fn segwit_script_spend_sighash_and_signature<K: KeyStore>(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        script: &ProtocolScript,
        value: &Amount,
        sighash_type: &EcdsaSighashType,
        key_manager: &KeyManager<K>,
    ) -> Result<(), ProtocolBuilderError> {
        let (hashed_messages, signatures) = if script.skip_signing() {
            (vec![None], vec![None])
        } else {
            let transaction = self.transaction(transaction_name)?.clone();
            let script_hash = WScriptHash::from(script.get_script().clone());
            let script_pubkey = ScriptBuf::new_p2wsh(&script_hash);

            let mut sighasher = SighashCache::new(transaction);

            let hashed_message = Message::from(sighasher.p2wsh_signature_hash(
                input_index,
                &script_pubkey,
                *value,
                *sighash_type,
            )?);

            let ecdsa_signature =
                key_manager.sign_ecdsa_message(&hashed_message, &script.get_verifying_key())?;
            let signature = Signature::Ecdsa(bitcoin::ecdsa::Signature {
                signature: ecdsa_signature,
                sighash_type: *sighash_type,
            });

            (vec![Some(hashed_message)], vec![Some(signature)])
        };

        self.graph
            .update_hashed_messages(transaction_name, input_index as u32, hashed_messages)?;
        self.graph
            .update_input_signatures(transaction_name, input_index as u32, signatures)?;

        Ok(())
    }

    fn taproot_key_spend_witness(
        &self,
        spending_args: &SpendingArgs,
    ) -> Result<Witness, ProtocolBuilderError> {
        let mut witness = Witness::default();
        for value in spending_args.iter() {
            witness.push(value.clone());
            //last element in script_args is the signature
            //witness.push(signature.serialize());
        }

        Ok(witness)
    }

    fn taproot_script_spend_witness(
        &self,
        input_index: usize,
        taproot_leaf: &ScriptBuf,
        spend_info: &TaprootSpendInfo,
        spending_args: &SpendingArgs,
    ) -> Result<Witness, ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();

        let control_block =
            match spend_info.control_block(&(taproot_leaf.clone(), LeafVersion::TapScript)) {
                Some(cb) => cb,
                None => return Err(ProtocolBuilderError::InvalidSpendingScript(input_index)),
            };

        if !control_block.verify_taproot_commitment(
            &secp,
            spend_info.output_key().to_inner(),
            taproot_leaf,
        ) {
            return Err(ProtocolBuilderError::InvalidSpendingScript(input_index));
        }

        let mut witness = Witness::default();

        for value in spending_args.iter() {
            witness.push(value.clone());
            //last element in script_args is the signature
            //witness.push(signature.serialize());
        }

        witness.push(taproot_leaf.to_bytes());
        witness.push(control_block.serialize());

        Ok(witness)
    }

    fn segwit_key_spend_witness(
        &self,
        public_key: &PublicKey,
        spending_args: &SpendingArgs,
    ) -> Result<Witness, ProtocolBuilderError> {
        let mut witness = Witness::default();
        for value in spending_args.iter() {
            witness.push(value.clone());
            //last element in script_args is the signature
            //witness.push(signature.serialize());
        }

        witness.push(public_key.to_bytes());
        Ok(witness)
    }

    fn segwit_script_spend_witness(
        &self,
        script: &ProtocolScript,
        spending_args: &SpendingArgs,
    ) -> Result<Witness, ProtocolBuilderError> {
        let mut witness = Witness::default();
        for value in spending_args.iter() {
            witness.push(value.clone());
            //last element in script_args is the signature
            //witness.push(signature.serialize());
        }

        witness.push(script.get_script().to_bytes());
        Ok(witness)
    }

    fn check_empty_scripts(
        spending_scripts: &[ProtocolScript],
    ) -> Result<(), ProtocolBuilderError> {
        if spending_scripts.is_empty() {
            return Err(ProtocolBuilderError::EmptySpendingScripts);
        }

        Ok(())
    }

    fn check_empty_transaction_name(name: &str) -> Result<(), ProtocolBuilderError> {
        if name.trim().is_empty() || name.chars().all(|c| c == '\t') {
            return Err(ProtocolBuilderError::MissingTransactionName);
        }

        Ok(())
    }

    fn check_empty_connection_name(name: &str) -> Result<(), ProtocolBuilderError> {
        if name.trim().is_empty() || name.chars().all(|c| c == '\t') {
            return Err(ProtocolBuilderError::MissingTransactionName);
        }

        Ok(())
    }

    fn check_zero_rounds(rounds: u32) -> Result<(), ProtocolBuilderError> {
        if rounds == 0 {
            return Err(ProtocolBuilderError::InvalidZeroRounds);
        }

        Ok(())
    }
}
