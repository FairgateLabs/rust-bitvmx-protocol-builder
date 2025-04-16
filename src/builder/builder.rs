use bitcoin::{
    hashes::Hash,
    secp256k1::{Message, Scalar},
    sighash::SighashCache,
    Address, Amount, EcdsaSighashType, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use key_manager::{key_manager::KeyManager, keystorage::keystore::KeyStore};

use crate::{
    errors::ProtocolBuilderError,
    scripts::{self, ProtocolScript},
    types::{input::SighashType, output::OutputType, Utxo},
};

use super::{
    check_params::{check_empty_scripts, check_zero_rounds},
    Protocol,
};

pub struct ProtocolBuilder {}

impl ProtocolBuilder {
    pub fn add_taproot_key_spend_output(
        &self,
        protocol: &mut Protocol,
        transaction_name: &str,
        value: u64,
        internal_key: &PublicKey,
        tweak: Option<&Scalar>,
        prevouts: Vec<TxOut>,
    ) -> Result<&Self, ProtocolBuilderError> {
        let output_type = OutputType::tr_key(value, internal_key, tweak, prevouts)?;
        protocol.add_transaction_output(transaction_name, output_type)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_taproot_script_spend_output(
        &self,
        protocol: &mut Protocol,
        transaction_name: &str,
        value: u64,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        with_key_path: bool,
        prevouts: Vec<TxOut>,
    ) -> Result<&Self, ProtocolBuilderError> {
        check_empty_scripts(leaves)?;

        let output_type = OutputType::tr_script(
            value,
            internal_key,
            leaves,
            with_key_path,
            prevouts,
        )?;
        protocol.add_transaction_output(transaction_name, output_type)?;
        Ok(self)
    }

    pub fn add_p2wpkh_output(
        &self,
        protocol: &mut Protocol,
        transaction_name: &str,
        value: u64,
        public_key: &PublicKey,
    ) -> Result<&Self, ProtocolBuilderError> {
        let output_type = OutputType::segwit_key(value, public_key)?;
        protocol.add_transaction_output(transaction_name, output_type)?;
        Ok(self)
    }

    pub fn add_p2wsh_output(
        &self,
        protocol: &mut Protocol,
        transaction_name: &str,
        value: u64,
        script: &ProtocolScript,
    ) -> Result<&Self, ProtocolBuilderError> {
        let output_type = OutputType::segwit_script(value, script)?;
        protocol.add_transaction_output(transaction_name, output_type)?;
        Ok(self)
    }

    pub fn add_speedup_output(
        &self,
        protocol: &mut Protocol,
        transaction_name: &str,
        value: u64,
        speedup_public_key: &PublicKey,
    ) -> Result<&Self, ProtocolBuilderError> {
        self.add_p2wpkh_output(protocol, transaction_name, value, speedup_public_key)
    }

    pub fn add_op_return_output(
        &self,
        protocol: &mut Protocol,
        transaction_name: &str,
        data: Vec<u8>,
    ) -> Result<&Self, ProtocolBuilderError> {
        let output_type = OutputType::segwit_unspendable(scripts::op_return(data))?;
        protocol.add_transaction_output(transaction_name, output_type)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_timelock_output(
        &self,
        protocol: &mut Protocol,
        transaction_name: &str,
        value: u64,
        internal_key: &PublicKey,
        expired_script: &ProtocolScript,
        renew_script: &ProtocolScript,
        with_key_path: bool,
        prevouts: Vec<TxOut>,
    ) -> Result<&Self, ProtocolBuilderError> {
        self.add_taproot_script_spend_output(
            protocol,
            transaction_name,
            value,
            internal_key,
            &[expired_script.clone(), renew_script.clone()],
            with_key_path,
            prevouts,
        )
    }

    pub fn add_timelock_input(
        &self,
        protocol: &mut Protocol,
        transaction_name: &str,
        previous_output: u32,
        blocks: u16,
        sighash_type: &SighashType,
    ) -> Result<&Self, ProtocolBuilderError> {
        let sequence = match blocks {
            0 => Sequence::ENABLE_RBF_NO_LOCKTIME,
            _ => Sequence::from_height(blocks),
        };

        protocol.add_transaction_input(
            Hash::all_zeros(),
            previous_output,
            transaction_name,
            sequence,
            sighash_type,
        )?;
        Ok(self)
    }

    pub fn speedup_transaction<K: KeyStore>(
        &self,
        transaction_to_speedup_utxo: Utxo,
        funding_transaction_utxo: Utxo,
        change_address: Address,
        speedup_fee: u64,
        key_manager: &KeyManager<K>,
    ) -> Result<Transaction, ProtocolBuilderError> {
        //let transaction_to_speedup = protocol.transaction_by_id(&transaction_to_speedup_utxo.txid)?;
        let mut speedup_transaction = Protocol::transaction_template();

        // The speedup input to consume the speedup output of the transaction to speedup
        push_input(&mut speedup_transaction, &transaction_to_speedup_utxo);

        // The speedup input to consume the funding output of the funding transaction
        push_input(&mut speedup_transaction, &funding_transaction_utxo);

        // The speedup output for the change
        push_output(
            &mut speedup_transaction,
            funding_transaction_utxo.amount,
            change_address,
            speedup_fee,
        )?;

        let mut sighasher = SighashCache::new(speedup_transaction.clone());

        // Witness for the speedup input 0
        push_witness(
            &mut speedup_transaction,
            transaction_to_speedup_utxo,
            0,
            key_manager,
            &mut sighasher,
        )?;

        // Witness for the funding input 1
        push_witness(
            &mut speedup_transaction,
            funding_transaction_utxo,
            1,
            key_manager,
            &mut sighasher,
        )?;

        Ok(speedup_transaction)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_taproot_key_spend_connection(
        &self,
        protocol: &mut Protocol,
        connection_name: &str,
        from: &str,
        value: u64,
        internal_key: &PublicKey,
        tweak: Option<&Scalar>,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&Self, ProtocolBuilderError> {
        self.add_taproot_key_spend_output(protocol, from, value, internal_key, tweak, vec![])?;
        let output_index = (protocol.transaction_by_name(from)?.output.len() - 1) as u32;

        protocol.add_transaction_input(
            Hash::all_zeros(),
            output_index,
            to,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            sighash_type,
        )?;
        let input_index = (protocol.transaction_by_name(to)?.input.len() - 1) as u32;

        protocol.connect(connection_name, from, output_index, to, input_index)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_taproot_script_spend_connection(
        &self,
        protocol: &mut Protocol,
        connection_name: &str,
        from: &str,
        value: u64,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        with_key_path: bool,
        prevouts: Vec<TxOut>,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&Self, ProtocolBuilderError> {
        self.add_taproot_script_spend_output(
            protocol,
            from,
            value,
            internal_key,
            leaves,
            with_key_path,
            prevouts,
        )?;
        let output_index = (protocol.transaction_by_name(from)?.output.len() - 1) as u32;

        protocol.add_transaction_input(
            Hash::all_zeros(),
            output_index,
            to,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            sighash_type,
        )?;
        let input_index = (protocol.transaction_by_name(to)?.input.len() - 1) as u32;

        protocol.connect(connection_name, from, output_index, to, input_index)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_p2wpkh_connection(
        &self,
        protocol: &mut Protocol,
        connection_name: &str,
        from: &str,
        value: u64,
        public_key: &PublicKey,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&Self, ProtocolBuilderError> {
        self.add_p2wpkh_output(protocol, from, value, public_key)?;
        let output_index = (protocol.transaction_by_name(from)?.output.len() - 1) as u32;

        protocol.add_transaction_input(
            Hash::all_zeros(),
            output_index,
            to,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            sighash_type,
        )?;
        let input_index = (protocol.transaction_by_name(to)?.input.len() - 1) as u32;

        protocol.connect(connection_name, from, output_index, to, input_index)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_p2wsh_connection(
        &self,
        protocol: &mut Protocol,
        connection_name: &str,
        from: &str,
        value: u64,
        script: &ProtocolScript,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<(), ProtocolBuilderError> {
        self.add_p2wsh_output(protocol, from, value, script)?;
        let output_index = (protocol.transaction_by_name(from)?.output.len() - 1) as u32;

        protocol.add_transaction_input(
            Hash::all_zeros(),
            output_index,
            to,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            sighash_type,
        )?;
        let input_index = (protocol.transaction_by_name(to)?.input.len() - 1) as u32;

        protocol.connect(connection_name, from, output_index, to, input_index)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_timelock_connection(
        &self,
        protocol: &mut Protocol,
        from: &str,
        value: u64,
        internal_key: &PublicKey,
        expired_script: &ProtocolScript,
        renew_script: &ProtocolScript,
        with_key_path: bool,
        prevouts: Vec<TxOut>,
        to: &str,
        _expired_blocks: u16,
        sighash_type: &SighashType,
    ) -> Result<&Self, ProtocolBuilderError> {
        self.add_timelock_output(
            protocol,
            from,
            value,
            internal_key,
            expired_script,
            renew_script,
            with_key_path,
            prevouts,
        )?;
        let output_index = (protocol.transaction_by_name(from)?.output.len() - 1) as u32;

        // This input consumes the renew_script output, no need to use the expired_blocks
        self.add_timelock_input(protocol, to, output_index, 0, sighash_type)?;
        let input_index = (protocol.transaction_by_name(to)?.input.len() - 1) as u32;

        protocol.connect("timelock", from, output_index, to, input_index)?;
        Ok(self)

        // TODO use expired_blocks to create a transaction that consumes the expired_script
    }

    pub fn add_external_connection(
        &self,
        protocol: &mut Protocol,
        txid: Txid,
        output_index: u32,
        output_type: OutputType,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&Self, ProtocolBuilderError> {
        protocol.add_external_connection(txid, output_index, output_type, to, sighash_type)?;
        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_linked_message_connection(
        &self,
        protocol: &mut Protocol,
        from: &str,
        to: &str,
        protocol_value: u64,
        protocol_scripts: &[ProtocolScript],
        timelock_value: u64,
        timelock_expired: &ProtocolScript,
        timelock_renew: &ProtocolScript,
        speedup_value: u64,
        speedup_key: &PublicKey,
        internal_key: &PublicKey,
        with_key_path: bool,
        prevouts: Vec<TxOut>,
        sighash_type: &SighashType,
    ) -> Result<&Self, ProtocolBuilderError> {
        self.add_taproot_script_spend_connection(
            protocol,
            "linked_messages",
            from,
            protocol_value,
            internal_key,
            protocol_scripts,
            with_key_path,
            prevouts.clone(),
            to,
            sighash_type,
        )?;
        self.add_timelock_connection(
            protocol,
            from,
            timelock_value,
            internal_key,
            timelock_expired,
            timelock_renew,
            with_key_path,
            prevouts,
            to,
            0,
            sighash_type,
        )?;
        self.add_speedup_output(protocol, from, speedup_value, speedup_key)?;

        Ok(self)
    }

    /// Creates a connection between two transactions for a given number of rounds creating the intermediate transactions to complete the DAG.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_taproot_script_spend_rounds(
        &self,
        protocol: &mut Protocol,
        connection_name: &str,
        rounds: u32,
        from: &str,
        to: &str,
        value: u64,
        internal_key: &PublicKey,
        leaves_from: &[ProtocolScript],
        leaves_to: &[ProtocolScript],
        with_key_path: bool,
        sighash_type: &SighashType,
    ) -> Result<(String, String), ProtocolBuilderError> {
        check_zero_rounds(rounds)?;
        // To create the names for the intermediate transactions in the rounds. We will use the following format: {name}_{round}.
        let mut from_round;
        let mut to_round;

        // In each round we will connect the from transaction to the to transaction and then the to transaction to the from transaction.
        // we need to do this because the transactions are connected in a DAG.
        for round in 0..rounds - 1 {
            // Create the new names for the intermediate transactions in the direct connection (from -> to).
            from_round = format!("{0}_{1}", from, round);
            to_round = format!("{0}_{1}", to, round);

            // Connection between the from and to transactions using the leaves_from.
            let output_type = OutputType::tr_script(
                value,
                internal_key,
                leaves_from,
                with_key_path,
                vec![],
            )?;
            protocol.add_connection(
                connection_name,
                &from_round,
                &to_round,
                output_type,
                sighash_type,
            )?;

            // Create the new names for the intermediate transactions in the reverse connection (to -> from).
            from_round = format!("{0}_{1}", from, round + 1);
            to_round = format!("{0}_{1}", to, round);

            // Reverse connection between the to and from transactions using the leaves_to.
            let output_type = OutputType::tr_script(
                value,
                internal_key,
                leaves_to,
                with_key_path,
                vec![],
            )?;
            protocol.add_connection(
                connection_name,
                &to_round,
                &from_round,
                output_type,
                sighash_type,
            )?;
        }

        // We don't need the last reverse connection, thus why we perform the last direct connection outside the loop.
        // Create the new names for the last direct connection (from -> to).
        from_round = format!("{0}_{1}", from, rounds - 1);
        to_round = format!("{0}_{1}", to, rounds - 1);

        // Last direct connection using leaves_from.
        let output_type = OutputType::tr_script(
            value,
            internal_key,
            leaves_from,
            with_key_path,
            vec![],
        )?;
        protocol.add_connection(
            connection_name,
            &from_round,
            &to_round,
            output_type,
            sighash_type,
        )?;

        Ok((format!("{0}_{1}", from, 0), to_round))
    }
}

fn push_input(transaction: &mut Transaction, utxo: &Utxo) {
    transaction.input.push(TxIn {
        previous_output: OutPoint {
            txid: utxo.txid,
            vout: utxo.vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });
}

fn push_output(
    transaction: &mut Transaction,
    amount: u64,
    address: Address,
    fees: u64,
) -> Result<(), ProtocolBuilderError> {
    let amount = Amount::from_sat(amount);
    let fees = Amount::from_sat(fees);
    let amount_to_send =
        amount
            .checked_sub(fees)
            .ok_or(ProtocolBuilderError::InsufficientFunds(
                amount.to_sat(),
                fees.to_sat(),
            ))?;
    let txout = TxOut {
        value: amount_to_send,
        script_pubkey: address.script_pubkey(),
    };
    transaction.output.push(txout);
    Ok(())
}

fn push_witness<K: KeyStore>(
    transaction: &mut Transaction,
    utxo: Utxo,
    input_index: usize,
    key_manager: &KeyManager<K>,
    sighasher: &mut SighashCache<Transaction>,
) -> Result<(), ProtocolBuilderError> {
    let value = Amount::from_sat(utxo.amount);
    let witness_public_key_hash = utxo.pub_key.wpubkey_hash().expect("key is compressed");
    let script_pubkey = ScriptBuf::new_p2wpkh(&witness_public_key_hash);
    let input_hash = Message::from(sighasher.p2wpkh_signature_hash(
        input_index,
        &script_pubkey,
        value,
        EcdsaSighashType::All,
    )?);
    let input_signature = bitcoin::ecdsa::Signature {
        signature: key_manager.sign_ecdsa_message(&input_hash, &utxo.pub_key)?,
        sighash_type: EcdsaSighashType::All,
    };
    let witness = Witness::p2wpkh(&input_signature, &utxo.pub_key.inner);

    transaction.input[input_index].witness = witness;
    Ok(())
}
