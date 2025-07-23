use std::rc::Rc;

use bitcoin::{
    hashes::Hash, secp256k1::Message, sighash::SighashCache, Address, Amount, EcdsaSighashType,
    OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_scriptexec::scriptint_vec;
use key_manager::key_manager::KeyManager;
use tracing::debug;

use crate::{
    errors::ProtocolBuilderError,
    graph::graph::GraphOptions,
    scripts::{self, ProtocolScript},
    types::{
        connection::{InputSpec, OutputSpec},
        input::{SighashType, SpendMode},
        output::{OutputType, SpeedupData},
        InputArgs, Utxo,
    },
};

use super::{check_params::check_zero_rounds, Protocol};

pub struct ProtocolBuilder {}

impl ProtocolBuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn add_taproot_output(
        &self,
        protocol: &mut Protocol,
        transaction_name: &str,
        value: u64,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
    ) -> Result<&Self, ProtocolBuilderError> {
        let output_type = OutputType::taproot(value, internal_key, leaves)?;
        protocol.add_transaction_output(transaction_name, &output_type)?;
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
        protocol.add_transaction_output(transaction_name, &output_type)?;
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
        protocol.add_transaction_output(transaction_name, &output_type)?;
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
        protocol.add_transaction_output(transaction_name, &output_type)?;
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
    ) -> Result<&Self, ProtocolBuilderError> {
        self.add_taproot_output(
            protocol,
            transaction_name,
            value,
            internal_key,
            &[expired_script.clone(), renew_script.clone()],
        )
    }

    pub fn add_timelock_input(
        &self,
        protocol: &mut Protocol,
        transaction_name: &str,
        previous_output: usize,
        blocks: u16,
        spend_mode: &SpendMode,
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
            spend_mode,
            sighash_type,
        )?;
        Ok(self)
    }

    pub fn speedup_transactions(
        &self,
        speedups_data: &[SpeedupData],
        funding_transaction_utxo: Utxo,
        change_address: &PublicKey,
        speedup_fee: u64,
        key_manager: &Rc<KeyManager>,
    ) -> Result<Transaction, ProtocolBuilderError> {
        let mut protocol = Protocol::new("speedup_tx");
        debug!(
            "Building speedup transaction with {:?} speedups and funding UTXO: {:?}, {}",
            speedups_data, funding_transaction_utxo, speedup_fee
        );

        for (idx, speedup_data) in speedups_data.iter().enumerate() {
            let tx_name = &format!("tx_to_speedup_{idx}");
            protocol.add_external_transaction(&tx_name)?;

            if let Some(utxo) = &speedup_data.utxo {
                protocol.add_unknown_outputs(&tx_name, utxo.vout)?;
                let external_output = OutputType::segwit_key(utxo.amount, &utxo.pub_key)?;
                protocol.add_connection(
                    &format!("speedup_{idx}"),
                    &tx_name,
                    external_output.into(),
                    "cpfp",
                    InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
                    None,
                    Some(utxo.txid),
                )?;
            } else {
                let partial_utxo = speedup_data.partial_utxo.as_ref().unwrap();
                protocol.add_unknown_outputs(&tx_name, partial_utxo.1)?;
                protocol.add_connection(
                    &format!("speedup_{idx}"),
                    &tx_name,
                    speedup_data.output_type.as_ref().unwrap().clone().into(),
                    "cpfp",
                    InputSpec::Auto(
                        SighashType::taproot_all(),
                        SpendMode::Script {
                            leaf: speedup_data.leaf_index.unwrap(),
                        },
                    ),
                    None,
                    Some(partial_utxo.0),
                )?;
            }
        }

        protocol.add_external_transaction("funding")?;
        protocol.add_unknown_outputs("funding", funding_transaction_utxo.vout)?;
        let external_output = OutputType::segwit_key(
            funding_transaction_utxo.amount,
            &funding_transaction_utxo.pub_key,
        )?;
        protocol.add_connection(
            "speedup_funding",
            "funding",
            external_output.into(),
            "cpfp",
            InputSpec::Auto(SighashType::ecdsa_all(), SpendMode::Segwit),
            None,
            Some(funding_transaction_utxo.txid),
        )?;

        protocol.add_transaction_output(
            "cpfp",
            &OutputType::segwit_key(
                funding_transaction_utxo.amount - speedup_fee,
                change_address,
            )?,
        )?;

        protocol.build_and_sign(key_manager, "id")?;

        let mut args_for_all_inputs = vec![];

        let total = speedups_data.len() + 1; // +1 for the funding input

        for idx in 0..total {
            if idx < speedups_data.len() {
                let speedup_data = &speedups_data[idx];
                if speedup_data.utxo.is_none() {
                    let leaf_index = speedup_data.leaf_index.unwrap();
                    let signature = protocol
                        .input_taproot_script_spend_signature("cpfp", idx, leaf_index)?
                        .unwrap();
                    let mut spending_args = InputArgs::new_taproot_script_args(leaf_index);
                    for wots in speedup_data.wots_sigs.as_ref().unwrap().iter() {
                        spending_args.push_winternitz_signature(wots.clone());
                    }
                    spending_args.push_taproot_signature(signature)?;
                    if speedup_data.leaf_identification {
                        spending_args.push_slice(scriptint_vec(leaf_index as i64).as_slice());
                    }
                    args_for_all_inputs.push(spending_args);

                    continue;
                }
            }
            let signature = protocol.input_ecdsa_signature("cpfp", idx)?.unwrap();
            let mut spending_args = InputArgs::new_segwit_args();
            spending_args.push_ecdsa_signature(signature)?;
            args_for_all_inputs.push(spending_args);
        }
        debug!("{}", protocol.visualize(GraphOptions::Default)?);

        let result = protocol.transaction_to_send("cpfp", &args_for_all_inputs)?;
        Ok(result)
    }

    pub fn speedup_transactions_old(
        &self,
        speedups_data: &[SpeedupData],
        funding_transaction_utxo: Utxo,
        change_address: Address,
        speedup_fee: u64,
        key_manager: &KeyManager,
    ) -> Result<Transaction, ProtocolBuilderError> {
        //let transaction_to_speedup = protocol.transaction_by_id(&transaction_to_speedup_utxo.txid)?;
        let mut speedup_transaction = Protocol::transaction_template();

        // The speedup input to consume the speedup output of the transaction to speedup
        for speedup_data in speedups_data {
            push_input(
                &mut speedup_transaction,
                speedup_data.utxo.as_ref().unwrap(),
            );
        }

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

        // Witness for all inputs
        for (index, speedup_data) in speedups_data.iter().enumerate() {
            push_witness(
                &mut speedup_transaction,
                speedup_data.utxo.as_ref().unwrap().clone(),
                index,
                key_manager,
                &mut sighasher,
            )?;
        }

        // Witness for the funding input (last)
        push_witness(
            &mut speedup_transaction,
            funding_transaction_utxo,
            speedups_data.len(),
            key_manager,
            &mut sighasher,
        )?;

        Ok(speedup_transaction)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_taproot_connection(
        &self,
        protocol: &mut Protocol,
        connection_name: &str,
        from: &str,
        value: u64,
        internal_key: &PublicKey,
        leaves: &[ProtocolScript],
        spend_mode: &SpendMode,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&Self, ProtocolBuilderError> {
        protocol.add_connection(
            connection_name,
            from,
            OutputSpec::Auto(OutputType::taproot(value, internal_key, leaves)?),
            to,
            InputSpec::Auto(sighash_type.clone(), spend_mode.clone()),
            None,
            None,
        )?;

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
        protocol.add_connection(
            connection_name,
            from,
            OutputSpec::Auto(OutputType::segwit_key(value, public_key)?),
            to,
            InputSpec::Auto(sighash_type.clone(), SpendMode::Segwit),
            None,
            None,
        )?;

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
        protocol.add_connection(
            connection_name,
            from,
            OutputSpec::Auto(OutputType::segwit_script(value, script)?),
            to,
            InputSpec::Auto(sighash_type.clone(), SpendMode::Segwit),
            None,
            None,
        )?;
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
        spend_mode: &SpendMode,
        to: &str,
        _expired_blocks: u16,
        sighash_type: &SighashType,
    ) -> Result<&Self, ProtocolBuilderError> {
        protocol.add_connection(
            "timelock",
            from,
            OutputSpec::Auto(OutputType::taproot(
                value,
                internal_key,
                &[expired_script.clone(), renew_script.clone()],
            )?),
            to,
            InputSpec::Auto(sighash_type.clone(), spend_mode.clone()),
            Some(0), // This is not used in the current implementation
            None,
        )?;
        Ok(self)

        // TODO use expired_blocks to create a transaction that consumes the expired_script
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_external_connection(
        &self,
        protocol: &mut Protocol,
        from: &str,
        txid: Txid,
        output: OutputSpec,
        to: &str,
        input: InputSpec,
    ) -> Result<&Self, ProtocolBuilderError> {
        protocol.add_connection("external", from, output, to, input, None, Some(txid))?;

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
        spend_mode: &SpendMode,
        sighash_type: &SighashType,
    ) -> Result<&Self, ProtocolBuilderError> {
        self.add_taproot_connection(
            protocol,
            "linked_messages",
            from,
            protocol_value,
            internal_key,
            protocol_scripts,
            spend_mode,
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
            spend_mode,
            to,
            0,
            sighash_type,
        )?;
        self.add_speedup_output(protocol, from, speedup_value, speedup_key)?;

        Ok(self)
    }

    /// Creates a connection between two transactions for a given number of rounds creating the intermediate transactions to complete the DAG.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_taproot_rounds(
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
        spend_mode: &SpendMode,
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
            protocol.add_connection(
                connection_name,
                &from_round,
                OutputSpec::Auto(OutputType::taproot(value, internal_key, leaves_from)?),
                &to_round,
                InputSpec::Auto(sighash_type.clone(), spend_mode.clone()),
                None,
                None,
            )?;

            // Create the new names for the intermediate transactions in the reverse connection (to -> from).
            from_round = format!("{0}_{1}", from, round + 1);
            to_round = format!("{0}_{1}", to, round);

            // Reverse connection between the to and from transactions using the leaves_to.
            protocol.add_connection(
                connection_name,
                &to_round,
                OutputSpec::Auto(OutputType::taproot(value, internal_key, leaves_to)?),
                &from_round,
                InputSpec::Auto(sighash_type.clone(), spend_mode.clone()),
                None,
                None,
            )?;
        }

        // We don't need the last reverse connection, thus why we perform the last direct connection outside the loop.
        // Create the new names for the last direct connection (from -> to).
        from_round = format!("{0}_{1}", from, rounds - 1);
        to_round = format!("{0}_{1}", to, rounds - 1);

        // Last direct connection using leaves_from.
        protocol.add_connection(
            connection_name,
            &from_round,
            OutputSpec::Auto(OutputType::taproot(value, internal_key, leaves_from)?),
            &to_round,
            InputSpec::Auto(sighash_type.clone(), spend_mode.clone()),
            None,
            None,
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

fn push_witness(
    transaction: &mut Transaction,
    utxo: Utxo,
    input_index: usize,
    key_manager: &KeyManager,
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
