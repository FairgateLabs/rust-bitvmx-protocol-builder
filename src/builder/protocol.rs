use bitcoin::{
    locktime,
    secp256k1::{self, Message},
    taproot::LeafVersion,
    transaction, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, Txid, Witness,
    XOnlyPublicKey,
};
use key_manager::key_manager::KeyManager;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, rc::Rc, vec};
use storage_backend::storage::{KeyValueStore, Storage};

use crate::{
    errors::ProtocolBuilderError,
    graph::graph::TransactionGraph,
    scripts::ProtocolScript,
    types::{
        connection::{ConnectionType, InputSpec, OutputSpec},
        input::{InputArgs, InputSignatures, InputType, SighashType, Signature, SpendMode},
        output::OutputType,
    },
    unspendable::unspendable_key,
};

use super::check_params::{check_empty_connection_name, check_empty_transaction_name};

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
        Ok(storage.get(&name)?)
    }

    pub fn save(&self, storage: Rc<Storage>) -> Result<(), ProtocolBuilderError> {
        storage.set(&self.name, &self, None)?;
        Ok(())
    }

    pub fn add_transaction(
        &mut self,
        transaction_name: &str,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.get_or_create_transaction(transaction_name, false)?;
        Ok(self)
    }

    pub fn add_external_transaction(
        &mut self,
        transaction_name: &str,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.get_or_create_transaction(transaction_name, true)?;
        Ok(self)
    }

    pub fn add_unkwnoun_outputs(
        &mut self,
        transaction_name: &str,
        count: u32,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        for _ in 0..count {
            self.add_transaction_output(
                transaction_name,
                &OutputType::ExternalUnknown {
                    script_pubkey: ScriptBuf::default(),
                },
            )?;
        }
        Ok(self)
    }

    pub fn add_transaction_input(
        &mut self,
        previous_txid: Txid,
        previous_output: usize,
        transaction_name: &str,
        sequence: Sequence,
        spend_mode: &SpendMode,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        check_empty_transaction_name(transaction_name)?;

        let mut transaction = self.get_or_create_transaction(transaction_name, false)?;

        transaction.input.push(transaction::TxIn {
            previous_output: OutPoint {
                txid: previous_txid,
                vout: previous_output as u32,
            },
            script_sig: ScriptBuf::default(),
            sequence,
            witness: Witness::default(),
        });

        self.graph.add_transaction_input(
            transaction_name,
            transaction,
            spend_mode,
            sighash_type,
        )?;

        Ok(self)
    }

    pub fn add_transaction_output(
        &mut self,
        transaction_name: &str,
        output_type: &OutputType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        check_empty_transaction_name(transaction_name)?;

        let mut transaction = self.get_or_create_transaction(transaction_name, false)?;

        transaction.output.push(transaction::TxOut {
            value: output_type.get_value(),
            script_pubkey: output_type.get_script_pubkey().clone(),
        });

        self.graph
            .add_transaction_output(transaction_name, transaction, output_type.clone())?;

        Ok(self)
    }

    pub fn get_output_count(&self, transaction_name: &str) -> Result<u32, ProtocolBuilderError> {
        let transaction = self.transaction_by_name(transaction_name)?;
        Ok(transaction.output.len() as u32)
    }

    pub fn add_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        output: OutputSpec,
        to: &str,
        input: InputSpec,
        timelock: Option<u16>,
        txid: Option<Txid>,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        let connection_type = match txid {
            Some(txid) => ConnectionType::external(txid, from, output, to, input, timelock),
            None => ConnectionType::internal(from, output, to, input, timelock),
        };

        self.add_connection_aux(connection_name, connection_type)
    }

    fn add_connection_aux(
        &mut self,
        connection_name: &str,
        connection_type: ConnectionType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        check_empty_connection_name(connection_name)?;
        check_empty_transaction_name(connection_type.from())?;
        check_empty_transaction_name(connection_type.to())?;

        let from_tx = self.get_or_create_transaction(
            connection_type.from(),
            connection_type.external_connection(),
        )?;

        let to_tx = self.get_or_create_transaction(connection_type.to(), false)?;

        let output_index = match connection_type.output() {
            OutputSpec::Index(index) => {
                // Check if the specified output index exists in the transaction
                if *index >= from_tx.output.len() {
                    return Err(ProtocolBuilderError::MissingOutput(
                        connection_type.from().to_string(),
                        *index,
                    ));
                }

                *index
            }
            OutputSpec::Auto(output_type) => {
                // Automatically add the output to the transaction
                self.add_transaction_output(connection_type.from(), output_type)?;
                self.transaction_by_name(connection_type.from())?
                    .output
                    .len()
                    - 1
            }
            OutputSpec::Last => {
                // Automatically point to the last output of the transaction
                let len = self
                    .transaction_by_name(connection_type.from())?
                    .output
                    .len();
                if len == 0 {
                    return Err(ProtocolBuilderError::MissingOutput(
                        connection_type.from().to_string(),
                        0,
                    ));
                }
                len - 1
            }
        };

        let input_index = match connection_type.input() {
            InputSpec::Index(index) => {
                // Check if the specified input index exists in the transaction
                if *index >= to_tx.input.len() {
                    return Err(ProtocolBuilderError::MissingInput(
                        connection_type.to().to_string(),
                        *index,
                    ));
                }
                *index
            }
            InputSpec::Auto(sighash_type, spend_mode) => {
                // Automatically add the input to the "to" transaction
                self.add_transaction_input(
                    connection_type.txid(),
                    output_index,
                    connection_type.to(),
                    connection_type.sequence(),
                    spend_mode,
                    sighash_type,
                )?;
                self.transaction_by_name(connection_type.to())?.input.len() - 1
            }
        };

        self.graph.connect(
            connection_name,
            connection_type.from(),
            output_index,
            connection_type.to(),
            input_index,
        )?;

        Ok(self)
    }

    pub fn build(
        &mut self,
        key_manager: &Rc<KeyManager>,
        id: &str,
    ) -> Result<Self, ProtocolBuilderError> {
        self.update_transaction_ids()?;
        self.compute_sighashes(key_manager, id)?;
        Ok(self.clone())
    }

    pub fn sign(
        &mut self,
        key_manager: &Rc<KeyManager>,
        id: &str,
    ) -> Result<Self, ProtocolBuilderError> {
        self.compute_signatures(key_manager, id)?;
        Ok(self.clone())
    }

    // To be used only when we don't need musig2
    pub fn build_and_sign(
        &mut self,
        key_manager: &Rc<KeyManager>,
        id: &str,
    ) -> Result<Self, ProtocolBuilderError> {
        self.update_transaction_ids()?;
        self.compute_sighashes(key_manager, id)?;
        self.compute_signatures(key_manager, id)?;
        Ok(self.clone())
    }

    pub fn sign_input(
        &mut self,
        transaction_name: &str,
        input_index: usize,
        leaf: Option<usize>,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<(), ProtocolBuilderError> {
        let input = &self.graph.get_inputs(transaction_name)?[input_index];
        let output_type = input.output_type().unwrap();

        let (signature, signature_index) = match input.sighash_type() {
            SighashType::Taproot(tap_sighash_type) => {
                let leaves = match output_type {
                    OutputType::Taproot { leaves, .. } => leaves,
                    _ => return Err(ProtocolBuilderError::InvalidOutputTypeForSighashType),
                };

                let (leaf, leaf_index) =
                    match leaf {
                        Some(leaf_index) => (
                            leaves.get(leaf_index).ok_or(
                                ProtocolBuilderError::MissingTaprootLeaf(leaf_index, input_index),
                            )?,
                            leaf_index,
                        ),
                        None => {
                            return Err(ProtocolBuilderError::InvalidLeaf(input_index));
                        }
                    };

                (
                    output_type.taproot_script_only_signature(
                        transaction_name,
                        input_index,
                        &input.hashed_messages(),
                        tap_sighash_type,
                        leaf,
                        leaf_index,
                        key_manager,
                        id,
                    )?,
                    leaf_index,
                )
            }

            SighashType::Ecdsa(ecdsa_sighash_type) => match output_type {
                OutputType::SegwitPublicKey { public_key, .. } => (
                    output_type.ecdsa_key_signature(
                        &input.hashed_messages(),
                        ecdsa_sighash_type,
                        key_manager,
                        public_key,
                    )?[0]
                        .clone(),
                    0,
                ),
                OutputType::SegwitScript { script, .. } => (
                    output_type.ecdsa_script_signature(
                        &input.hashed_messages(),
                        ecdsa_sighash_type,
                        key_manager,
                        script,
                    )?[0]
                        .clone(),
                    0,
                ),
                _ => return Err(ProtocolBuilderError::InvalidOutputTypeForSighashType),
            },
        };

        self.graph.update_input_signature(
            transaction_name,
            input_index as u32,
            signature,
            signature_index,
        )?;

        Ok(())
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
        args: &[InputArgs],
    ) -> Result<Transaction, ProtocolBuilderError> {
        let mut transaction = self
            .graph
            .get_transaction_by_name(transaction_name)?
            .clone();

        for (input_index, input) in self.graph.get_inputs(transaction_name)?.iter().enumerate() {
            let witness = self.get_witness_for_input(input_index, input, &args[input_index])?;
            transaction.input[input_index].witness = witness;
        }

        Ok(transaction)
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

    pub fn inputs(&self, transaction_name: &str) -> Result<Vec<InputType>, ProtocolBuilderError> {
        Ok(self.graph.get_inputs(transaction_name)?)
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

    pub fn transaction_by_name(
        &self,
        transaction_name: &str,
    ) -> Result<&Transaction, ProtocolBuilderError> {
        Ok(self.graph.get_transaction_by_name(transaction_name)?)
    }

    pub fn transaction_by_id(&self, txid: &Txid) -> Result<&Transaction, ProtocolBuilderError> {
        Ok(self.graph.get_transaction_by_id(txid)?)
    }

    pub fn transaction_name_by_id(&self, txid: Txid) -> Result<&String, ProtocolBuilderError> {
        Ok(self.graph.get_transaction_name_by_id(txid)?)
    }

    pub fn transaction_without_witness(
        &self,
        transaction_name: &str,
    ) -> Result<Transaction, ProtocolBuilderError> {
        let transaction = self.transaction_by_name(transaction_name)?.clone();
        Ok(transaction)
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
            .get_ecdsa_signature(transaction_name, input_index)?;
        Ok(input_signature)
    }

    pub fn input_taproot_script_spend_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
        leaf_index: usize,
    ) -> Result<Option<bitcoin::taproot::Signature>, ProtocolBuilderError> {
        let input_signature =
            self.graph
                .get_taproot_script_signature(transaction_name, input_index, leaf_index)?;
        Ok(input_signature)
    }

    pub fn input_taproot_key_spend_signature(
        &self,
        transaction_name: &str,
        input_index: usize,
    ) -> Result<Option<bitcoin::taproot::Signature>, ProtocolBuilderError> {
        let input_signature = self
            .graph
            .get_taproot_key_signature(transaction_name, input_index)?;
        Ok(input_signature)
    }

    pub fn get_script_from_output(
        &self,
        transaction_name: &str,
        output_index: u32,
    ) -> Result<(&OutputType, &Vec<ProtocolScript>), ProtocolBuilderError> {
        if let Some(output_type) = self
            .graph
            .get_output(transaction_name, output_index as usize)?
        {
            match output_type {
                OutputType::Taproot { leaves, .. } => return Ok((output_type, &leaves)),
                _ => {}
            }
        }
        return Err(ProtocolBuilderError::CannotGetScriptForOutputType(
            transaction_name.to_string(),
            output_index,
            0,
            "Output not found".to_string(),
        ));
    }

    pub fn get_script_to_spend(
        &self,
        transaction_name: &str,
        input_index: u32,
        script_index: u32,
    ) -> Result<ProtocolScript, ProtocolBuilderError> {
        let input = self
            .graph
            .get_input(transaction_name, input_index as usize)?;

        let script = match input.output_type()? {
            OutputType::Taproot { leaves, .. } => leaves[script_index as usize].clone(),
            // TODO complete this for all other output types and remove the "Unknown output type".to_string() value in the error
            OutputType::SegwitScript { script, .. } => script.clone(),
            _ => {
                return Err(ProtocolBuilderError::CannotGetScriptForOutputType(
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

    pub(crate) fn transaction_template() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,            // Post BIP-68.
            lock_time: locktime::absolute::LockTime::ZERO, // Ignore the locktime.
            input: vec![],
            output: vec![],
        }
    }

    fn get_or_create_transaction(
        &mut self,
        transaction_name: &str,
        external: bool,
    ) -> Result<Transaction, ProtocolBuilderError> {
        check_empty_transaction_name(transaction_name)?;

        if !self.graph.contains_transaction(transaction_name) {
            let transaction = Protocol::transaction_template();
            self.graph
                .add_transaction(transaction_name, transaction, external)?;
        };

        Ok(self
            .graph
            .get_transaction_by_name(transaction_name)
            .unwrap()
            .clone())
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
            let transaction = self.transaction_by_name(&from)?;
            let txid = transaction.compute_txid();

            for (to, input_index) in self.get_dependencies(&from)? {
                let mut dependency = self.transaction_by_name(&to)?.clone();
                dependency.input[input_index as usize].previous_output.txid = txid;

                self.graph.update_transaction(&to, dependency)?;
            }
        }

        Ok(())
    }

    fn compute_sighashes(
        &mut self,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<(), ProtocolBuilderError> {
        let (transactions, transaction_names) = self.graph.sorted_transactions()?;
        for (transaction, transaction_name) in transactions.iter().zip(transaction_names.iter()) {
            for (input_index, input) in self.graph.get_inputs(transaction_name)?.iter().enumerate()
            {
                let output_type = input.output_type().unwrap();

                let hashed_messages = match input.sighash_type() {
                    SighashType::Taproot(tap_sighash_type) => {
                        //let prevouts = if output_type.has_prevouts() {
                        //    output_type.get_prevouts()
                        //} else {
                        let prevouts = self.graph.get_prevouts(transaction_name)?;
                        //};

                        output_type.compute_taproot_sighash(
                            transaction,
                            transaction_name,
                            input_index,
                            &prevouts,
                            input.spend_mode(),
                            tap_sighash_type,
                            key_manager,
                            id,
                        )?
                    }
                    SighashType::Ecdsa(ecdsa_sighash_type) => output_type.compute_ecdsa_sighash(
                        transaction,
                        transaction_name,
                        input_index,
                        input.spend_mode(),
                        ecdsa_sighash_type,
                    )?,
                };

                self.graph.update_hashed_messages(
                    transaction_name,
                    input_index as u32,
                    hashed_messages,
                )?;
            }
        }

        Ok(())
    }

    fn compute_signatures(
        &mut self,
        key_manager: &KeyManager,
        id: &str,
    ) -> Result<(), ProtocolBuilderError> {
        let (transactions, transaction_names) = self.graph.sorted_transactions()?;
        for (_, transaction_name) in transactions.iter().zip(transaction_names.iter()) {
            for (input_index, input) in self.graph.get_inputs(transaction_name)?.iter().enumerate()
            {
                let output_type = input.output_type().unwrap();

                let signatures = match input.sighash_type() {
                    SighashType::Taproot(tap_sighash_type) => output_type
                        .compute_taproot_signature(
                            transaction_name,
                            input_index,
                            &input.hashed_messages(),
                            input.spend_mode(),
                            tap_sighash_type,
                            key_manager,
                            id,
                        )?,
                    SighashType::Ecdsa(ecdsa_sighash_type) => output_type.compute_ecdsa_signature(
                        transaction_name,
                        input_index,
                        &input.hashed_messages(),
                        input.spend_mode(),
                        ecdsa_sighash_type,
                        key_manager,
                    )?,
                };

                self.graph.update_input_signatures(
                    transaction_name,
                    input_index as u32,
                    signatures,
                )?;
            }
        }

        Ok(())
    }

    fn get_witness_for_input(
        &self,
        input_index: usize,
        input: &InputType,
        args: &InputArgs,
    ) -> Result<Witness, ProtocolBuilderError> {
        let witness = match input.sighash_type() {
            SighashType::Taproot(..) => match input.output_type()? {
                OutputType::Taproot { .. } => match args {
                    InputArgs::TaprootScript { leaf, .. } => {
                        self.taproot_script_witness(input_index, *leaf, input, args)?
                    }
                    InputArgs::TaprootKey { .. } => self.taproot_key_witness(args)?,
                    _ => {
                        return Err(ProtocolBuilderError::InvalidInputArgsType(
                            "TaprootScript or TaprootKey".to_string(),
                            "Segwit".to_string(),
                        ))
                    }
                },
                _ => return Err(ProtocolBuilderError::InvalidOutputTypeForSighashType),
            },
            SighashType::Ecdsa(..) => match input.output_type()? {
                OutputType::SegwitPublicKey { public_key, .. } => {
                    self.segwit_key_witness(public_key, args)?
                }
                OutputType::SegwitScript { ref script, .. } => {
                    self.segwit_script_witness(script, args)?
                }
                OutputType::SegwitUnspendable { .. } => {
                    // Create an empty witness for unspendable outputs
                    Witness::new()
                }
                _ => return Err(ProtocolBuilderError::InvalidOutputTypeForSighashType),
            },
        };

        Ok(witness)
    }

    pub fn create_unspendable_key() -> Result<XOnlyPublicKey, ProtocolBuilderError> {
        let mut rng = secp256k1::rand::thread_rng();
        let key = XOnlyPublicKey::from(unspendable_key(&mut rng)?);
        Ok(key)
    }

    pub fn get_hashed_message(
        &mut self,
        transaction_name: &str,
        input_index: u32,
        message_index: u32,
    ) -> Result<Option<Message>, ProtocolBuilderError> {
        Ok(self
            .graph
            .get_hashed_message(transaction_name, input_index, message_index)?)
    }

    fn taproot_key_witness(&self, args: &InputArgs) -> Result<Witness, ProtocolBuilderError> {
        let mut witness = Witness::default();
        for value in args.iter() {
            witness.push(value.clone());
        }

        Ok(witness)
    }

    fn taproot_script_witness(
        &self,
        input_index: usize,
        leaf: usize,
        input: &InputType,
        args: &InputArgs,
    ) -> Result<Witness, ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();
        let spend_info = &input.output_type()?.get_taproot_spend_info()?.unwrap();

        let leaf = match input.output_type()? {
            OutputType::Taproot { leaves, .. } => {
                if leaf >= leaves.len() {
                    return Err(ProtocolBuilderError::InvalidLeaf(input_index));
                }
                leaves[leaf].get_script().clone()
            }
            _ => return Err(ProtocolBuilderError::InvalidOutputTypeForSighashType),
        };

        let control_block = match spend_info.control_block(&(leaf.clone(), LeafVersion::TapScript))
        {
            Some(cb) => cb,
            None => return Err(ProtocolBuilderError::InvalidLeaf(input_index)),
        };

        if !control_block.verify_taproot_commitment(
            &secp,
            spend_info.output_key().to_inner(),
            &leaf,
        ) {
            return Err(ProtocolBuilderError::InvalidLeaf(input_index));
        }

        let mut witness = Witness::default();

        for value in args.iter() {
            witness.push(value.clone());
        }

        witness.push(leaf.to_bytes());
        witness.push(control_block.serialize());

        Ok(witness)
    }

    fn segwit_key_witness(
        &self,
        public_key: &PublicKey,
        args: &InputArgs,
    ) -> Result<Witness, ProtocolBuilderError> {
        let mut witness = Witness::default();
        for value in args.iter() {
            witness.push(value.clone());
        }

        witness.push(public_key.to_bytes());
        Ok(witness)
    }

    fn segwit_script_witness(
        &self,
        script: &ProtocolScript,
        args: &InputArgs,
    ) -> Result<Witness, ProtocolBuilderError> {
        let mut witness = Witness::default();
        for value in args.iter() {
            witness.push(value.clone());
        }

        witness.push(script.get_script().to_bytes());
        Ok(witness)
    }
}
