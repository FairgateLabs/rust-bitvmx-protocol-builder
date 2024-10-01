use std::cmp;

use bitcoin::{hashes::Hash, key::TweakedPublicKey, locktime, secp256k1, taproot::{TaprootBuilder, TaprootSpendInfo}, transaction, Amount, EcdsaSighashType, OutPoint, PublicKey, ScriptBuf, Sequence, TapSighashType, Transaction, Witness};

use crate::errors::ProtocolBuilderError;

pub struct Output {
    index: usize, 
    output_type: OutputType,
}

impl Output {
    fn new_taproot_key_spend(index: usize, value: u64, output_key: TweakedPublicKey) -> Self {
        Output {
            index,
            output_type: OutputType::TaprootKeySpend { value, output_key },
        }
    }

    fn new_taproot_script_spend(index: usize, value: u64, internal_key: PublicKey, spending_scripts: Vec<ScriptBuf>) -> Self {
        Output {
            index,
            output_type: OutputType::TaprootScriptSpend { value, internal_key, spending_scripts },
        }
    }

    fn new_p2wpkh(index: usize, value: u64, script_pubkey: ScriptBuf) -> Self {
        Output {
            index,
            output_type: OutputType::P2WPKH { value, script_pubkey },
        }
    }

    fn new_p2wsh(index: usize, value: u64, script_pubkey: ScriptBuf) -> Self {
        Output {
            index,
            output_type: OutputType::P2WSH { value, script_pubkey },
        }
    }

    fn new_timelock(index: usize, value: u64, internal_key: PublicKey, expired_script: ScriptBuf, renew_script: ScriptBuf) -> Self {
        Output {
            index,
            output_type: OutputType::Timelock { value, internal_key, expired_script, renew_script },
        }
    }

    fn get_type(&self) -> &OutputType {
        &self.output_type
    }
}
pub struct Input {
    index: usize, 
    input_type: InputType,
}

impl Input {
    fn new_taproot_key_spend(index: usize, sighash_type: TapSighashType) -> Self {
        Input {
            index,
            input_type: InputType::TaprootKeySpend { sighash_type },
        }
    }

    fn new_taproot_script_spend(index: usize, sighash_type: TapSighashType) -> Self {
        Input {
            index,
            input_type: InputType::TaprootScriptSpend { sighash_type },
        }
    }

    fn new_p2wpkh(index: usize, sighash_type: EcdsaSighashType) -> Self {
        Input {
            index,
            input_type: InputType::P2WPKH { sighash_type },
        }
    }

    fn new_p2wsh(index: usize, sighash_type: EcdsaSighashType) -> Self {
        Input {
            index,
            input_type: InputType::P2WSH { sighash_type },
        }
    }

    fn new_timelock(index: usize, renew_script: ScriptBuf, blocks: u16, sighash_type: TapSighashType) -> Self {
        Input {
            index,
            input_type: InputType::Timelock { blocks, renew_script, sighash_type },
        }
    }

    fn get_type(&self) -> &InputType {
        &self.input_type
    }
}

pub struct Connection {
    output: Output,
    input: Input,
}

impl Connection {
    fn new(output: Output, input: Input) -> Self {
        Connection {
            output,
            input,
        }
    }

    pub fn new_taproot_key_spend(input_index: usize, output_index: usize, value: u64, output_key: TweakedPublicKey, sighash_type: TapSighashType) -> Self {
        Connection::new(
            Output::new_taproot_key_spend(output_index, value, output_key),
            Input::new_taproot_key_spend(input_index, sighash_type),
        )
    }

    pub fn new_taproot_script_spend(input_index: usize, output_index: usize, value: u64, internal_key: PublicKey, spending_scripts: Vec<ScriptBuf>, sighash_type: TapSighashType) -> Self {
        Connection::new(
            Output::new_taproot_script_spend(output_index, value, internal_key, spending_scripts),
            Input::new_taproot_script_spend(input_index, sighash_type),
        )
    }

    pub fn new_p2wpkh(input_index: usize, output_index: usize, value: u64, script_pubkey: ScriptBuf, sighash_type: EcdsaSighashType) -> Self {
        Connection::new(
            Output::new_p2wpkh(output_index, value, script_pubkey),
            Input::new_p2wpkh(input_index, sighash_type),
        )
    }

    pub fn new_p2wsh(input_index: usize, output_index: usize, value: u64, script_pubkey: ScriptBuf, sighash_type: EcdsaSighashType) -> Self {
        Connection::new(
            Output::new_p2wsh(output_index, value, script_pubkey),
            Input::new_p2wsh(input_index, sighash_type),
        )
    }

    pub fn new_timelock(input_index: usize, output_index: usize, value: u64, blocks: u16, internal_key: PublicKey, expired_script: ScriptBuf, renew_script: ScriptBuf, sighash_type: TapSighashType) -> Self {
        let renew_script_clone = renew_script.clone();
        Connection::new(
            Output::new_timelock(output_index, value, internal_key, expired_script, renew_script),
            Input::new_timelock(input_index, renew_script_clone, blocks, sighash_type),
        )
    }
}

#[derive(Debug)]
pub enum OutputType {
    P2WPKH {
        value: u64,
        script_pubkey: ScriptBuf,
    },
    P2WSH {
        value: u64,
        script_pubkey: ScriptBuf,
    },
    TaprootKeySpend {
        value: u64,
        output_key: TweakedPublicKey,
    },
    TaprootScriptSpend {
        value: u64,
        internal_key: PublicKey,
        spending_scripts: Vec<ScriptBuf>,
    },
    Speedup {
        value: u64,
        speedup_script: ScriptBuf,
    },
    Timelock {
        value: u64,
        internal_key: PublicKey,
        expired_script: ScriptBuf,
        renew_script: ScriptBuf,
    },
}

#[derive(Debug)]
pub enum InputType {
    P2WPKH {
        sighash_type: EcdsaSighashType,
    },
    P2WSH {
        sighash_type: EcdsaSighashType,
    },
    TaprootKeySpend {
        sighash_type: TapSighashType,
    },
    TaprootScriptSpend {
        sighash_type: TapSighashType,
    },
    Timelock {
        blocks: u16,
        renew_script: ScriptBuf,
        sighash_type: TapSighashType,
    },
}

impl std::fmt::Display for InputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct Protocol {
    transactions: Vec<Transaction>,
}

pub struct ProtocolBuilder {
}

impl ProtocolBuilder {
    pub fn new() -> Self {
        ProtocolBuilder {}
    }

    pub fn build() -> Protocol {
        let protocol = Protocol {
            transactions: vec![],
        };  

        protocol
    }

    pub fn build_transaction(&self, inputs: &[Input], outputs: &[Output]) -> Result<Transaction, ProtocolBuilderError> {
        let mut transaction = ProtocolBuilder::tx_template();
        for input in inputs.iter() {
            ProtocolBuilder::add_input(&mut transaction, input, 0, None)?;
        }

        for output in outputs.iter() {
            ProtocolBuilder::add_output(&mut transaction, output)?;
        }

        Ok(transaction)
    }

    pub fn connect_with_transaction(&self, transaction: &Transaction, to: &str, connections: &[Connection]) {
        let mut transaction = ProtocolBuilder::tx_template();

    }


    pub fn connect_transactions(&self, from: &str, to: &str, connections: &[Connection]) -> Result<(), ProtocolBuilderError> {
        let mut from_tx = ProtocolBuilder::tx_template();
        let mut to_tx = ProtocolBuilder::tx_template();

        let mut output_index = from_tx.output.len();
        let mut input_index = to_tx.input.len();

        for connection in connections.iter() {
            let spend_info = ProtocolBuilder::add_output(&mut from_tx, &connection.output)?;
            ProtocolBuilder::add_input(&mut to_tx, &connection.input, output_index, spend_info)?;

            output_index += 1;
        }

        Ok(())
    }

    fn tx_template() -> Transaction{
        Transaction {
            version: transaction::Version::TWO, // Post BIP-68.
            lock_time: locktime::absolute::LockTime::ZERO, // Ignore the locktime.
            input: vec![],
            output: vec![],
        }
    }

    fn add_output(transaction: &mut Transaction, output: &Output) -> Result<Option<TaprootSpendInfo>, ProtocolBuilderError> {
        let spend_info = match output.get_type() {
            OutputType::P2WPKH { value, script_pubkey } => {
                transaction.output.push(transaction::TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: script_pubkey.clone(),
                });

                None
            },
            OutputType::P2WSH { value, script_pubkey } => {
                transaction.output.push(transaction::TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: script_pubkey.clone(),
                });

                None
            },
            OutputType::TaprootKeySpend { value, output_key } => {
                transaction.output.push(transaction::TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: ScriptBuf::new_p2tr_tweaked(*output_key),
                });

                None
            },
            OutputType::TaprootScriptSpend { value, internal_key, spending_scripts } => {
                let (info, script) = ProtocolBuilder::taproot_spend_info(internal_key.clone(), &spending_scripts)?;

                transaction.output.push(transaction::TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: script,
                });

                Some(info)
            },
            OutputType::Speedup { value, speedup_script } => {
                transaction.output.push(transaction::TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: speedup_script.clone(),
                });

                None
            },
            OutputType::Timelock { value, internal_key, expired_script: timelock_expired_script, renew_script: timelock_renew_script } => {
                let scripts = vec![timelock_expired_script.clone(), timelock_renew_script.clone()];
                let (info, script) = ProtocolBuilder::taproot_spend_info(internal_key.clone(), &scripts)?;
                
                transaction.output.push(transaction::TxOut {
                    value: Amount::from_sat(*value),
                    script_pubkey: script,
                });

                Some(info)
            },
        };

        Ok(spend_info)
    }

    fn add_input(transaction: &mut Transaction, input: &Input, output_index: usize, spend_info: Option<TaprootSpendInfo>) -> Result<(), ProtocolBuilderError> {
        match spend_info {
            Some(info) => {
                match input.get_type() {
                    InputType::TaprootScriptSpend { sighash_type } => {
                        let pevious_outpoint = OutPoint { txid: Hash::all_zeros(), vout: output_index as u32 };
                        
                        transaction.input.push(transaction::TxIn {
                            previous_output: pevious_outpoint,
                            script_sig: ScriptBuf::default(),
                            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                            witness: Witness::default(),
                        });
                    },

                    InputType::Timelock { blocks, renew_script, sighash_type } => {
                        let pevious_outpoint = OutPoint { txid: Hash::all_zeros(), vout: output_index as u32 };
        
                        let sequence = match blocks {
                            0 => Sequence::ENABLE_RBF_NO_LOCKTIME,
                            _ => Sequence::from_height(*blocks),
                        };
                
                        transaction.input.push(transaction::TxIn {
                            previous_output: pevious_outpoint,
                            script_sig: ScriptBuf::default(),
                            sequence,
                            witness: Witness::default(),
                        });
                    },

                    _ => {
                        return Err(ProtocolBuilderError::MissingSpendInfoForInputType(input.get_type().to_string()));
                    }
                }
            },
            None => {
                match input.get_type() {
                    InputType::P2WPKH { sighash_type } => {
                        let pevious_outpoint = OutPoint { txid: Hash::all_zeros(), vout: output_index as u32 };

                        transaction.input.push(transaction::TxIn {
                            previous_output: pevious_outpoint,
                            script_sig: ScriptBuf::default(),
                            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                            witness: Witness::default(),
                        });
                    },

                    InputType::P2WSH { sighash_type } => {
                        let pevious_outpoint = OutPoint { txid: Hash::all_zeros(), vout: output_index as u32 };

                        transaction.input.push(transaction::TxIn {
                            previous_output: pevious_outpoint,
                            script_sig: ScriptBuf::default(),
                            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                            witness: Witness::default(),
                        });
                    },

                    InputType::TaprootKeySpend { sighash_type } => {
                        let pevious_outpoint = OutPoint { txid: Hash::all_zeros(), vout: output_index as u32 };

                        transaction.input.push(transaction::TxIn {
                            previous_output: pevious_outpoint,
                            script_sig: ScriptBuf::default(),
                            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                            witness: Witness::default(),
                        });
                    },

                    _ => {
                        return Err(ProtocolBuilderError::UnnecessarySpendInfoForInputType(input.get_type().to_string()));
                    }
                }
            }
        }

        Ok(())
    }

    fn taproot_spend_info(internal_key: PublicKey, taproot_spending_scripts: &[ScriptBuf]) -> Result<(TaprootSpendInfo, ScriptBuf), ProtocolBuilderError> {
        let secp = secp256k1::Secp256k1::new();
        let scripts_count = taproot_spending_scripts.len();
        
        // To build a taproot tree, we need to calculate the depth of the tree.
        // If the list of scripts only contains 1 element, the depth is 1, otherwise we compute the depth 
        // as the log2 of the number of scripts rounded up to the nearest integer.
        let depth = cmp::max(1, (scripts_count as f32).log2().ceil() as u8);

        let mut tr_builder = TaprootBuilder::new();
        for script in taproot_spending_scripts.iter() {
            tr_builder = tr_builder.add_leaf(depth, script.clone())?;
        }

        // If the number of spend conditions is odd, add the last one again
        if scripts_count % 2 != 0 {
            tr_builder = tr_builder.add_leaf(depth, taproot_spending_scripts[scripts_count - 1].clone())?;
        }
    
        let tr_spend_info = tr_builder.finalize(&secp, internal_key.into()).map_err(|_| ProtocolBuilderError::TapTreeFinalizeError)?;

        let script_pubkey = ScriptBuf::new_p2tr(
            &secp,
            tr_spend_info.internal_key(),
            tr_spend_info.merkle_root(),
        );

        Ok((tr_spend_info, script_pubkey))
    }
}

