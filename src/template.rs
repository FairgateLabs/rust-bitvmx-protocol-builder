use std::{cmp, vec};
use lazy_static::lazy_static;
use bitcoin::{hashes::Hash, key::Secp256k1, locktime, secp256k1::{self, All}, sighash::{self, SighashCache}, taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo}, transaction, Amount, EcdsaSighashType, OutPoint, PublicKey, ScriptBuf, SegwitV0Sighash, Sequence, TapLeafHash, TapSighash, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness};

use crate::{errors::TemplateError, scripts::ScriptWithParams, unspendable::unspendable_key};

lazy_static! {
    static ref SECP: Secp256k1<All> = Secp256k1::new();
}

#[derive(Clone, Debug)]
pub struct Output {
    from: String,
    index: usize,
    txout: TxOut,
}

impl Output { 
    pub fn new(from: String, index: usize, txout: TxOut) -> Self {
        Output {
            from,
            index,
            txout,
        }
    }

    pub fn get_from(&self) -> &str {
        &self.from
    }

    pub fn get_index(&self) -> usize {
        self.index
    }

    pub fn get_txout(&self) -> &TxOut {
        &self.txout
    }
}

#[derive(Clone, Debug)]
pub struct SpendingPath {
    sighash: Option<TapSighash>,
    script: ScriptBuf,
}

impl SpendingPath {
    pub fn new(script: ScriptBuf) -> Self {
        Self {
            sighash: None,
            script,
        }
    }
    
    pub fn get_sighash(&self) -> Option<TapSighash> {
        self.sighash
    }

    pub fn get_taproot_leaf(&self) -> ScriptBuf {
        self.script.clone()
    }
}

#[derive(Clone, Debug)]
pub enum InputType {
    Taproot {
        sighash_type: TapSighashType,
        taproot_spend_info: TaprootSpendInfo,
        spending_paths: Vec<SpendingPath>,
    },
    P2WPKH {
        sighash_type: EcdsaSighashType,
        script_pubkey: ScriptBuf,
        sighash: Option<SegwitV0Sighash>,
        amount: Amount,
    },
}

// TODO add taproot key_spend type
#[derive(Clone, Debug)]
pub enum SpendingType {
    Taproot {
        spending_script: ScriptBuf
    },
    P2WPKH,
}

#[derive(Clone, Debug)]
pub struct SpendingInformation {
    input_index: usize, 
    spending_type: SpendingType,
    script_args: Vec<Vec<u8>>,
}

impl SpendingInformation {
    pub fn new_taproot_spending(input_index: usize, spending_script: ScriptBuf) -> Self {
        Self {
            input_index,
            spending_type: SpendingType::Taproot {
                spending_script
            },
            script_args: vec![],
        }
    }

    pub fn new_p2wpkh_spending(input_index: usize) -> Self {
        Self {
            input_index,
            spending_type: SpendingType::P2WPKH,
            script_args: vec![],
        }
    }

    pub fn push_script_arg(&mut self, arg: &[u8]) {
        self.script_args.push(arg.to_vec());
    }

    pub fn get_script_args(&self) -> Vec<Vec<u8>> {
        self.script_args.clone()
    }
}

#[derive(Clone, Debug)]
pub struct Input {
    to: String,
    index: usize,
    input_type: InputType,
}

impl Input {
    pub fn new(to: &str, index: usize, input_type: InputType) -> Self {
        Input {
            to: to.to_string(),
            index,
            input_type,
        }
    }

    pub fn get_to(&self) -> &str {
        &self.to
    }

    pub fn get_index(&self) -> usize {
        self.index
    }

    pub fn get_type(&self) -> &InputType {
        &self.input_type
    }
}

#[derive(Clone, Debug)]
pub struct Template {
    name: String,
    txid: Txid,
    transaction: Transaction,
    inputs: Vec<Input>,
    previous_outputs: Vec<Output>,
    next_inputs: Vec<Input>,
}

impl Template {
    pub fn new(name: &str, speedup_script: &ScriptBuf, speedup_amount: u64) -> Self {
        let mut template = Template {
            name: name.to_string(),
            txid: Hash::all_zeros(),
            transaction: Self::build_transaction(),
            previous_outputs: vec![],
            next_inputs: vec![],
            inputs: vec![],
        };

        template.push_output_with_script(speedup_amount, speedup_script);
        template
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_next_inputs(&self) -> Vec<Input> {
        self.next_inputs.clone()
    }

    pub fn get_previous_outputs(&self) -> Vec<Output> {
        self.previous_outputs.clone()
    }

    pub fn get_outputs(&self) -> Vec<TxOut> {
        self.transaction.output.clone()
    }

    pub fn get_transaction(&self) -> Transaction {
        self.transaction.clone()
    }

    pub fn compute_txid(&mut self) -> Txid {
        let txid = self.transaction.compute_txid();
        self.txid = txid;

        txid
    }

    /// Computes the sighash for each each input. Since templates are pre-signed, and we could have
    /// multiple spending scripts (tapleaves) per input, we need to compute the sighash for each spending script.
    pub fn compute_spend_signature_hashes(&mut self) -> Result<(), TemplateError> {
        let mut sighasher = SighashCache::new(self.transaction.clone());
    
        for input in &mut self.inputs {
            match &mut input.input_type {
                InputType::Taproot { sighash_type, spending_paths, .. } => {
                    let tx_outs  = self.previous_outputs.iter().map(|po| po.txout.clone()).collect::<Vec<TxOut>>();

                    for spending_path in spending_paths {
                        let sighash = sighasher.taproot_script_spend_signature_hash(
                            input.index,
                            &sighash::Prevouts::All(&tx_outs),
                            TapLeafHash::from_script(&spending_path.get_taproot_leaf(), LeafVersion::TapScript),
                            *sighash_type,
                        )?;
    
                        spending_path.sighash = Some(sighash);
                    }
                },
    
                InputType::P2WPKH { sighash_type, script_pubkey, amount,  .. } => {
                    let sighash = sighasher.p2wpkh_signature_hash(
                        input.index,
                        script_pubkey,
                        *amount,
                        *sighash_type,
                    )?;
    
                    input.input_type = InputType::P2WPKH { 
                        sighash_type: *sighash_type, 
                        script_pubkey: script_pubkey.clone(), 
                        amount: *amount, 
                        sighash: Some(sighash), 
                    };
                },
            }
        }
    
        Ok(())
    }

    pub fn get_inputs(&self) -> Vec<Input> {
        self.inputs.clone()
    }

    pub fn get_input(&self, input_index: usize) -> Input {
        self.inputs[input_index].clone()
    }

    pub fn update_input(&mut self, index: usize, txid: Txid) {
        self.transaction.input[index].previous_output.txid = txid;
    }

    pub fn push_start_input(&mut self, sighash_type: EcdsaSighashType, previous_tx: Txid, vout: u32, amount: u64, script_pubkey: ScriptBuf) {
        let previous_outpoint = OutPoint {
            txid: previous_tx,
            vout,
        };

        let txin = Self::build_input(previous_outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME);
        self.transaction.input.push(txin);

        let input_type = InputType::P2WPKH {
            sighash_type,
            script_pubkey: script_pubkey.clone(),
            amount: Amount::from_sat(amount),
            sighash: None,
        };

        let input = Input::new(&self.name, self.transaction.input.len() - 1, input_type);
        self.inputs.push(input.clone());
    }

    pub fn push_taproot_input(&mut self, sighash_type: TapSighashType, previous_output: Output, locked_blocks: u16, taproot_spend_info: TaprootSpendInfo, taproot_spending_scripts: &[ScriptWithParams]) -> Input {        
        let pevious_outpoint = OutPoint { txid: Hash::all_zeros(), vout: previous_output.index as u32 };
        
        let sequence = match locked_blocks {
            0 => Sequence::ENABLE_RBF_NO_LOCKTIME,
            _ => Sequence::from_height(locked_blocks),
        };

        let txin = Self::build_input(pevious_outpoint, sequence);

        self.transaction.input.push(txin);
        self.previous_outputs.push(previous_output);

        let input_type = InputType::Taproot {
            sighash_type,
            taproot_spend_info,
            spending_paths: taproot_spending_scripts.iter().map(|s| {
                let path = SpendingPath::new(s.get_script().clone());
                path
            }).collect()
        };

        let input = Input::new(&self.name, self.transaction.input.len() - 1, input_type);
        self.inputs.push(input.clone());

        input
    }

    pub fn push_segwit_input(&mut self, sighash_type: EcdsaSighashType, previous_output: Output, script_pubkey: ScriptBuf, amount: u64) -> Input {
        let outpoint = OutPoint { txid: Hash::all_zeros(), vout: previous_output.index as u32 };
        let txin = Self::build_input(outpoint, Sequence::ENABLE_RBF_NO_LOCKTIME);

        self.transaction.input.push(txin);
        self.previous_outputs.push(previous_output);

        let input_type = InputType::P2WPKH {
            sighash_type,
            script_pubkey: script_pubkey.clone(),
            amount: Amount::from_sat(amount),
            sighash: None,
        };

        let input = Input::new(&self.name, self.transaction.input.len() - 1, input_type);
        self.inputs.push(input.clone());

        input
    }
    
    pub fn push_output(&mut self, amount: u64, taproot_spending_scripts: &[ScriptWithParams]) -> Result<(Output, TaprootSpendInfo), TemplateError> {
        let internal_key = Self::create_unspendable_key()?;

        let scripts: &[ScriptBuf] = &taproot_spending_scripts.iter().map(|s| s.get_script().clone()).collect::<Vec<ScriptBuf>>();

        let (taproot_spend_info, script) = Self::taproot_spend_info(internal_key, scripts)?;
        let txout = Self::build_output(amount, &script);
        
        self.transaction.output.push(txout.clone());

        let output = Output::new(self.name.to_string(),self.transaction.output.len() - 1, txout);

        Ok((output, taproot_spend_info))
    }

    pub fn push_next_input(&mut self, next_input: Input) {
        self.next_inputs.push(next_input);
    }

    pub fn get_transaction_for_inputs(&mut self, spending_information: Vec<&SpendingInformation>) -> Result<Transaction, TemplateError> {
        for info in spending_information {
            let input_index = info.input_index;
            let witness = self.get_witness_for_input(info)?;
            self.transaction.input[input_index].witness = witness;
        }

        Ok(self.transaction.clone())
    }

    pub fn get_transaction_for_input(&mut self, spending_info: &SpendingInformation) -> Result<Transaction, TemplateError> {
        let input_index = spending_info.input_index;
        let witness = self.get_witness_for_input(spending_info)?;
        self.transaction.input[input_index].witness = witness;
        Ok(self.transaction.clone())
    }

    fn get_witness_for_input(&self, spending_info: &SpendingInformation) -> Result<Witness, TemplateError> {
        let input_index = spending_info.input_index;

        match &self.inputs[input_index].input_type {
            InputType::Taproot { taproot_spend_info, .. } => {
                let script_args = spending_info.get_script_args();
                let leaf = match &spending_info.spending_type {
                    SpendingType::Taproot { spending_script } => {
                        spending_script
                    },

                    SpendingType::P2WPKH => return Err(TemplateError::InvalidScriptParams(input_index)),
                };
                
                let control_block = match taproot_spend_info.control_block(&(leaf.clone(), LeafVersion::TapScript)) {
                    Some(cb) => cb,
                    None => return Err(TemplateError::InvalidSpendingPath(input_index)),
                };

                if !control_block.verify_taproot_commitment(&SECP, taproot_spend_info.output_key().to_inner(), leaf) {
                    return Err(TemplateError::InvalidSpendingPath(input_index));
                }

                let mut witness = Witness::default();
        
                for value in script_args.iter() {
                    witness.push(value.clone());
                }

                witness.push(leaf.to_bytes());
                witness.push(control_block.serialize());
        
                Ok(witness)
            },

            InputType::P2WPKH { .. } => {
                let mut witness = Witness::default();

                // TODO fix the relationship between values and OT Signatures
                for value in spending_info.script_args.iter() {
                    witness.push(value.clone());
                }

                Ok(witness)
            },
        }
    }

    fn push_output_with_script(&mut self, amount: u64, script: &ScriptBuf) -> usize {
        let txout = Self::build_output(amount, script);

        self.transaction.output.push(txout);
        self.transaction.output.len() - 1
    }

    fn taproot_spend_info(internal_key: PublicKey, taproot_spending_scripts: &[ScriptBuf]) -> Result<(TaprootSpendInfo, ScriptBuf), TemplateError> {
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
    
        let tr_spend_info = tr_builder.finalize(&secp, internal_key.into()).map_err(|_| TemplateError::TapTreeFinalizeError)?;

        let script_pubkey = ScriptBuf::new_p2tr(
            &secp,
            tr_spend_info.internal_key(),
            tr_spend_info.merkle_root(),
        );

        Ok((tr_spend_info, script_pubkey))
    }

    fn build_transaction() -> Transaction {
        Transaction {
            version: transaction::Version::TWO, // Post BIP-68.
            lock_time: locktime::absolute::LockTime::ZERO, // Ignore the locktime.
            input: vec![],
            output: vec![],
        }
    }

    fn build_input(outpoint: OutPoint, sequence: Sequence) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::default(), // For p2wpkh script_sig is empty.
            sequence,
            witness: Witness::default(),
        }
    }

    fn build_output(amount: u64, script: &ScriptBuf) -> TxOut {
        TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: script.clone(),
        }
    }

    fn create_unspendable_key() -> Result<PublicKey, TemplateError> {
        let mut rng = secp256k1::rand::thread_rng();
        let key = unspendable_key(&mut rng)?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use bitcoin::PublicKey;
    use bitcoin_scriptexec::treepp::*;

    use super::*;

    const PUB_KEY: &str = "03c7805b5add3c9ae01d0998392295f09dbcf25d33677842e8ad0b29f51bbaeac2";

    fn get_script_buff() -> ScriptBuf {
        
        let aggregated_key = PublicKey::from_str(PUB_KEY);
        let script = script!(
            { aggregated_key.unwrap().to_bytes() }
            OP_CHECKSIG
        );
    
        return script!{
            OP_IF
            OP_TRUE
            OP_ELSE
            {script}
            OP_ENDIF
        };
    }

    fn get_test_output() -> Output{
        let taproot_spending_scripts = [ScriptWithParams::new(get_script_buff())];

        let scripts: &[ScriptBuf] = &taproot_spending_scripts.iter().map(|s| s.get_script().clone()).collect::<Vec<ScriptBuf>>();
        let internal_key = Template::create_unspendable_key();

        let (_taproot_spend_info, script) = Template::taproot_spend_info(internal_key.unwrap(), scripts).unwrap();
        let txout = Template::build_output(1, &script);
        
        return Output::new("test".to_string(),0, txout);
    }    

    #[test]
    fn test_get_tx_output() {
        let output = get_test_output();

        assert_eq!(output.get_txout().value, Amount::from_sat(1));
    }

    #[test]
    fn test_push_segwit_input() {
        let taproot_spending_scripts = [ScriptWithParams::new(get_script_buff())];
        let scripts: &[ScriptBuf] = &taproot_spending_scripts.iter().map(|s| s.get_script().clone()).collect::<Vec<ScriptBuf>>();        
        let output = get_test_output();        
        let mut template = Template::new("test", &scripts[0], 1);
        let input = Template::push_segwit_input(&mut template, EcdsaSighashType::from_consensus(1), output, get_script_buff(), 1);

        assert_eq!(input.to, "test");        
    }

    #[test]
    fn test_get_tx_input() {
        let taproot_spending_scripts = [ScriptWithParams::new(get_script_buff())];
        let scripts: &[ScriptBuf] = &taproot_spending_scripts.iter().map(|s| s.get_script().clone()).collect::<Vec<ScriptBuf>>();
        let output = get_test_output();                
        let mut template = Template::new("test", &scripts[0], 1);
        
        Template::push_segwit_input(&mut template, EcdsaSighashType::from_consensus(1), output, get_script_buff(), 1);        
        
        let spending_info = &SpendingInformation::new_taproot_spending(0, get_script_buff());
        let tx_for_input = Template::get_transaction_for_input(&mut template, spending_info);
        
        assert_eq!(tx_for_input.unwrap().input.len(), 1)
    }

    #[test]
    fn test_get_tx_inputs() {
        let taproot_spending_scripts = [ScriptWithParams::new(get_script_buff())];
        let scripts: &[ScriptBuf] = &taproot_spending_scripts.iter().map(|s| s.get_script().clone()).collect::<Vec<ScriptBuf>>();
        let output = get_test_output();                
        let mut template = Template::new("test", &scripts[0], 1);
        
        Template::push_segwit_input(&mut template, EcdsaSighashType::from_consensus(1), output, get_script_buff(), 1);        
        
        let spending_info = &SpendingInformation::new_taproot_spending(0, get_script_buff());
        let tx_for_input = Template::get_transaction_for_inputs(&mut template, vec![spending_info]);
        
        assert_eq!(tx_for_input.unwrap().input.len(), 1)
    }

    #[test]
    fn test_get_witness_for_inputs() {
        let taproot_spending_scripts = [ScriptWithParams::new(get_script_buff())];
        let scripts: &[ScriptBuf] = &taproot_spending_scripts.iter().map(|s| s.get_script().clone()).collect::<Vec<ScriptBuf>>();
        let output = get_test_output();                
        let mut template = Template::new("test", &scripts[0], 1);
        let sighash = Some(SegwitV0Sighash::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash("asd".as_bytes())));

        let input = Input::new("B", 0, InputType::P2WPKH { sighash_type: EcdsaSighashType::from_consensus(1),
             script_pubkey: get_script_buff(),
              sighash: sighash,
              amount: Amount::from_int_btc(1)});

        template.push_next_input(input);              
        Template::push_segwit_input(&mut template, EcdsaSighashType::from_consensus(1), output, get_script_buff(), 1);        
        
        let taproot_spending_info = &SpendingInformation::new_taproot_spending(0, get_script_buff());
        let p2wpkh_spending_info = &&SpendingInformation::new_p2wpkh_spending(0);
        let _tx_taproot_for_input = Template::get_witness_for_input(&mut template, taproot_spending_info);
        let _tx_p2wpkh_for_input = Template::get_witness_for_input(&mut template, p2wpkh_spending_info);
        
        assert!(_tx_taproot_for_input.unwrap().is_empty());
        assert!(_tx_p2wpkh_for_input.unwrap().is_empty());
    }
}