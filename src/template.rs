use std::collections::HashMap;
use lazy_static::lazy_static;
use bitcoin::{hashes::Hash, key::Secp256k1, locktime, secp256k1::{self, All}, sighash::{self, SighashCache}, taproot::{LeafVersion, Signature, TaprootBuilder, TaprootSpendInfo}, transaction, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TapLeafHash, TapSighash, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness};

use crate::{errors::TemplateError, scripts::{ScriptParam, ScriptWithParams}, unspendable::unspendable_key};

lazy_static! {
    static ref SECP: Secp256k1<All> = Secp256k1::new();
}

#[derive(Clone, Debug)]
/// Represents an output of a previous transaction that is consumed by an output in this transaction.
pub struct PreviousOutput {
    from: String,
    index: usize,
    txout: TxOut,
    taproot_spend_info: TaprootSpendInfo
}

impl PreviousOutput { 
    pub fn new(from: String, index: usize, txout: TxOut, taproot_spend_info: TaprootSpendInfo) -> Self {
        PreviousOutput {
            from,
            index,
            txout,
            taproot_spend_info,
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

    pub fn get_taproot_spend_info(&self) -> TaprootSpendInfo {
        self.taproot_spend_info.clone()
    }
}

#[derive(Clone, Debug)]
/// Represents an input of a subsequent transaction that consumes an output from this transaction.
pub struct NextInput {
    to: String,
    index: usize,
}

impl NextInput {
    pub fn new(to: String, index: usize) -> Self {
        NextInput {
            to,
            index,
        }
    }
    
    pub fn get_to(&self) -> &str {
        &self.to
    }

    pub fn get_index(&self) -> usize {
        self.index
    }
}

#[derive(Clone, Debug)]
pub struct Input {
    taproot_spend_info: TaprootSpendInfo,
    signature_verifying_key: Option<PublicKey>,
    spending_paths: HashMap<TapLeafHash, SpendingPath>,
}

impl Input {
    pub fn new(sighash_type: TapSighashType, taproot_spending_scripts: &[ScriptWithParams], taproot_spend_info: TaprootSpendInfo) -> Self {
        Input {
            taproot_spend_info,
            signature_verifying_key: None,
            spending_paths: taproot_spending_scripts.iter().map(|taproot_leaf| {
                let leaf_hash = TapLeafHash::from_script(taproot_leaf.get_script(), LeafVersion::TapScript);
                let path = SpendingPath::new(sighash_type, taproot_leaf.clone());

                (leaf_hash, path)
            }).collect(),
        }
    }

    pub fn get_spending_path(&self, taproot_leaf: &ScriptBuf) -> Option<SpendingPath> {
        let leaf_hash = TapLeafHash::from_script(taproot_leaf, LeafVersion::TapScript);
        self.spending_paths.get(&leaf_hash).cloned()
    }
    
    pub fn get_spending_paths(&self) -> Vec<SpendingPath> {
        self.spending_paths.values().cloned().collect()
    }
    
    pub fn get_sighashes(&self) -> Vec<TapSighash> {
        self.spending_paths.values().map(|sp| sp.sighash.unwrap()).collect()
    }
    
    pub fn get_signatures(&self) -> Vec<Signature> {
        self.spending_paths.values().map(|sp| sp.signature.unwrap()).collect()
    }

    pub fn get_verifying_key(&self) -> Option<PublicKey> {
        self.signature_verifying_key
    }

    pub fn get_taproot_spend_info(&self) -> TaprootSpendInfo {
        self.taproot_spend_info.clone()
    }
}

#[derive(Clone, Debug)]
pub struct SpendingPath {
    sighash_type: TapSighashType,
    sighash: Option<TapSighash>,
    signature: Option<Signature>,
    taproot_leaf: ScriptWithParams,
}

impl SpendingPath {
    fn new(sighash_type: TapSighashType, taproot_leaf: ScriptWithParams) -> Self {
        SpendingPath {
            sighash_type,
            sighash: None,
            signature: None,
            taproot_leaf,
        }
    }

    pub fn tap_leaf_hash(&self) -> TapLeafHash {
        TapLeafHash::from_script(self.taproot_leaf.get_script(), LeafVersion::TapScript)
    }

    pub fn get_sighash_type(&self) -> TapSighashType {
        self.sighash_type
    }

    pub fn get_sighash(&self) -> Option<TapSighash> {
        self.sighash
    }

    pub fn get_signature(&self) -> Option<Signature> {
        self.signature
    }

    pub fn get_taproot_leaf(&self) -> ScriptWithParams {
        self.taproot_leaf.clone()
    }

    pub fn get_script_params(&self) -> Vec<ScriptParam> {
        self.taproot_leaf.get_params()
    }
}

#[derive(Clone, Debug)]
pub struct Template {
    name: String,
    txid: Txid,
    transaction: Transaction,
    inputs: Vec<Input>,
    previous_outputs: Vec<PreviousOutput>,
    next_inputs: Vec<NextInput>,
}

impl Template {
    pub fn new(name: &str, speedup_script: &ScriptBuf, speedup_amount: u64, timelock_script: &ScriptBuf, locked_amount: u64) -> Self {
        let mut template = Template {
            name: name.to_string(),
            txid: Hash::all_zeros(),
            transaction: Self::build_transaction(),
            previous_outputs: vec![],
            next_inputs: vec![],
            inputs: vec![],
        };

        template.push_output_with_script(speedup_amount, speedup_script);
        template.push_output_with_script(locked_amount, timelock_script);
        template
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    // pub fn get_inputs(&self) -> Vec<TxIn> {
    //     self.transaction.input.clone()
    // }

    pub fn get_next_inputs(&self) -> Vec<NextInput> {
        self.next_inputs.clone()
    }

    pub fn get_previous_outputs(&self) -> Vec<PreviousOutput> {
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

    /// Computes the sighash for each spending script of each input. Since templates are pre-signed, and we have
    /// multiple spending scripts (tapleaves) per input, we need to compute the sighash for each spending script.
    pub fn compute_spend_signature_hashes(&mut self) -> Result<(), TemplateError> {
        let mut sighasher = SighashCache::new(self.transaction.clone());
        let prevouts = self.get_txouts();

        for input_index in 0..self.transaction.input.len() {
            let spending_info = &mut self.inputs[input_index];

            for spending_path in spending_info.get_spending_paths() {
                let leaf_hash = spending_path.tap_leaf_hash();
                let sighash = sighasher.taproot_script_spend_signature_hash(
                    input_index,
                    &sighash::Prevouts::All(&prevouts),
                    leaf_hash,
                    spending_path.sighash_type,
                )?;

                spending_info.spending_paths.get_mut(&leaf_hash).unwrap().sighash = Some(sighash);
            };
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

    pub fn push_input(&mut self, sighash_type: TapSighashType, previous_output: PreviousOutput, taproot_spending_scripts: &[ScriptWithParams]) -> NextInput {
        let outpoint = OutPoint { txid: Hash::all_zeros(), vout: previous_output.index as u32 };
        let txin = Self::build_input(outpoint);
        let taproot_spend_info = previous_output.get_taproot_spend_info();

        self.transaction.input.push(txin);
        self.previous_outputs.push(previous_output);

        self.inputs.push(Input::new(sighash_type, taproot_spending_scripts, taproot_spend_info));

        NextInput::new(self.name.clone(), self.transaction.input.len() - 1)
    }
    
    pub fn push_output(&mut self, amount: u64, taproot_spending_scripts: &[ScriptWithParams]) -> Result<PreviousOutput, TemplateError> {
        let internal_key = Self::create_unspendable_key()?;

        let scripts: &[ScriptBuf] = &taproot_spending_scripts.iter().map(|s| s.get_script().clone()).collect::<Vec<ScriptBuf>>();

        let (taproot_spend_info, script) = Self::taproot_spend_info(internal_key, scripts)?;
        let txout = Self::build_output(amount, &script);
        
        self.transaction.output.push(txout.clone());

        Ok(PreviousOutput::new(self.name.to_string(),self.transaction.output.len() - 1, txout, taproot_spend_info))
    }

    pub fn push_next_input(&mut self, next_input: NextInput) {
        self.next_inputs.push(next_input);
    }

    pub fn push_signature(&mut self, index: usize, spending_path: SpendingPath, signature: Signature, public_key: &PublicKey) {
        self.inputs[index].signature_verifying_key = Some(*public_key);
        self.inputs[index].spending_paths.get_mut(&spending_path.tap_leaf_hash()).unwrap().signature = Some(signature);
    }

    pub fn get_params_for_spending_path(&self, input_index: usize, spending_leaf: &ScriptBuf) -> Result<Vec<ScriptParam>, TemplateError> {
        let input = &self.inputs[input_index];
        let spending_path = match input.get_spending_path(spending_leaf) {
            Some(sp) => sp,
            None => return Err(TemplateError::MissingSpendingPath(input_index)),
        };

        Ok(spending_path.get_script_params())
    }

    pub fn get_transaction_for_spending_path(&mut self, input_index: usize, spending_leaf: &ScriptBuf, values: Vec<Vec<u8>>) -> Result<Transaction, TemplateError> {
        let input = &self.inputs[input_index];
        let spending_path = match input.get_spending_path(spending_leaf) {
            Some(sp) => sp,
            None => return Err(TemplateError::MissingSpendingPath(input_index)),
        };

        let taproot_spend_info = input.get_taproot_spend_info();
        let signature = spending_path.get_signature().unwrap();

        let params = spending_path.get_script_params();

        let control_block = taproot_spend_info.control_block(&(spending_leaf.clone(), LeafVersion::TapScript)).unwrap();
        if !control_block.verify_taproot_commitment(&SECP, taproot_spend_info.output_key().to_inner(), spending_leaf) {
            return Err(TemplateError::InvalidSpendingPath(input_index));
        }

        let mut witness = Witness::default();
        witness.push(signature.serialize());
        witness.push(spending_leaf.to_bytes());
        witness.push(control_block.serialize());

        for (param, value) in params.iter().zip(values.iter()) {
            witness.push(param.get_verifying_key().to_bytes());
            witness.push(value.clone());
        }

        self.transaction.input[input_index].witness = witness;

        Ok(self.transaction.clone())
    }

    fn get_txouts(&self) -> Vec<TxOut> {
        self.previous_outputs.iter().map(|po| po.txout.clone()).collect()
    }

    fn push_output_with_script(&mut self, amount: u64, script: &ScriptBuf) -> usize {
        let txout = Self::build_output(amount, script);

        self.transaction.output.push(txout);
        self.transaction.output.len() - 1
    }

    fn taproot_spend_info(internal_key: PublicKey, taproot_spending_scripts: &[ScriptBuf]) -> Result<(TaprootSpendInfo, ScriptBuf), TemplateError> {
        let secp = secp256k1::Secp256k1::new();
        let scripts_count = taproot_spending_scripts.len();
        
        let depth = (scripts_count as f32).log2().ceil() as u8;

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
        Transaction{
            version: transaction::Version::TWO, // Post BIP-68.
            lock_time: locktime::absolute::LockTime::ZERO, // Ignore the locktime.
            input: vec![],
            output: vec![],
        }
    }

    fn build_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::default(), // For p2wpkh script_sig is empty.
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
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
