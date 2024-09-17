use std::{collections::HashMap, cmp::max};
use lazy_static::lazy_static;

use bitcoin::{EcdsaSighashType, SegwitV0Sighash,hashes::Hash, key::Secp256k1, locktime, secp256k1::{self, All}, sighash::{self, SighashCache}, taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo}, transaction, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TapLeafHash, TapSighash, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness};
use serde::{Deserialize, Serialize, ser::SerializeStruct};

use crate::{errors::TemplateError, scripts::{ScriptParam, ScriptWithParams}, unspendable::unspendable_key};

lazy_static! {
    static ref SECP: Secp256k1<All> = Secp256k1::new();
}

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Represents an output of a previous transaction that is consumed by an output in this transaction.
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendingPath {
    sighash: Option<TapSighash>,
    signature: Option<bitcoin::taproot::Signature>,
    script: ScriptBuf,
    script_params: Vec<ScriptParam>,
}

impl SpendingPath {
    pub fn get_signature(&self) -> Option<bitcoin::taproot::Signature> {
        self.signature
    }

    pub fn get_sighash(&self) -> Option<TapSighash> {
        self.sighash
    }

    pub fn get_taproot_leaf(&self) -> ScriptBuf {
        self.script.clone()
    }

    pub fn get_script_params(&self) -> Vec<ScriptParam> {
        self.script_params.clone()
    }
}


#[derive(Clone, Debug)]
pub enum InputType {
    Taproot {
        sighash_type: TapSighashType,
        taproot_spend_info: TaprootSpendInfo,
        taproot_internal_key: PublicKey,
        spending_paths: HashMap<TapLeafHash, SpendingPath>,
    },
    P2WPKH {
        sighash_type: EcdsaSighashType,
        script_pubkey: ScriptBuf,
        sighash: Option<SegwitV0Sighash>,
        signature: Option<bitcoin::ecdsa::Signature>,
        amount: Amount,
    },
}

impl Serialize for InputType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            InputType::Taproot {
                sighash_type,
                spending_paths,
                taproot_spend_info: _,
                taproot_internal_key
            } => {
                let mut state = serializer.serialize_struct("Taproot", 2)?;
                state.serialize_field("tap_sighash_type", sighash_type)?;
                state.serialize_field("spending_paths", spending_paths)?;
                state.serialize_field("taproot_internal_key", taproot_internal_key)?;
                state.end()
            }
            InputType::P2WPKH {
                sighash_type,
                script_pubkey,
                sighash,
                signature,
                amount,
            } => {
                let mut state = serializer.serialize_struct("P2WPKH", 5)?;
                state.serialize_field("ecdsa_sighash_type", sighash_type)?;
                state.serialize_field("script_pubkey", script_pubkey)?;
                state.serialize_field("sighash", sighash)?;
                state.serialize_field("signature", signature)?;
                state.serialize_field("amount", amount)?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for InputType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            TapSighashType,
            EcdsaSighashType,
            SpendingPaths,
            TaprootInternalKey,
            ScriptPubkey,
            Sighash,
            Signature,
            Amount,
        }

        struct InputTypeVisitor;

        impl<'de> serde::de::Visitor<'de> for InputTypeVisitor {
            type Value = InputType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct InputType")
            }

            fn visit_map<V>(self, mut map: V) -> Result<InputType, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut tap_sighash_type = None;
                let mut ecdsa_sighash_type = None;
                let mut spending_paths: Option<HashMap<TapLeafHash, SpendingPath>> = None;
                let mut taproot_internal_key: Option<PublicKey> = None;
                let mut script_pubkey = None;
                let mut sighash = None;
                let mut signature = None;
                let mut amount = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::TapSighashType => {
                            if tap_sighash_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("tap_sighash_type"));
                            }
                            if let Some(value) = map.next_value()?{
                                tap_sighash_type = Some(value);
                            };
                            
                        }
                        Field::EcdsaSighashType => {
                            if ecdsa_sighash_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("ecdsa_sighash_type"));
                            }
                            if let Some(value) = map.next_value()?{
                                ecdsa_sighash_type = Some(value);
                            };
                        }
                        Field::SpendingPaths => {
                            if spending_paths.is_some() {
                                return Err(serde::de::Error::duplicate_field("spending_paths"));
                            }
                            if let Some(value) = map.next_value()?{
                                spending_paths = Some(value);
                            };
                        }
                        Field::TaprootInternalKey => {
                            if taproot_internal_key.is_some() {
                                return Err(serde::de::Error::duplicate_field("taproot_internal_key"));
                            }
                            if let Some(value) = map.next_value()?{
                                taproot_internal_key = Some(value);
                            };
                        }
                        Field::ScriptPubkey => {
                            if script_pubkey.is_some() {
                                return Err(serde::de::Error::duplicate_field("script_pubkey"));
                            }
                            if let Some(value) = map.next_value()?{
                                script_pubkey = Some(value);
                            }
                        }
                        Field::Sighash => {
                            if sighash.is_some() {
                                return Err(serde::de::Error::duplicate_field("sighash"));
                            }
                            if let Some(value) = map.next_value()?{
                                sighash = Some(value);
                            }
                        }
                        Field::Signature => {
                            if signature.is_some() {
                                return Err(serde::de::Error::duplicate_field("signature"));
                            }
                            if let Some(value) =  map.next_value()?{
                                signature = Some(value);   
                            }
                        }
                        Field::Amount => {
                            if amount.is_some() {
                                return Err(serde::de::Error::duplicate_field("amount"));
                            }
                            if let Some(value) = map.next_value()?{
                                amount = Some(value);
                            }
                        }
                    }
                }

                if spending_paths.is_some() {
                    Ok(InputType::Taproot {
                        sighash_type: tap_sighash_type.ok_or_else(|| serde::de::Error::missing_field("sighash_type"))?,
                        taproot_spend_info: {
                            let internal_key = taproot_internal_key.ok_or_else(|| serde::de::Error::missing_field("taproot_internal_key"))?;
                            let spending_paths_ok = spending_paths.clone().ok_or_else(|| serde::de::Error::missing_field("spending_paths"))?;
                            let scripts: Vec<ScriptBuf> = spending_paths_ok.values().into_iter().map(|sp| sp.get_taproot_leaf()).collect();
                            match Template::taproot_spend_info(internal_key, &scripts){
                                Ok((taproot_spend_info, _)) => taproot_spend_info,
                                Err(e) => {
                                    eprintln!("Error creating taproot spend info: {:?}", e);
                                    return Err(serde::de::Error::custom("Error creating taproot spend info"))
                                }
                            }
                        },
                        taproot_internal_key: taproot_internal_key.ok_or_else(|| serde::de::Error::missing_field("taproot_internal_key"))?,                      
                        spending_paths: match spending_paths {
                            Some(paths) => paths,
                            None => HashMap::new(),
                            
                        },
                    })
                } else {
                    Ok(InputType::P2WPKH {
                        sighash_type: ecdsa_sighash_type.ok_or_else(|| serde::de::Error::missing_field("ecdsa_sighash_type"))?,
                        script_pubkey: script_pubkey.ok_or_else(|| serde::de::Error::missing_field("script_pubkey"))?,
                        sighash,
                        signature,
                        amount: amount.ok_or_else(|| serde::de::Error::missing_field("amount"))?,
                    })
                }
            }
        }

        const FIELDS: &[&str] = &[
            "sighash_type",
            "spending_paths",
            "script_pubkey",
            "sighash",
            "signature",
            "amount",
        ];
        deserializer.deserialize_struct("InputType", FIELDS, InputTypeVisitor)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Input {
    to: String,
    index: usize,
    input_type: InputType,
    signature_verifying_key: Option<PublicKey>,
}



impl Input {
    pub fn new(to: &str, index: usize, input_type: InputType) -> Self {
        Input {
            to: to.to_string(),
            index,
            input_type,
            signature_verifying_key: None,
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

    pub fn get_verifying_key(&self) -> Option<PublicKey> {
        self.signature_verifying_key
    }
}

pub struct ScriptArgs {
    input_index: usize,
    spending_leaf: ScriptBuf,
    values: Vec<Vec<u8>>,
}

impl ScriptArgs {
    pub fn new(input_index: usize, spending_leaf: ScriptBuf, values: Vec<Vec<u8>>) -> Self {
        ScriptArgs {
            input_index,
            spending_leaf,
            values,
        }
    }

    pub fn get_input_index(&self) -> usize {
        self.input_index
    }

    pub fn get_spending_leaf(&self) -> ScriptBuf {
        self.spending_leaf.clone()
    }

    pub fn get_values(&self) -> Vec<Vec<u8>> {
        self.values.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]

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

                    for (leaf_hash, spending_path) in spending_paths {
                        let sighash = sighasher.taproot_script_spend_signature_hash(
                            input.index,
                            &sighash::Prevouts::All(&tx_outs),
                            *leaf_hash,
                            *sighash_type,
                        )?;
    
                        spending_path.sighash = Some(sighash);
                    }
                },
    
                InputType::P2WPKH { sighash_type, script_pubkey, amount, signature, .. } => {
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
                        signature: *signature 
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
            signature: None,
        };

        let input = Input::new(&self.name, self.transaction.input.len() - 1, input_type);
        self.inputs.push(input.clone());
    }

    pub fn push_taproot_input(&mut self, sighash_type: TapSighashType, previous_output: Output, locked_blocks: u16, taproot_spend_info: TaprootSpendInfo, taproot_spending_scripts: &[ScriptWithParams]) -> Input {
        let pevious_outpoint = OutPoint { txid: Hash::all_zeros(), vout: previous_output.index as u32 };
        let txin = Self::build_input(pevious_outpoint, Sequence::from_height(locked_blocks));

        self.transaction.input.push(txin);
        self.previous_outputs.push(previous_output);

        let input_type = InputType::Taproot {
            sighash_type,
            taproot_spend_info: taproot_spend_info.clone(),
            taproot_internal_key: {
                let internal_key = taproot_spend_info.internal_key();
                PublicKey::new(internal_key.public_key(taproot_spend_info.output_key_parity()))
            },
            spending_paths: taproot_spending_scripts.iter().map(|s| {
                let leaf_hash = TapLeafHash::from_script(s.get_script(), LeafVersion::TapScript);
                let path = SpendingPath {
                    sighash: None,
                    signature: None,
                    script: s.get_script().clone(),
                    script_params: s.get_params(),
                };
            

                (leaf_hash, path)
            }).collect(),
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
            signature: None,
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

    pub fn push_taproot_signature(&mut self, index: usize, taproot_leaf: &ScriptBuf, signature: bitcoin::taproot::Signature, public_key: &PublicKey) -> Result<(), TemplateError> {
        self.inputs[index].signature_verifying_key = Some(*public_key);
        
        match &mut self.inputs[index].input_type {
            InputType::Taproot { spending_paths, .. } => {
                let leaf_hash = TapLeafHash::from_script(taproot_leaf, LeafVersion::TapScript);
                
                let spending_path = match spending_paths.get_mut(&leaf_hash) {
                    Some(sp) => sp,
                    None => return Err(TemplateError::MissingSpendingPath(index)),
                };

                spending_path.signature = Some(signature);

                Ok(())
            },
            _ => Err(TemplateError::InvalidInputType(index)),
        }
    }

    pub fn push_ecdsa_signature(&mut self, index: usize, signature: bitcoin::ecdsa::Signature, public_key: &PublicKey) -> Result<(), TemplateError> {
        self.inputs[index].signature_verifying_key = Some(*public_key);

        match &mut self.inputs[index].input_type {
            InputType::P2WPKH { sighash_type, script_pubkey, amount, sighash, .. }  => {
                self.inputs[index].input_type = InputType::P2WPKH { 
                    sighash_type: *sighash_type, 
                    script_pubkey: script_pubkey.clone(), 
                    amount: *amount, 
                    sighash: *sighash, 
                    signature: Some(signature) 
                };

                Ok(())
            },
            _ => Err(TemplateError::InvalidInputType(index)),
        }
    }

    pub fn get_transaction_for_inputs(&mut self, params: Vec<ScriptArgs>) -> Result<Transaction, TemplateError> {
        for param in params {
            let input_index = param.input_index;

            let witness = self.get_witness_for_spending_path(param)?;
            self.transaction.input[input_index].witness = witness;
        }

        Ok(self.transaction.clone())
    }

    pub fn get_transaction_for_input(&mut self, params: ScriptArgs) -> Result<Transaction, TemplateError> {
        let input_index = params.input_index;

        let witness = self.get_witness_for_spending_path(params)?;
        self.transaction.input[input_index].witness = witness;
        Ok(self.transaction.clone())
    }

    fn get_witness_for_spending_path(&self, params: ScriptArgs) -> Result<Witness, TemplateError> {
        let input = &self.inputs[params.input_index];

        match &input.input_type {
            InputType::Taproot { spending_paths, taproot_spend_info, .. } => {
                let leaf_hash = TapLeafHash::from_script(&params.spending_leaf, LeafVersion::TapScript);
                let path = match spending_paths.get(&leaf_hash) {
                    Some(sp) => sp,
                    None => return Err(TemplateError::MissingSpendingPath(params.input_index)),
                };

                let signature = match path.signature {
                    Some(sig) => sig,
                    None => return Err(TemplateError::MissingSpendingPath(params.input_index)),
                };

                let control_block = match taproot_spend_info.control_block(&(params.spending_leaf.clone(), LeafVersion::TapScript)) {
                    Some(cb) => cb,
                    None => return Err(TemplateError::InvalidSpendingPath(params.input_index)),
                };

                if !control_block.verify_taproot_commitment(&SECP, taproot_spend_info.output_key().to_inner(), &params.spending_leaf) {
                    return Err(TemplateError::InvalidSpendingPath(params.input_index));
                }
        
                let mut witness = Witness::default();
                witness.push(signature.serialize());
                witness.push(params.spending_leaf.to_bytes());
                witness.push(control_block.serialize());

                // TODO fix the relationship between values and OT Signatures
                for value in params.values.iter() {
                    // We only need to push the winternitz signed values
                    // witness.push(param.get_verifying_key().to_bytes());
                    witness.push(value.clone());
                }
        
                Ok(witness)
            },
            InputType::P2WPKH { signature, .. } => {

                let signature = match signature {
                    Some(sig) => sig,
                    None => return Err(TemplateError::MissingSignature(params.input_index)),
                };

                let pubkey = match input.signature_verifying_key {
                    Some(pk) => pk,
                    None => return Err(TemplateError::MissingSignatureVerifyingKey(params.input_index)),
                };

                let witness = Witness::p2wpkh(
                    signature, 
                    &pubkey.inner
                );

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
        let depth = max(1, (scripts_count as f32).log2().ceil() as u8);

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
