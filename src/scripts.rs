use std::collections::HashMap;

use bitcoin::{PublicKey, ScriptBuf, XOnlyPublicKey};

use bitcoin_scriptexec::treepp::*;
use itertools::Itertools;
use key_manager::winternitz::WinternitzPublicKey;

use crate::errors::ScriptError;

#[derive(Clone, Debug)]
pub enum KeyType {
    EcdsaPublicKey,
    XOnlyPublicKey,
    WinternitzPublicKey,
}

#[derive(Clone, Debug)]
pub struct ScriptParam {
    name: String,
    verifying_key_index: u32,
    verifying_key_type: KeyType,
    param_position: u32,
}

impl ScriptParam {
    pub fn new(name: &str, verifying_key_index: u32, verifying_key_type: KeyType, param_position: u32) -> Self {
        Self {
            name: name.to_string(),
            verifying_key_index,
            verifying_key_type,
            param_position, 
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn get_verifying_key_index(&self) -> u32 {
        self.verifying_key_index
    }

    pub fn get_verifying_key_type(&self) -> KeyType {
        self.verifying_key_type.clone()
    }

    pub fn get_param_position(&self) -> u32 {
        self.param_position
    }
}

#[derive(Clone, Debug)]
pub struct ScriptWithParams {
    script: ScriptBuf,
    params: HashMap<String, ScriptParam>,
}

impl ScriptWithParams {
    pub fn new(script: ScriptBuf) -> Self {
        Self {
            script,
            params: HashMap::new(),
        }
    }

    pub fn get_script(&self) -> &ScriptBuf {
        &self.script
    }

    pub fn get_param(&self, name: &str) -> Option<ScriptParam> {
        self.params.get(name).cloned()
    }

    // Returns the parameters in ascending order using their param_position.
    pub fn get_params(&self) -> Vec<ScriptParam> {
        self.params.values().cloned().sorted_by(|a, b| Ord::cmp(&a.get_param_position(), &b.get_param_position())).collect()
    }

    pub fn add_param(&mut self, name: &str, verifying_key_index: u32, verifying_key_type: KeyType, param_position: u32) {
        let param = ScriptParam::new(name, verifying_key_index, verifying_key_type, param_position);
        self.params.insert(param.name().to_string(), param);
    }

}



pub fn speedup(speedup_key: &PublicKey) -> Result<ScriptBuf, ScriptError> {
    let pubkey_hash = speedup_key.wpubkey_hash()?;
    Ok(ScriptBuf::new_p2wpkh(&pubkey_hash))
}

pub fn timelock(blocks: u16, timelock_public_key: &XOnlyPublicKey) -> ScriptWithParams {
    let script = script!(
        // If blocks have passed since this transaction has been confirmed, the timelocked public key can spend the funds
        { blocks.to_le_bytes().to_vec() }
        OP_CSV
        OP_DROP
        { timelock_public_key.serialize().to_vec() }
        OP_CHECKSIG
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param("timelock_expired_signature", 0, KeyType::EcdsaPublicKey, 0);
    script_with_params
}

// TODO aggregated_key must be an aggregated key and not a single public key
pub fn timelock_renew(aggregated_key: &XOnlyPublicKey) -> ScriptWithParams {
    let script = script!(
        { aggregated_key.serialize().to_vec() }
        OP_CHECKSIG
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param("aggregated_signature", 0, KeyType::EcdsaPublicKey, 0);
    script_with_params
}

pub fn check_signature(public_key: &XOnlyPublicKey) -> ScriptWithParams {
    let script = script!(
        { public_key.serialize().to_vec() }
        OP_CHECKSIG
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param("signature", 0, KeyType::EcdsaPublicKey, 0);

    script_with_params
}

pub fn check_aggregated_signature(aggregated_key: &XOnlyPublicKey) -> ScriptWithParams {
    check_signature(aggregated_key)
}

pub fn check_winterniz_signature(value_name: &str, verifying_key: &WinternitzPublicKey, keep_message: bool) -> ScriptWithParams {
    let script = script!(
        { ots_checksig(verifying_key, keep_message) }
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param(value_name, 0, KeyType::WinternitzPublicKey, 0);
    script_with_params
}

pub fn linked_message_challenge(key_c: &XOnlyPublicKey, key_p: &XOnlyPublicKey, xc_key: &WinternitzPublicKey) -> ScriptWithParams {
    let script = script!(
        { two_out_of_two_multisig(key_c, key_p) }
        { ots_checksig(xc_key, false) }
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param("signature_1", 0, KeyType::XOnlyPublicKey, 0);
    script_with_params.add_param("signature_2", 1, KeyType::XOnlyPublicKey, 1);
    script_with_params.add_param("signature_winternitz", 0, KeyType::WinternitzPublicKey, 2);    

    script_with_params
}

pub fn linked_message_response(key_c: &XOnlyPublicKey, key_p: &XOnlyPublicKey, xc_key: &WinternitzPublicKey, xp_key: &WinternitzPublicKey, y_key: &WinternitzPublicKey) -> ScriptWithParams {
    let script = script!(
        { two_out_of_two_multisig(key_c, key_p) }
        { ots_checksig(xc_key, false) }
        { ots_checksig(xp_key, false) }
        { ots_checksig(y_key, false) }
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param("signature_1", 0, KeyType::XOnlyPublicKey, 0);
    script_with_params.add_param("signature_2", 0, KeyType::XOnlyPublicKey, 1);
    script_with_params.add_param("signature_x_a", 0, KeyType::WinternitzPublicKey, 2);    
    script_with_params.add_param("signature_x_b", 0, KeyType::WinternitzPublicKey, 3);  
    script_with_params.add_param("signature_y", 0, KeyType::WinternitzPublicKey, 4);  

    script_with_params
}

// Winternitz Signature verification. Note that the script inputs are malleable.
fn ots_checksig(public_key: &WinternitzPublicKey, keep_message: bool) -> ScriptBuf {
    let total_size = public_key.total_len() as u32;
    let message_size = public_key.message_size() as u32;
    let checksum_size = public_key.checksum_size() as u32;
    let base = public_key.get_base() as u32;
    let bits_per_digit = public_key.get_bits_per_digit();
    let public_key_hashes = public_key.to_hashes();

    let verify = script! {
        // Verify the hash chain for each digit
        for digit_index in 0..total_size {
            // Verify that the digit is in the range [0, d]
            { base }
            OP_MIN

            // Push two copies of the digit onto the altstack
            OP_DUP OP_TOALTSTACK OP_TOALTSTACK

            // Hash the input hash d times and put every result on the stack
            for _ in 0..base {
                OP_DUP OP_HASH160
            }

            // Compute the offset of the hash table entry for this digit 
            { base }
            OP_FROMALTSTACK
            OP_SUB

            // Verify the signature for this digit   
            OP_PICK
            { public_key_hashes[(total_size - 1) as usize - digit_index as usize].clone() }
            OP_EQUALVERIFY

            // Drop the hash table entries from the stack
            for _ in 0..(base + 1) / 2 {
                OP_2DROP
            }
        }

        // Verify the Checksum
        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK
        OP_DUP
        OP_NEGATE

        for _ in 1..message_size {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }

        { base * message_size }
        OP_ADD

        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK

        for _ in 0..checksum_size - 1 {
            for _ in 0..bits_per_digit {
                OP_DUP
                OP_ADD
            }

            OP_FROMALTSTACK
            OP_ADD
        }

        // 3. Ensure both checksums are equal
        OP_EQUAL

        if !keep_message {
            // Drop the message's digits from the stack keeping only the OP_EQUAL result 
            OP_TOALTSTACK
            if message_size == 1 {
                OP_DROP
            } else {
                if message_size % 2 == 0 {
                    for _ in 0..(message_size / 2) {
                        OP_2DROP
                    }
                } else {
                    for _ in 0..(message_size / 2) {
                        OP_2DROP
                    }
                    OP_DROP
                }
            }
            OP_FROMALTSTACK
        } else {
            // Drop the checksum OP_EQUAL result to keep in the stack only the message digits
            OP_DROP
        }
    };

    verify
}


pub fn two_out_of_two_multisig(public_key_1: &XOnlyPublicKey, public_key_2: &XOnlyPublicKey) -> ScriptBuf {
    let script = script!(
        OP_IF
            { public_key_1.serialize().to_vec() }
            OP_CHECKSIGVERIFY
            { public_key_2.serialize().to_vec() }
            OP_CHECKSIG
        OP_ELSE
            { public_key_2.serialize().to_vec() }
            OP_CHECKSIGVERIFY
            { public_key_1.serialize().to_vec() }
            OP_CHECKSIG
        OP_ENDIF
    );

    script
}