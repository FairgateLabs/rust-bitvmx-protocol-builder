use std::collections::HashMap;

use bitcoin::{PublicKey, ScriptBuf};

use bitcoin_scriptexec::treepp::*;
use itertools::Itertools;
use key_manager::winternitz::WinternitzPublicKey;

use crate::errors::ScriptError;

#[derive(Clone, Debug)]
pub enum KeyType {
    EcdsaPublicKey,
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

    /// Returns the parameters in ascending order using their param_position.
    pub fn get_params(&self) -> Vec<ScriptParam> {
        self.params.values().cloned().sorted_by(|a, b| Ord::cmp(&a.get_param_position(), &b.get_param_position())).collect()
    }

    pub fn add_param(&mut self, name: &str, verifying_key_index: u32, verifying_key_type: KeyType, param_position: u32) {
        let param = ScriptParam::new(name, verifying_key_index, verifying_key_type, param_position);
        self.params.insert(param.name().to_string(), param);
    }

}

pub fn speedup(public_key: &PublicKey) -> Result<ScriptBuf, ScriptError> {
    let pubkey_hash = public_key.wpubkey_hash()?;
    Ok(ScriptBuf::new_p2wpkh(&pubkey_hash))
}

pub fn timelock(blocks: u16, timelocked_public_key: &PublicKey) -> ScriptWithParams {
    let script = script!(
        // If blocks have passed since this transaction has been confirmed, the timelocked public key can spend the funds
        { blocks.to_le_bytes().to_vec() }
        OP_CSV
        OP_IF
        OP_DROP
        { timelocked_public_key.to_bytes() }
        OP_CHECKSIG
        OP_ENDIF
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param("timelock_expired_signature", 0, KeyType::EcdsaPublicKey, 0);
    script_with_params
}

pub fn collaborative_spend(aggregated_key: &PublicKey) -> ScriptWithParams {
    let script = script!(
        { aggregated_key.to_bytes() }
        OP_CHECKSIG
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param("aggregated_signature", 0, KeyType::EcdsaPublicKey, 0);
    script_with_params
}

pub fn signature(public_key: &PublicKey) -> ScriptWithParams {
    let script = script!(
        { public_key.to_bytes() }
        OP_CHECKSIG
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param("signature", 0, KeyType::EcdsaPublicKey, 0);

    script_with_params
}

pub fn aggregated_signature(aggregated_key: &PublicKey) -> ScriptWithParams {
    signature(aggregated_key)
}

pub fn kickoff(f_key: &WinternitzPublicKey, input_key: &WinternitzPublicKey) -> ScriptWithParams {        
    let script = script!(
        {ots_checksig_verify(f_key, false)}
        {ots_checksig_verify(input_key, false)}
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param("f", 0, KeyType::WinternitzPublicKey, 0);
    script_with_params.add_param("input", 1, KeyType::WinternitzPublicKey, 1);

    script_with_params
}

pub fn verify_single_value(value_name: &str, verifying_key: &WinternitzPublicKey) -> ScriptWithParams {
    let script = script!(
        {ots_checksig_verify(verifying_key, false)}
    );

    let mut script_with_params = ScriptWithParams::new(script);
    script_with_params.add_param(value_name, 0, KeyType::WinternitzPublicKey, 0);
    script_with_params
}

// Winternitz Signature verification. Note that the script inputs are malleable.
// Optimized by @SergioDemianLerner, @tomkosm
fn ots_checksig_verify(public_key: &WinternitzPublicKey, keep_message: bool) -> ScriptBuf {
    let message_size = public_key.message_size() as u32;
    let bits_per_digit = 4; 
    let base: u32 = (1 << bits_per_digit) - 1;
    let log_digits_per_message:f32 = ((base * message_size) as f32).log((base + 1) as f32).ceil() + 1.0;
    let checksum_size: usize = usize::try_from(log_digits_per_message as u32).unwrap();
    let total_size = message_size + checksum_size as u32;

    script! {
        // Verify the hash chain for each digit
        // Repeat this for every of the n many digits
        for digit_index in 0..total_size {
            // Verify that the digit is in the range [0, d]
            // See https://github.com/BitVM/BitVM/issues/35
            { base }
            OP_MIN

            // Push two copies of the digit onto the altstack
            OP_DUP
            OP_TOALTSTACK
            OP_TOALTSTACK

            // Hash the input hash d times and put every result on the stack
            for _ in 0..base {
                OP_DUP OP_HASH160
            }

            // Verify the signature for this digit
            OP_FROMALTSTACK
            OP_PICK
            { public_key.to_hashes()[digit_index as usize].clone() }
            OP_EQUALVERIFY

            // Drop the d+1 stack items
            for _ in 0..(base + 1) / 2 {
                OP_2DROP
            }
        }

        // Verify the Checksum
        // 1. Compute the checksum of the message's digits
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..message_size {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { base * message_size }
        OP_ADD

        // 2. Sum up the signed checksum's digits
        OP_FROMALTSTACK
        for _ in 0..checksum_size - 1 {
            for _ in 0..bits_per_digit {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }

        // 3. Ensure both checksums are equal
        OP_EQUALVERIFY

        if keep_message {
            // Convert the message's digits to bytes
            for i in 0..message_size / 2 {
                OP_SWAP
                for _ in 0..bits_per_digit {
                    OP_DUP OP_ADD
                }
                OP_ADD
                // Push all bytes to the altstack, except for the last byte containing the OP_EQUALVERIFY result
                if i != (message_size / 2) - 1 {
                    OP_TOALTSTACK
                }
            }
            // Read the bytes from the altstack and push them to the stack
            for _ in 0..message_size / 2 - 1{
                OP_FROMALTSTACK
            }
        } else {
            // Drop the message's digits from the stack keeping only the last OP_EQUALVERIFY result 
            for i in 0..(message_size) / 2 {
                OP_SWAP
                if i != (message_size / 2) - 1 {
                    OP_2DROP
                } else {
                    OP_DROP
                }
            }
        }   
    }
}
