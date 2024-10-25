use std::collections::HashMap;

use bitcoin::{PublicKey, ScriptBuf, XOnlyPublicKey};

use bitcoin_scriptexec::treepp::*;
use itertools::Itertools;
use key_manager::winternitz::{WinternitzPublicKey, WinternitzType};

#[derive(Clone, Debug, PartialEq)]
pub enum KeyType {
    EcdsaKey,
    XOnlyKey,
    WinternitzKey(WinternitzType),
}

#[derive(Clone, Debug)]
pub struct ScriptKey {
    name: String,
    key_type: KeyType,
    key_position: u32,
    derivation_index: u32,
}

impl ScriptKey {
    pub fn new(name: &str, derivation_index: u32, key_type: KeyType, key_position: u32) -> Self {
        Self {
            name: name.to_string(),
            key_type,
            key_position, 
            derivation_index,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn derivation_index(&self) -> u32 {
        self.derivation_index
    }

    pub fn key_type(&self) -> KeyType {
        self.key_type.clone()
    }

    pub fn key_position(&self) -> u32 {
        self.key_position
    }
}

#[derive(Clone, Debug)]
pub struct ProtocolScript {
    script: ScriptBuf,
    keys: HashMap<String, ScriptKey>,
    verifying_key: PublicKey,
}

impl ProtocolScript {
    pub fn new(script: ScriptBuf, verifying_key: &PublicKey) -> Self {
        Self {
            script,
            keys: HashMap::new(),
            verifying_key: *verifying_key,
        }
    }

    pub fn add_key(&mut self, name: &str, derivation_index: u32, key_type: KeyType, key_position: u32) {
        let key = ScriptKey::new(name, derivation_index, key_type, key_position);
        self.keys.insert(key.name().to_string(), key);
    }

    pub fn get_script(&self) -> &ScriptBuf {
        &self.script
    }

    pub fn get_key(&self, name: &str) -> Option<ScriptKey> {
        self.keys.get(name).cloned()
    }

    // Returns the keys in ascending order using their key_position.
    pub fn get_keys(&self) -> Vec<ScriptKey> {
        self.keys.values().cloned().sorted_by(|a, b| Ord::cmp(&a.key_position(), &b.key_position())).collect()
    }

    pub fn get_verifying_key(&self) -> PublicKey {
        self.verifying_key
    }
}

pub fn timelock(blocks: u16, timelock_key: &PublicKey) -> ProtocolScript {
    let script = script!(
        // If blocks have passed since this transaction has been confirmed, the timelocked public key can spend the funds
        { blocks as u32 }
        OP_CSV
        OP_DROP
        { XOnlyPublicKey::from(*timelock_key).serialize().to_vec() }
        OP_CHECKSIG
    );

    ProtocolScript::new(script, timelock_key)
}

// TODO aggregated_key must be an aggregated key and not a single public key
pub fn timelock_renew(aggregated_key: &PublicKey) -> ProtocolScript {
    let script = script!(
        { XOnlyPublicKey::from(*aggregated_key).serialize().to_vec() }
        OP_CHECKSIG
    );

    ProtocolScript::new(script, aggregated_key)
}

pub fn check_signature(public_key: &PublicKey) -> ProtocolScript {
    let script = script!(
        { XOnlyPublicKey::from(*public_key).serialize().to_vec() }
        OP_CHECKSIG
    );

    ProtocolScript::new(script, public_key)
}

pub fn check_aggregated_signature(aggregated_key: &PublicKey) -> ProtocolScript {
    check_signature(aggregated_key)
}

pub fn linked_message_challenge(aggregated_key: &PublicKey, xc_key: &WinternitzPublicKey) -> ProtocolScript {
    let script = script!(
        { XOnlyPublicKey::from(*aggregated_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY
        { ots_checksig(xc_key, false) }
        OP_PUSHNUM_1
    );

    let mut script_with_keys = ProtocolScript::new(script, aggregated_key);
    script_with_keys.add_key("xc", xc_key.derivation_index(), KeyType::WinternitzKey(xc_key.key_type()), 0);     

    script_with_keys
}

pub fn linked_message_response(aggregated_key: &PublicKey, xc_key: &WinternitzPublicKey, xp_key: &WinternitzPublicKey, yp_key: &WinternitzPublicKey) -> ProtocolScript {
    let script = script!(
        { XOnlyPublicKey::from(*aggregated_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY
        { ots_checksig(xc_key, false) }
        { ots_checksig(xp_key, false) }
        { ots_checksig(yp_key, false) }
        OP_PUSHNUM_1
    );

    let mut script_with_keys = ProtocolScript::new(script, aggregated_key);
    script_with_keys.add_key("xc", xc_key.derivation_index(), KeyType::WinternitzKey(xc_key.key_type()), 0);    
    script_with_keys.add_key("xp", xp_key.derivation_index(),KeyType::WinternitzKey(xp_key.key_type()), 1);  
    script_with_keys.add_key("yp", yp_key.derivation_index(), KeyType::WinternitzKey(yp_key.key_type()), 2);  

    script_with_keys
}

// Winternitz Signature verification. Note that the script inputs are malleable.
pub fn ots_checksig(public_key: &WinternitzPublicKey, keep_message: bool) -> ScriptBuf {
    let total_size = public_key.total_len() as u32;
    let message_size = public_key.message_size() as u32;
    let checksum_size = public_key.checksum_size() as u32;
    let base = public_key.base() as u32;
    let bits_per_digit = public_key.bits_per_digit();
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
        OP_EQUALVERIFY

        if !keep_message {
            // Drop the message's digits from the stack
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
        }
    };

    verify
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use bitcoin::PublicKey;
    use super::*;

    const AGGREGATED_SIGNATURE: &str = "aggregated_signature";
    const PUB_KEY: &str = "03c7805b5add3c9ae01d0998392295f09dbcf25d33677842e8ad0b29f51bbaeac2";

    fn get_script_buff() -> ScriptBuf {
        
        let aggregated_key = PublicKey::from_str(PUB_KEY);
        let script = script!(
            { aggregated_key.unwrap().to_bytes() }
            OP_CHECKSIG
        );
    
        script!{
            OP_IF
            OP_TRUE
            OP_ELSE
            {script}
            OP_ENDIF
        }
    }

    #[test]
    fn test_get_key_index() {
        let test_script: ScriptKey = ScriptKey::new("test_script", 10, KeyType::EcdsaKey, 20);
        
        assert_eq!(test_script.derivation_index(), 10);
        assert_eq!(test_script.key_position(), 20);
        assert_eq!(test_script.key_type(), KeyType::EcdsaKey);
    }

    #[test]
    fn test_script_with_keys() {
        let pubkey_bytes = hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd").expect("Decoding failed");
        let verifying_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let mut script = ProtocolScript::new(get_script_buff(), &verifying_key);
        script.add_key(AGGREGATED_SIGNATURE, 1, KeyType::EcdsaKey, 0);
        
        assert_eq!(script.get_key(AGGREGATED_SIGNATURE).unwrap().name, AGGREGATED_SIGNATURE);
        assert_eq!(script.get_key(AGGREGATED_SIGNATURE).unwrap().key_position(), 0);
        assert_eq!(script.get_key(AGGREGATED_SIGNATURE).unwrap().derivation_index(), 1);
        assert_eq!(script.get_key(AGGREGATED_SIGNATURE).unwrap().key_type(), KeyType::EcdsaKey);        
    }

    #[test]
    fn test_script_with_multiple_keys() {
        let pubkey_bytes = hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd").expect("Decoding failed");
        let verifying_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let mut script = ProtocolScript::new(get_script_buff(), &verifying_key);
        script.add_key(AGGREGATED_SIGNATURE, 0, KeyType::EcdsaKey, 0);
        script.add_key(AGGREGATED_SIGNATURE, 2, KeyType::EcdsaKey, 2);
        script.add_key(AGGREGATED_SIGNATURE, 1, KeyType::EcdsaKey, 1);
        let keys = script.get_keys();

        assert!(keys.windows(2).all(|w| w[0].key_position() <= w[1].key_position()))        
    }
}