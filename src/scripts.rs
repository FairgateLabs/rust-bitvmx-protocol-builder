use std::{
    collections::HashMap,
    fmt::{Display, Formatter},
};

use bitcoin::{
    key::{Secp256k1, UntweakedPublicKey},
    secp256k1::All,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    PublicKey, ScriptBuf, XOnlyPublicKey,
};

use bitcoin_scriptexec::treepp::*;
use itertools::Itertools;
use key_manager::winternitz::{WinternitzPublicKey, WinternitzType};
use serde::{Deserialize, Serialize};

use crate::errors::ScriptError;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    EcdsaKey,
    XOnlyKey,
    WinternitzKey(WinternitzType),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
// Controls how the script is signed using the verifying key
pub enum SignMode {
    // No signature is required
    Skip,
    // The script is signed using the verifying key in ecdsa mode
    Single,
    // The script is signed using the verifying key in musig2 mode
    Aggregate,
}

impl Display for SignMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SignMode::Skip => write!(f, "SignMode::Skip"),
            SignMode::Single => write!(f, "SignMode::Single"),
            SignMode::Aggregate => write!(f, "SignMode::Aggregate"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolScript {
    script: ScriptBuf,
    keys: HashMap<String, ScriptKey>,
    verifying_key: Option<PublicKey>,
    sign_mode: SignMode,
}

impl ProtocolScript {
    pub fn new(script: ScriptBuf, verifying_key: &PublicKey, sign_mode: SignMode) -> Self {
        Self {
            script,
            keys: HashMap::new(),
            verifying_key: Some(*verifying_key),
            sign_mode,
        }
    }

    pub fn new_unspendable(script: ScriptBuf) -> Self {
        Self {
            script,
            keys: HashMap::new(),
            verifying_key: None,
            sign_mode: SignMode::Skip,
        }
    }

    pub fn add_key(
        &mut self,
        name: &str,
        derivation_index: u32,
        key_type: KeyType,
        key_position: u32,
    ) -> Result<(), ScriptError> {
        if name.trim().is_empty() {
            return Err(ScriptError::EmptyScriptName);
        }
        let key = ScriptKey::new(name, derivation_index, key_type, key_position);
        self.keys.insert(key.name().to_string(), key);

        Ok(())
    }

    pub fn set_assert_leaf_id(&mut self, leaf_id: u32) {
        let original_script = self.script.clone();
        self.script = script!(
            { leaf_id }
            OP_EQUALVERIFY
            { original_script }
        );
    }

    pub fn get_script(&self) -> &ScriptBuf {
        &self.script
    }

    pub fn get_key(&self, name: &str) -> Option<ScriptKey> {
        self.keys.get(name).cloned()
    }

    // Returns the keys in ascending order using their key_position.
    pub fn get_keys(&self) -> Vec<ScriptKey> {
        self.keys
            .values()
            .cloned()
            .sorted_by(|a, b| Ord::cmp(&a.key_position(), &b.key_position()))
            .collect()
    }

    pub fn get_verifying_key(&self) -> Option<PublicKey> {
        self.verifying_key
    }

    pub fn skip_signing(&self) -> bool {
        self.sign_mode == SignMode::Skip
    }

    pub fn normal_signing(&self) -> bool {
        self.sign_mode == SignMode::Single
    }

    pub fn aggregate_signing(&self) -> bool {
        self.sign_mode == SignMode::Aggregate
    }
}

pub fn op_return_script(data: Vec<u8>) -> Result<ProtocolScript, ScriptError> {
    let script = script!(OP_RETURN { data });

    let protocol_script = ProtocolScript::new_unspendable(script);
    Ok(protocol_script)
}

pub fn verify_winternitz_signatures<T: AsRef<str>>(
    verifying_key: &PublicKey,
    public_keys: &Vec<(T, &WinternitzPublicKey)>,
    sign_mode: SignMode,
) -> Result<ProtocolScript, ScriptError> {
    verify_winternitz_signatures_aux(verifying_key, public_keys, sign_mode, false, None)
}

pub fn verify_winternitz_signatures_aux<T: AsRef<str>>(
    verifying_key: &PublicKey,
    public_keys: &Vec<(T, &WinternitzPublicKey)>,
    sign_mode: SignMode,
    keep_message: bool,
    extra_check_script: Option<Vec<ScriptBuf>>,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(*verifying_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY
        for (_,key) in public_keys {
            { ots_checksig(key, keep_message)? }
        }
        if keep_message {
            for (_,key) in public_keys {
                for _ in 0..key.message_size()? {
                    OP_FROMALTSTACK
                }
            }
        }
        if let Some(extra_script) = extra_check_script {
            { extra_script }
        }
        OP_PUSHNUM_1
    );

    let mut protocol_script = ProtocolScript::new(script, verifying_key, sign_mode);
    for (i, (name, key)) in public_keys.iter().enumerate() {
        protocol_script.add_key(
            name.as_ref(),
            key.derivation_index()?,
            KeyType::WinternitzKey(key.key_type()),
            i as u32,
        )?;
    }

    Ok(protocol_script)
}

pub fn verify_winternitz_signature(
    verifying_key: &PublicKey,
    public_key: &WinternitzPublicKey,
    sign_mode: SignMode,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(*verifying_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY
        { ots_checksig(public_key, false)? }
        OP_PUSHNUM_1
    );

    let mut protocol_script = ProtocolScript::new(script, verifying_key, sign_mode);
    protocol_script.add_key(
        "value",
        public_key.derivation_index()?,
        KeyType::WinternitzKey(public_key.key_type()),
        0,
    )?;

    Ok(protocol_script)
}

pub fn timelock(blocks: u16, timelock_key: &PublicKey, sign_mode: SignMode) -> ProtocolScript {
    let script = script!(
        // If blocks have passed since this transaction has been confirmed, the timelocked public key can spend the funds
        { blocks as u32 }
        OP_CSV
        OP_DROP
        { XOnlyPublicKey::from(*timelock_key).serialize().to_vec() }
        OP_CHECKSIG
    );

    ProtocolScript::new(script, timelock_key, sign_mode)
}

pub fn op_return(data: Vec<u8>) -> ScriptBuf {
    script!(OP_RETURN { data })
}

// TODO aggregated_key must be an aggregated key and not a single public key
pub fn timelock_renew(aggregated_key: &PublicKey, sign_mode: SignMode) -> ProtocolScript {
    let script = script!(
        { XOnlyPublicKey::from(*aggregated_key).serialize().to_vec() }
        OP_CHECKSIG
    );

    ProtocolScript::new(script, aggregated_key, sign_mode)
}

pub fn check_signature(public_key: &PublicKey, sign_mode: SignMode) -> ProtocolScript {
    let script = script!(
        { XOnlyPublicKey::from(*public_key).serialize().to_vec() }
        OP_CHECKSIG
    );

    ProtocolScript::new(script, public_key, sign_mode)
}

pub fn check_aggregated_signature(
    aggregated_key: &PublicKey,
    sign_mode: SignMode,
) -> ProtocolScript {
    check_signature(aggregated_key, sign_mode)
}

pub fn kickoff(
    aggregated_key: &PublicKey,
    input_key: &WinternitzPublicKey,
    ending_state_key: &WinternitzPublicKey,
    ending_step_number_key: &WinternitzPublicKey,
    sign_mode: SignMode,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(*aggregated_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY
        { ots_checksig(input_key, false)? }
        { ots_checksig(ending_state_key, false)? }
        { ots_checksig(ending_step_number_key, false)? }
    );

    let mut protocol_script = ProtocolScript::new(script, aggregated_key, sign_mode);
    protocol_script.add_key(
        "input",
        input_key.derivation_index()?,
        KeyType::WinternitzKey(input_key.key_type()),
        0,
    )?;
    protocol_script.add_key(
        "ending_state",
        ending_state_key.derivation_index()?,
        KeyType::WinternitzKey(ending_state_key.key_type()),
        1,
    )?;
    protocol_script.add_key(
        "ending_step_number",
        ending_step_number_key.derivation_index()?,
        KeyType::WinternitzKey(ending_step_number_key.key_type()),
        2,
    )?;
    Ok(protocol_script)
}

pub fn initial_stages(
    stage: usize,
    aggregated_key: &PublicKey,
    interval_keys: &[WinternitzPublicKey],
    selection_key: &WinternitzPublicKey,
    sign_mode: SignMode,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(*aggregated_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY
        for key in interval_keys {
            { ots_checksig(key, false)? }
        }
        { ots_checksig(selection_key, false)? }
        OP_PUSHNUM_1
    );

    let mut protocol_script = ProtocolScript::new(script, aggregated_key, sign_mode);
    for (index, key) in interval_keys.iter().enumerate() {
        protocol_script.add_key(
            format!("stage_{}_{}", stage, index).as_str(),
            key.derivation_index()?,
            KeyType::WinternitzKey(key.key_type()),
            index as u32,
        )?;
    }

    protocol_script.add_key(
        format!("selection_{}", stage).as_str(),
        selection_key.derivation_index()?,
        KeyType::WinternitzKey(selection_key.key_type()),
        interval_keys.len() as u32,
    )?;
    Ok(protocol_script)
}

pub fn stage_from_3_and_upward(
    stage: usize,
    aggregated_key: &PublicKey,
    interval_keys: &[WinternitzPublicKey],
    key_previous_selection_bob: &WinternitzPublicKey,
    key_previous_selection_alice: &WinternitzPublicKey,
    sign_mode: SignMode,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(*aggregated_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY
        for key in interval_keys {
            { ots_checksig(key, false)? }
        }
        { ots_checksig(key_previous_selection_bob, false)? }
        { ots_checksig(key_previous_selection_alice, false)? }
        OP_PUSHNUM_1
    );

    let mut protocol_script = ProtocolScript::new(script, aggregated_key, sign_mode);
    for (index, key) in interval_keys.iter().enumerate() {
        protocol_script.add_key(
            format!("stage_{}_{}", stage, index).as_str(),
            key.derivation_index()?,
            KeyType::WinternitzKey(key.key_type()),
            index as u32,
        )?;
    }

    protocol_script.add_key(
        format!("selection_{}", stage).as_str(),
        key_previous_selection_bob.derivation_index()?,
        KeyType::WinternitzKey(key_previous_selection_bob.key_type()),
        interval_keys.len() as u32,
    )?;
    protocol_script.add_key(
        format!("selection_{}", stage).as_str(),
        key_previous_selection_alice.derivation_index()?,
        KeyType::WinternitzKey(key_previous_selection_alice.key_type()),
        interval_keys.len() as u32,
    )?;

    Ok(protocol_script)
}

pub fn linked_message_challenge(
    aggregated_key: &PublicKey,
    xc_key: &WinternitzPublicKey,
    sign_mode: SignMode,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(*aggregated_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY
        { ots_checksig(xc_key, false)? }
        OP_PUSHNUM_1
    );

    let mut protocol_script = ProtocolScript::new(script, aggregated_key, sign_mode);
    protocol_script.add_key(
        "xc",
        xc_key.derivation_index()?,
        KeyType::WinternitzKey(xc_key.key_type()),
        0,
    )?;

    Ok(protocol_script)
}

pub fn linked_message_response(
    aggregated_key: &PublicKey,
    xc_key: &WinternitzPublicKey,
    xp_key: &WinternitzPublicKey,
    yp_key: &WinternitzPublicKey,
    sign_mode: SignMode,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(*aggregated_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY
        { ots_checksig(xc_key, false)? }
        { ots_checksig(xp_key, false)? }
        { ots_checksig(yp_key, false)? }
        OP_PUSHNUM_1
    );

    let mut protocol_script = ProtocolScript::new(script, aggregated_key, sign_mode);
    protocol_script.add_key(
        "xc",
        xc_key.derivation_index()?,
        KeyType::WinternitzKey(xc_key.key_type()),
        0,
    )?;
    protocol_script.add_key(
        "xp",
        xp_key.derivation_index()?,
        KeyType::WinternitzKey(xp_key.key_type()),
        1,
    )?;
    protocol_script.add_key(
        "yp",
        yp_key.derivation_index()?,
        KeyType::WinternitzKey(yp_key.key_type()),
        2,
    )?;

    Ok(protocol_script)
}

// Winternitz Signature verification. Note that the script inputs are malleable.
pub fn ots_checksig(
    public_key: &WinternitzPublicKey,
    keep_message: bool,
) -> Result<ScriptBuf, ScriptError> {
    let total_size = public_key.total_len() as u32;
    let message_size = public_key.message_size()? as u32;
    let checksum_size = public_key.checksum_size()? as u32;
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
        } else {
            for _ in 0..message_size {
                OP_TOALTSTACK
            }
        }
    };

    Ok(verify)
}

pub fn reveal_secret(
    hashed_secret: Vec<u8>,
    pub_key: &PublicKey,
    sign_mode: SignMode,
) -> ProtocolScript {
    let script = script!(
        OP_SHA256
        { hashed_secret }
        OP_EQUALVERIFY
        { XOnlyPublicKey::from(*pub_key).serialize().to_vec() }
        OP_CHECKSIG
    );

    ProtocolScript::new(script, pub_key, sign_mode)
}

pub fn build_taproot_spend_info(
    secp: &Secp256k1<All>,
    internal_key: &UntweakedPublicKey,
    leaves: &[ProtocolScript],
) -> Result<TaprootSpendInfo, ScriptError> {
    let scripts_count = leaves.len();

    let mut tr_builder = TaprootBuilder::new();

    // For empty scripts finalize the tree
    if scripts_count == 0 {
        return tr_builder
            .finalize(secp, *internal_key)
            .map_err(|_| ScriptError::TapTreeFinalizeError);
    }

    // For a single script, add it at depth 0
    if scripts_count == 1 {
        tr_builder = tr_builder.add_leaf(0, leaves[0].get_script().clone())?;
        return tr_builder
            .finalize(secp, *internal_key)
            .map_err(|_| ScriptError::TapTreeFinalizeError);
    }

    // For multiple scripts, build a balanced tree
    //
    // Example tree structure for 7 scripts:
    //
    //           [Root]
    //          /      \
    //      [1-3]      [4-7]
    //     /     \     /    \
    //   [1-2]  [3]  [4-5] [6-7]
    //   /  \         /  \   /  \
    // [1] [2]     [4] [5] [6] [7]
    //
    // The algorithm calculates the minimum depth needed to hold all scripts
    // and then distributes the scripts between that depth and the next one
    // to maintain a balanced tree structure.

    // Calculate the minimum depth needed to hold all scripts
    let min_depth = (scripts_count as f32 - 1.0).log2().floor() as u8;
    // Calculate how many nodes go at the minimum depth vs minimum depth + 1
    let total_slots = 1 << (min_depth + 1); // 2^(min_depth + 1)
    let nodes_at_min_depth = total_slots - scripts_count;
    // Add leaves at minimum depth
    for i in 0..nodes_at_min_depth {
        tr_builder = tr_builder.add_leaf(min_depth, leaves[i].get_script().clone())?;
    }

    // Add remaining leaves at minimum depth + 1
    for i in nodes_at_min_depth..scripts_count {
        tr_builder = tr_builder.add_leaf(min_depth + 1, leaves[i].get_script().clone())?;
    }

    tr_builder
        .finalize(secp, *internal_key)
        .map_err(|_| ScriptError::TapTreeFinalizeError)
}

pub fn operator_hashed_slot_preimage(
    public_key: PublicKey,
    slot_preimage: Vec<u8>,
) -> ProtocolScript {
    let script = script!(
        { XOnlyPublicKey::from(public_key).serialize().to_vec() }
        OP_CHECKSIGVERIFY
        OP_SHA256
        { slot_preimage }
        OP_EQUAL
    );

    ProtocolScript::new(script, &public_key, SignMode::Single)
}

pub fn start_dispute_core(
    dispute_pubkey: PublicKey,
    pegout_id_pubkey: &WinternitzPublicKey,
    bit0_pubkey: &WinternitzPublicKey,
    bit1_pubkey: &WinternitzPublicKey,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(dispute_pubkey).serialize().to_vec() }
        OP_CHECKSIGVERIFY

        { ots_checksig(&pegout_id_pubkey, false)? }
        { ots_checksig(&bit1_pubkey, true)? }
        // TODO compare the message with BIT1 (1)
        OP_IF
            OP_PUSHNUM_1
        OP_ELSE
            { ots_checksig(&bit0_pubkey, true)? }
            // TODO compare the message with BIT0 0)
        OP_ENDIF
    );

    let mut protocol_script = ProtocolScript::new(script, &dispute_pubkey, SignMode::Single);
    protocol_script.add_key(
        "ot_pegout_id",
        pegout_id_pubkey.derivation_index()?,
        KeyType::WinternitzKey(pegout_id_pubkey.key_type()),
        0,
    )?;

    protocol_script.add_key(
        "ot_bit1",
        bit1_pubkey.derivation_index()?,
        KeyType::WinternitzKey(bit1_pubkey.key_type()),
        1,
    )?;

    protocol_script.add_key(
        "bit0_pubkey",
        pegout_id_pubkey.derivation_index()?,
        KeyType::WinternitzKey(bit0_pubkey.key_type()),
        2,
    )?;

    Ok(protocol_script)
}

pub fn verify_bit(
    take_pubkey: PublicKey,
    bit_pubkey: &WinternitzPublicKey,
    _bit_value: Vec<u8>,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(take_pubkey).serialize().to_vec() }
        OP_CHECKSIGVERIFY

        { ots_checksig(&bit_pubkey, true)? }
        // TODO compare the message with bit_value
    );

    let mut protocol_script = ProtocolScript::new(script, &take_pubkey, SignMode::Single);
    protocol_script.add_key(
        "ot_bit",
        bit_pubkey.derivation_index()?,
        KeyType::WinternitzKey(bit_pubkey.key_type()),
        0,
    )?;

    Ok(protocol_script)
}

pub fn verify_signature(
    public_key: &PublicKey,
    sign_mode: SignMode,
) -> Result<ProtocolScript, ScriptError> {
    let script = script!(
        { XOnlyPublicKey::from(*public_key).serialize().to_vec() }
        OP_CHECKSIG
    );

    let protocol_script = ProtocolScript::new(script, public_key, sign_mode);
    Ok(protocol_script)
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        hex::FromHex,
        opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_RETURN},
        PublicKey, XOnlyPublicKey,
    };
    use std::str::FromStr;

    use super::*;

    const AGGREGATED_SIGNATURE: &str = "aggregated_signature";
    const PUB_KEY: &str = "03c7805b5add3c9ae01d0998392295f09dbcf25d33677842e8ad0b29f51bbaeac2";

    fn get_script_buff() -> ScriptBuf {
        let aggregated_key = PublicKey::from_str(PUB_KEY);
        let script = script!(
            { aggregated_key.unwrap().to_bytes() }
            OP_CHECKSIG
        );

        script! {
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
    fn test_protocol_script() {
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let verifying_key =
            PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let mut script = ProtocolScript::new(get_script_buff(), &verifying_key, SignMode::Single);
        script
            .add_key(AGGREGATED_SIGNATURE, 1, KeyType::EcdsaKey, 0)
            .expect("Failed to add key");

        assert_eq!(
            script.get_key(AGGREGATED_SIGNATURE).unwrap().name,
            AGGREGATED_SIGNATURE
        );
        assert_eq!(
            script.get_key(AGGREGATED_SIGNATURE).unwrap().key_position(),
            0
        );
        assert_eq!(
            script
                .get_key(AGGREGATED_SIGNATURE)
                .unwrap()
                .derivation_index(),
            1
        );
        assert_eq!(
            script.get_key(AGGREGATED_SIGNATURE).unwrap().key_type(),
            KeyType::EcdsaKey
        );
    }

    #[test]
    fn test_script_with_multiple_keys() {
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let verifying_key =
            PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let mut script = ProtocolScript::new(get_script_buff(), &verifying_key, SignMode::Single);
        script
            .add_key(AGGREGATED_SIGNATURE, 0, KeyType::EcdsaKey, 0)
            .expect("Failed to add key");
        script
            .add_key(AGGREGATED_SIGNATURE, 2, KeyType::EcdsaKey, 2)
            .expect("Failed to add key");
        script
            .add_key(AGGREGATED_SIGNATURE, 1, KeyType::EcdsaKey, 1)
            .expect("Failed to add key");
        let keys = script.get_keys();

        assert!(keys
            .windows(2)
            .all(|w| w[0].key_position() <= w[1].key_position()));
    }

    #[test]
    fn test_invalid_key_position() {
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let verifying_key =
            PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let mut script = ProtocolScript::new(get_script_buff(), &verifying_key, SignMode::Single);
        script
            .add_key(AGGREGATED_SIGNATURE, 0, KeyType::EcdsaKey, 0)
            .unwrap();

        // Non-existent key
        assert!(script.get_key("non_existent_key").is_none());
    }

    #[test]
    fn test_script_key_type() {
        let ecdsa_key = ScriptKey::new("ecdsa_key", 1, KeyType::EcdsaKey, 0);
        let xonly_key = ScriptKey::new("xonly_key", 1, KeyType::XOnlyKey, 0);
        let winternitz_key = ScriptKey::new(
            "winternitz_key",
            1,
            KeyType::WinternitzKey(WinternitzType::HASH160),
            0,
        );

        assert_eq!(xonly_key.key_type(), KeyType::XOnlyKey);
        assert_eq!(ecdsa_key.key_type(), KeyType::EcdsaKey);
        assert_eq!(
            winternitz_key.key_type(),
            KeyType::WinternitzKey(WinternitzType::HASH160)
        );
        assert_ne!(winternitz_key.key_type(), ecdsa_key.key_type());
    }

    #[test]
    fn test_empty_protocol_script() {
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let verifying_key =
            PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let script = ProtocolScript::new(get_script_buff(), &verifying_key, SignMode::Single);
        assert!(script.get_keys().is_empty());
    }

    #[test]
    fn test_empty_script_name() {
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let verifying_key =
            PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let mut script = ProtocolScript::new(get_script_buff(), &verifying_key, SignMode::Single);
        assert!(script.add_key("", 1, KeyType::EcdsaKey, 0).is_err());
    }

    #[test]
    fn test_timelock_output_script() {
        // Arrange
        let blocks = 587;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        // Act
        let script_timelock = timelock(blocks, &public_key, SignMode::Single);

        // Assert
        let instructions = script_timelock
            .get_script()
            .instructions()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(instructions.len(), 5, "Script should have 5 instructions");
        assert_eq!(
            instructions[0].script_num(),
            Some(blocks as i64),
            "First instruction should be a number"
        );
        assert_eq!(
            instructions[1].opcode(),
            Some(OP_CSV),
            "Second instruction should be OP_CSV"
        );
        assert_eq!(
            instructions[2].opcode(),
            Some(OP_DROP),
            "Third instruction should be OP_DROP"
        );
        // First byte is the even byte, we skip it to get the x-only public key
        assert_eq!(
            instructions[3].push_bytes().unwrap().as_bytes(),
            &public_key.inner.serialize()[1..],
            "Fourth instruction should be the public key"
        );
        assert_eq!(
            instructions[4].opcode(),
            Some(OP_CHECKSIG),
            "Fifth instruction should be OP_CHECKSIG"
        );
        // Check the scriptPubKey hex is ok
        let script_timelock_bytes_hex = hex::encode(script_timelock.get_script().to_bytes());
        assert_eq!(
            script_timelock_bytes_hex,
            "024b02b27520c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fdac"
        );
    }

    #[test]
    fn test_op_return_output_script() {
        // Arrange
        let value: u64 = 587;
        let address = Vec::from_hex("7ac5496aee77c1ba1f0854206a26dda82a81d6d8").unwrap();
        let data = [&value.to_be_bytes(), address.as_slice()].concat();

        // Act
        let script_op_return = op_return(data.clone());

        // Assert
        let instructions = script_op_return
            .instructions()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(instructions.len(), 2, "Script should have 2 instructions");
        assert_eq!(
            instructions[0].opcode(),
            Some(OP_RETURN),
            "First instruction should be OP_RETURN"
        );

        assert_eq!(
            instructions[1].push_bytes().unwrap().as_bytes(),
            &data,
            "Second instruction should be the data"
        );
        // Check the scriptPubKey hex is ok
        let script_bytes_hex = hex::encode(script_op_return.to_bytes());
        assert_eq!(
            script_bytes_hex,
            "6a1c000000000000024b7ac5496aee77c1ba1f0854206a26dda82a81d6d8"
        );
    }

    #[test]
    fn test_build_taproot_spend_info_no_scripts() {
        // Arrange
        let secp = Secp256k1::new();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let internal_key = XOnlyPublicKey::from(public_key);

        // Act
        let taproot_spend_info = build_taproot_spend_info(&secp, &internal_key, &[])
            .expect("Failed to build taproot spend info");

        // Assert
        assert_eq!(taproot_spend_info.merkle_root(), None);
    }

    #[test]
    fn test_build_taproot_spend_info_one_leaf() {
        // Arrange
        let secp = Secp256k1::new();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let internal_key = XOnlyPublicKey::from(public_key);

        // Act
        let taproot_spend_info = build_taproot_spend_info(
            &secp,
            &internal_key,
            &[timelock(1, &public_key, SignMode::Single)],
        )
        .expect("Failed to build taproot spend info");

        // Assert
        assert_eq!(taproot_spend_info.internal_key(), internal_key);
    }

    #[test]
    fn test_build_taproot_spend_info_two_leaf() {
        // Arrange
        let secp = Secp256k1::new();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let internal_key = XOnlyPublicKey::from(public_key);

        // Act
        let taproot_spend_info = build_taproot_spend_info(
            &secp,
            &internal_key,
            &[
                timelock(1, &public_key, SignMode::Single),
                timelock(2, &public_key, SignMode::Single),
            ],
        )
        .expect("Failed to build taproot spend info");

        // Assert
        assert_eq!(taproot_spend_info.internal_key(), internal_key);
    }

    #[test]
    fn test_build_taproot_spend_info_three_leaf() {
        // Arrange
        let secp = Secp256k1::new();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let internal_key = XOnlyPublicKey::from(public_key);

        // Act
        let taproot_spend_info = build_taproot_spend_info(
            &secp,
            &internal_key,
            &[
                timelock(1, &public_key, SignMode::Single),
                timelock(2, &public_key, SignMode::Single),
                timelock(3, &public_key, SignMode::Single),
            ],
        )
        .expect("Failed to build taproot spend info");

        // Assert
        assert_eq!(taproot_spend_info.internal_key(), internal_key);
    }

    #[test]
    fn test_build_taproot_spend_info_four_leaf() {
        // Arrange
        let secp = Secp256k1::new();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let internal_key = XOnlyPublicKey::from(public_key);

        // Act
        let taproot_spend_info = build_taproot_spend_info(
            &secp,
            &internal_key,
            &[
                timelock(1, &public_key, SignMode::Single),
                timelock(2, &public_key, SignMode::Single),
                timelock(3, &public_key, SignMode::Single),
                timelock(4, &public_key, SignMode::Single),
            ],
        )
        .expect("Failed to build taproot spend info");

        // Assert
        assert_eq!(taproot_spend_info.internal_key(), internal_key);
    }

    #[test]
    fn test_build_taproot_spend_info_five_leaf() {
        // Arrange
        let secp = Secp256k1::new();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let internal_key = XOnlyPublicKey::from(public_key);

        // Act
        let taproot_spend_info = build_taproot_spend_info(
            &secp,
            &internal_key,
            &[
                timelock(1, &public_key, SignMode::Single),
                timelock(2, &public_key, SignMode::Single),
                timelock(3, &public_key, SignMode::Single),
                timelock(4, &public_key, SignMode::Single),
                timelock(5, &public_key, SignMode::Single),
            ],
        )
        .expect("Failed to build taproot spend info");

        // Assert
        assert_eq!(taproot_spend_info.internal_key(), internal_key);
    }

    #[test]
    fn test_build_taproot_spend_info_six_leaf() {
        // Arrange
        let secp = Secp256k1::new();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let internal_key = XOnlyPublicKey::from(public_key);

        // Act
        let taproot_spend_info = build_taproot_spend_info(
            &secp,
            &internal_key,
            &[
                timelock(1, &public_key, SignMode::Single),
                timelock(2, &public_key, SignMode::Single),
                timelock(3, &public_key, SignMode::Single),
                timelock(4, &public_key, SignMode::Single),
                timelock(5, &public_key, SignMode::Single),
                timelock(6, &public_key, SignMode::Single),
            ],
        )
        .expect("Failed to build taproot spend info");

        // Assert
        assert_eq!(taproot_spend_info.internal_key(), internal_key);
    }

    #[test]
    fn test_build_taproot_spend_info_seven_leaf() {
        // Arrange
        let secp = Secp256k1::new();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let internal_key = XOnlyPublicKey::from(public_key);

        //
        let taproot_spend_info = build_taproot_spend_info(
            &secp,
            &internal_key,
            &[
                timelock(1, &public_key, SignMode::Single),
                timelock(2, &public_key, SignMode::Single),
                timelock(3, &public_key, SignMode::Single),
                timelock(4, &public_key, SignMode::Single),
                timelock(5, &public_key, SignMode::Single),
                timelock(6, &public_key, SignMode::Single),
                timelock(7, &public_key, SignMode::Single),
            ],
        )
        .expect("Failed to build taproot spend info");

        // Assert
        assert_eq!(taproot_spend_info.internal_key(), internal_key);
    }

    #[test]
    fn test_build_taproot_spend_info_ten_leaf() {
        // Arrange
        let secp = Secp256k1::new();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let internal_key = XOnlyPublicKey::from(public_key);

        // Act
        let taproot_spend_info = build_taproot_spend_info(
            &secp,
            &internal_key,
            &[
                timelock(1, &public_key, SignMode::Single),
                timelock(2, &public_key, SignMode::Single),
                timelock(3, &public_key, SignMode::Single),
                timelock(4, &public_key, SignMode::Single),
                timelock(5, &public_key, SignMode::Single),
                timelock(6, &public_key, SignMode::Single),
                timelock(7, &public_key, SignMode::Single),
                timelock(8, &public_key, SignMode::Single),
                timelock(9, &public_key, SignMode::Single),
                timelock(10, &public_key, SignMode::Single),
            ],
        )
        .expect("Failed to build taproot spend info");

        // Assert
        assert_eq!(taproot_spend_info.internal_key(), internal_key);
    }
}
