//! Structural export of a built protocol into bitvmx-protocol-studio YAML
//! (`packages/codegen/src/yaml/schema.ts`). Scripts are emitted as synthesized
//! placeholder defs; see
//! docs/superpowers/specs/2026-07-31-studio-yaml-export-design.md
//! (in the rust-bitvmx-client repo).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Environment variable used by [`StudioExportSettings::default`] to select
/// the directory where protocol YAML files are written.
pub const PROTOCOL_BUILDER_EXPORT_DIR: &str = "PROTOCOL_BUILDER_EXPORT_DIR";

/// Filesystem settings for Studio YAML exports.
#[derive(Debug, Clone)]
pub struct StudioExportSettings {
    /// When set, exports are also written to
    /// `<output_dir>/<protocol-name>.yaml`.
    ///
    /// Keeping this optional lets callers use `export_studio_yaml` purely as a
    /// serializer. Applications can set it directly from their configuration,
    /// or use [`PROTOCOL_BUILDER_EXPORT_DIR`] with the default settings. When
    /// neither is configured, no file is written.
    pub output_dir: Option<PathBuf>,
}

impl StudioExportSettings {
    pub fn with_output_dir(mut self, output_dir: impl Into<PathBuf>) -> Self {
        self.output_dir = Some(output_dir.into());
        self
    }

    pub(crate) fn output_path(&self, protocol_name: &str) -> Option<PathBuf> {
        self.output_dir
            .as_deref()
            .map(|directory| studio_yaml_path(directory, protocol_name))
    }
}

pub(crate) fn studio_yaml_path(directory: &Path, protocol_name: &str) -> PathBuf {
    directory.join(format!("{protocol_name}.yaml"))
}

impl Default for StudioExportSettings {
    fn default() -> Self {
        Self {
            output_dir: std::env::var_os(PROTOCOL_BUILDER_EXPORT_DIR).map(PathBuf::from),
        }
    }
}

use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioDoc {
    pub format_version: u8,
    pub name: String,
    pub keys: Vec<StudioKey>,
    pub scripts: Vec<StudioScript>,
    pub transactions: Vec<StudioTransaction>,
    pub connections: Vec<StudioConnection>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum StudioKey {
    #[serde(rename = "ecdsa", rename_all = "camelCase")]
    Ecdsa { name: String, derivation_index: u32 },
    #[serde(rename = "xonly", rename_all = "camelCase")]
    Xonly { name: String, derivation_index: u32 },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioScript {
    pub name: String,
    pub default_sign_mode: StudioSignMode,
    pub source: String,
    pub params: Vec<StudioScriptParam>,
    pub stack_items: Vec<StudioStackItem>,
    pub stack_items_overridden: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioScriptParam {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) enum StudioSignMode {
    Skip,
    Single,
    Aggregate,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum StudioStackItem {
    #[serde(rename = "schnorrSig", rename_all = "camelCase")]
    SchnorrSig { non_default_sighash: bool },
    #[serde(rename = "ecdsaSig")]
    EcdsaSig,
    #[serde(rename = "winternitzSig")]
    WinternitzSig { size: usize },
    #[serde(rename = "lamportSig")]
    LamportSig { size: usize },
    #[serde(rename = "raw")]
    Raw { size: usize },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioScriptUse {
    pub script_ref: String,
    pub sign_mode: StudioSignMode,
    pub bindings: BTreeMap<String, StudioBinding>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum StudioBinding {
    #[serde(rename = "key", rename_all = "camelCase")]
    Key { key_ref: String },
    #[serde(rename = "hex")]
    Hex { value: String },
    #[serde(rename = "number")]
    Number { value: i64 },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum StudioAmount {
    Sats(u64),
    Symbol(String), // "AUTO" | "RECOVER"
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum StudioOutput {
    #[serde(rename = "taproot", rename_all = "camelCase")]
    Taproot {
        amount: StudioAmount,
        internal_key: String,
        leaves: Vec<StudioScriptUse>,
    },
    #[serde(rename = "p2wpkh", rename_all = "camelCase")]
    P2wpkh { amount: StudioAmount, key: String },
    #[serde(rename = "p2wsh", rename_all = "camelCase")]
    P2wsh {
        amount: StudioAmount,
        script: StudioScriptUse,
    },
    #[serde(rename = "opReturn", rename_all = "camelCase")]
    OpReturn { data_hex: String },
    #[serde(rename = "externalUnknown")]
    ExternalUnknown,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioTransaction {
    pub name: String,
    pub external: bool,
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_txid: Option<String>,
    pub outputs: Vec<StudioOutput>,
    pub inputs: Vec<StudioInput>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioInput {
    pub sighash_type: StudioSighashType,
    pub spend_mode: StudioSpendMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioSighashType {
    pub class: StudioSighashClass,
    pub flag: StudioSighashFlag,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum StudioSighashClass {
    Taproot,
    Ecdsa,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum StudioSighashFlag {
    Default,
    All,
    None,
    Single,
    AllPlusAnyoneCanPay,
    NonePlusAnyoneCanPay,
    SinglePlusAnyoneCanPay,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub(crate) enum StudioSpendMode {
    #[serde(rename = "All", rename_all = "camelCase")]
    All { key_path_sign: StudioSignMode },
    #[serde(rename = "KeyOnly", rename_all = "camelCase")]
    KeyOnly { key_path_sign: StudioSignMode },
    #[serde(rename = "ScriptsOnly")]
    ScriptsOnly,
    #[serde(rename = "Scripts")]
    Scripts { leaves: Vec<usize> },
    #[serde(rename = "Script")]
    Script { leaf: usize },
    #[serde(rename = "Segwit")]
    Segwit,
    #[serde(rename = "None")]
    None,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioConnection {
    pub name: String,
    pub from: StudioEndpointFrom,
    pub to: StudioEndpointTo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timelock_blocks: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioEndpointFrom {
    pub tx: String,
    pub output_index: u32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioEndpointTo {
    pub tx: String,
    pub input_index: u32,
}

use std::collections::{HashMap, HashSet};

use bitcoin::hex::DisplayHex;
use bitcoin::PublicKey;

use crate::scripts::{ProtocolScript, SignMode, StackItem};
use crate::types::output::AmountType;

pub(crate) fn make_connection_names_unique(connections: &mut [StudioConnection]) {
    let reserved_names: HashSet<String> = connections
        .iter()
        .map(|connection| connection.name.clone())
        .collect();
    let mut occurrences = HashMap::<String, usize>::new();
    let mut generated_names = HashSet::<String>::new();

    for connection in connections {
        let base_name = connection.name.clone();
        let occurrence = occurrences.entry(base_name.clone()).or_insert(0);
        *occurrence += 1;

        if *occurrence == 1 {
            continue;
        }

        let mut suffix = *occurrence;
        loop {
            let candidate = format!("{base_name}_{suffix}");
            if !reserved_names.contains(&candidate) && generated_names.insert(candidate.clone()) {
                connection.name = candidate;
                break;
            }
            suffix += 1;
        }
    }
}

impl From<SignMode> for StudioSignMode {
    fn from(m: SignMode) -> Self {
        match m {
            SignMode::Skip => StudioSignMode::Skip,
            SignMode::Single => StudioSignMode::Single,
            SignMode::Aggregate => StudioSignMode::Aggregate,
        }
    }
}

pub(crate) fn map_amount(a: &AmountType) -> StudioAmount {
    match a {
        AmountType::Value(v) => StudioAmount::Sats(v.to_sat()),
        AmountType::Auto => StudioAmount::Symbol("AUTO".to_string()),
        AmountType::Recover => StudioAmount::Symbol("RECOVER".to_string()),
        // Return/None carry no explicit sats. Amount-bearing placeholders that
        // reach here (e.g. a non-op_return SegwitUnspendable mapped to p2wsh)
        // serialize amount 0.
        AmountType::Return | AmountType::None => StudioAmount::Sats(0),
    }
}

pub(crate) fn map_stack_item(item: &StackItem) -> StudioStackItem {
    match item {
        StackItem::SchnorrSig {
            non_default_sighash,
        } => StudioStackItem::SchnorrSig {
            non_default_sighash: *non_default_sighash,
        },
        StackItem::EcdsaSig { .. } => StudioStackItem::EcdsaSig,
        StackItem::WinternitzSig { size } => StudioStackItem::WinternitzSig { size: *size },
        StackItem::LamportSig { size } => StudioStackItem::LamportSig { size: *size },
        StackItem::Raw { size } => StudioStackItem::Raw { size: *size },
    }
}

/// Accumulates deduped key/script registries while mapping the graph.
pub(crate) struct DocBuilder {
    pub keys: Vec<StudioKey>,
    pub scripts: Vec<StudioScript>,
    key_names: HashMap<String, String>, // "x:<hex>" | "e:<hex>" -> key name
    script_names: HashMap<String, String>, // script hex -> script name
}

impl DocBuilder {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            scripts: Vec::new(),
            key_names: HashMap::new(),
            script_names: HashMap::new(),
        }
    }

    pub fn intern_xonly_key(&mut self, pk: &PublicKey) -> String {
        let hex = pk.inner.x_only_public_key().0.to_string();
        let map_key = format!("x:{hex}");
        if let Some(name) = self.key_names.get(&map_key) {
            return name.clone();
        }
        let name = format!("key_{}", self.keys.len() + 1);
        self.keys.push(StudioKey::Xonly {
            name: name.clone(),
            derivation_index: 0,
        });
        self.key_names.insert(map_key, name.clone());
        name
    }

    pub fn intern_ecdsa_key(&mut self, pk: &PublicKey) -> String {
        let hex = pk.to_string();
        let map_key = format!("e:{hex}");
        if let Some(name) = self.key_names.get(&map_key) {
            return name.clone();
        }
        let name = format!("key_{}", self.keys.len() + 1);
        self.keys.push(StudioKey::Ecdsa {
            name: name.clone(),
            derivation_index: 0,
        });
        self.key_names.insert(map_key, name.clone());
        name
    }

    fn intern_script_bytes(
        &mut self,
        script: &bitcoin::ScriptBuf,
        sign_mode: StudioSignMode,
        stack_items: Vec<StudioStackItem>,
    ) -> String {
        let hex = script.to_hex_string();
        if let Some(name) = self.script_names.get(&hex) {
            return name.clone();
        }
        let name = format!("script_{}", self.scripts.len() + 1);
        self.scripts.push(StudioScript {
            name: name.clone(),
            default_sign_mode: sign_mode,
            source: format!("# opaque script 0x{hex}"),
            params: Vec::new(),
            stack_items,
            stack_items_overridden: true,
        });
        self.script_names.insert(hex, name.clone());
        name
    }

    pub fn intern_script(&mut self, ps: &ProtocolScript) -> StudioScriptUse {
        let sign_mode: StudioSignMode = ps.sign_mode().into();
        let items = ps.stack_items().iter().map(map_stack_item).collect();
        let name = self.intern_script_bytes(ps.get_script(), sign_mode, items);
        StudioScriptUse {
            script_ref: name,
            sign_mode,
            bindings: BTreeMap::new(),
        }
    }

    pub fn intern_raw_script(
        &mut self,
        script: &bitcoin::ScriptBuf,
        sign_mode: StudioSignMode,
    ) -> StudioScriptUse {
        let name = self.intern_script_bytes(script, sign_mode, Vec::new());
        StudioScriptUse {
            script_ref: name,
            sign_mode,
            bindings: BTreeMap::new(),
        }
    }
}

use crate::types::output::OutputType;

impl DocBuilder {
    pub fn map_output(&mut self, out: &OutputType) -> StudioOutput {
        match out {
            OutputType::Taproot {
                value,
                internal_key,
                leaves,
                ..
            } => StudioOutput::Taproot {
                amount: map_amount(value),
                internal_key: self.intern_xonly_key(internal_key),
                leaves: leaves.iter().map(|l| self.intern_script(l)).collect(),
            },
            OutputType::SegwitPublicKey {
                value, public_key, ..
            } => StudioOutput::P2wpkh {
                amount: map_amount(value),
                key: self.intern_ecdsa_key(public_key),
            },
            OutputType::SegwitScript { value, script, .. } => StudioOutput::P2wsh {
                amount: map_amount(value),
                script: self.intern_script(script),
            },
            OutputType::SegwitUnspendable {
                value,
                script_pubkey,
            } => {
                if script_pubkey.is_op_return() {
                    let mut data = Vec::new();
                    for ins in script_pubkey.instructions().flatten() {
                        if let bitcoin::script::Instruction::PushBytes(b) = ins {
                            data.extend_from_slice(b.as_bytes());
                        }
                    }
                    StudioOutput::OpReturn {
                        data_hex: data.to_lower_hex_string(),
                    }
                } else {
                    // Non-op_return unspendable: best-effort placeholder p2wsh.
                    StudioOutput::P2wsh {
                        amount: map_amount(value),
                        script: self.intern_raw_script(script_pubkey, StudioSignMode::Skip),
                    }
                }
            }
            OutputType::ExternalUnknown { .. } => StudioOutput::ExternalUnknown,
        }
    }
}

pub(crate) fn to_yaml(doc: &StudioDoc) -> Result<String, serde_yaml::Error> {
    serde_yaml::to_string(doc)
}

pub(crate) fn assemble_doc(
    builder: DocBuilder,
    name: &str,
    transactions: Vec<StudioTransaction>,
    connections: Vec<StudioConnection>,
) -> StudioDoc {
    StudioDoc {
        format_version: 1,
        name: name.to_string(),
        keys: builder.keys,
        scripts: builder.scripts,
        transactions,
        connections,
    }
}

use bitcoin::{EcdsaSighashType, Sequence, TapSighashType};

use crate::types::input::{InputType, SighashType, SpendMode};

fn map_tap_flag(t: TapSighashType) -> StudioSighashFlag {
    match t {
        TapSighashType::Default => StudioSighashFlag::Default,
        TapSighashType::All => StudioSighashFlag::All,
        TapSighashType::None => StudioSighashFlag::None,
        TapSighashType::Single => StudioSighashFlag::Single,
        TapSighashType::AllPlusAnyoneCanPay => StudioSighashFlag::AllPlusAnyoneCanPay,
        TapSighashType::NonePlusAnyoneCanPay => StudioSighashFlag::NonePlusAnyoneCanPay,
        TapSighashType::SinglePlusAnyoneCanPay => StudioSighashFlag::SinglePlusAnyoneCanPay,
    }
}

fn map_ecdsa_flag(t: EcdsaSighashType) -> StudioSighashFlag {
    match t {
        EcdsaSighashType::All => StudioSighashFlag::All,
        EcdsaSighashType::None => StudioSighashFlag::None,
        EcdsaSighashType::Single => StudioSighashFlag::Single,
        EcdsaSighashType::AllPlusAnyoneCanPay => StudioSighashFlag::AllPlusAnyoneCanPay,
        EcdsaSighashType::NonePlusAnyoneCanPay => StudioSighashFlag::NonePlusAnyoneCanPay,
        EcdsaSighashType::SinglePlusAnyoneCanPay => StudioSighashFlag::SinglePlusAnyoneCanPay,
    }
}

fn map_spend_mode(m: &SpendMode) -> StudioSpendMode {
    match m {
        SpendMode::All { key_path_sign } => StudioSpendMode::All {
            key_path_sign: (*key_path_sign).into(),
        },
        SpendMode::KeyOnly { key_path_sign } => StudioSpendMode::KeyOnly {
            key_path_sign: (*key_path_sign).into(),
        },
        SpendMode::ScriptsOnly => StudioSpendMode::ScriptsOnly,
        SpendMode::Scripts { leaves } => StudioSpendMode::Scripts {
            leaves: leaves.clone(),
        },
        SpendMode::Script { leaf } => StudioSpendMode::Script { leaf: *leaf },
        SpendMode::Segwit => StudioSpendMode::Segwit,
        SpendMode::None => StudioSpendMode::None,
    }
}

pub(crate) fn map_input(input: &InputType, sequence: Sequence) -> StudioInput {
    let sighash_type = match input.sighash_type() {
        SighashType::Taproot(t) => StudioSighashType {
            class: StudioSighashClass::Taproot,
            flag: map_tap_flag(*t),
        },
        SighashType::Ecdsa(e) => StudioSighashType {
            class: StudioSighashClass::Ecdsa,
            flag: map_ecdsa_flag(*e),
        },
    };
    let sequence = if sequence == Sequence::MAX {
        None
    } else {
        Some(sequence.to_consensus_u32())
    };
    StudioInput {
        sighash_type,
        spend_mode: map_spend_mode(input.spend_mode()),
        sequence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_taproot_doc_in_studio_shape() {
        use std::collections::BTreeMap;
        let doc = StudioDoc {
            format_version: 1,
            name: "demo".into(),
            keys: vec![StudioKey::Xonly {
                name: "key_1".into(),
                derivation_index: 0,
            }],
            scripts: vec![StudioScript {
                name: "script_1".into(),
                default_sign_mode: StudioSignMode::Single,
                source: "# opaque script 0x00".into(),
                params: vec![],
                stack_items: vec![StudioStackItem::SchnorrSig {
                    non_default_sighash: false,
                }],
                stack_items_overridden: true,
            }],
            transactions: vec![StudioTransaction {
                name: "start".into(),
                external: false,
                txid: "aa".repeat(32),
                external_txid: None,
                outputs: vec![StudioOutput::Taproot {
                    amount: StudioAmount::Sats(1000),
                    internal_key: "key_1".into(),
                    leaves: vec![StudioScriptUse {
                        script_ref: "script_1".into(),
                        sign_mode: StudioSignMode::Single,
                        bindings: BTreeMap::new(),
                    }],
                }],
                inputs: vec![],
            }],
            connections: vec![],
        };
        let yaml = to_yaml(&doc).unwrap();
        assert!(yaml.contains("formatVersion: 1"));
        assert!(!yaml.contains("settings:"));
        assert!(yaml.contains("kind: taproot"));
        assert!(yaml.contains("internalKey: key_1"));
        assert!(yaml.contains("scriptRef: script_1"));
        assert!(yaml.contains("nonDefaultSighash: false"));
        assert!(yaml.contains("stackItemsOverridden: true"));
        assert!(yaml.contains(&format!("txid: {}", "aa".repeat(32))));
        // round-trips back into the model
        let back: StudioDoc = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.transactions[0].name, "start");
    }

    #[test]
    fn maps_scalars_and_dedups_scripts() {
        use crate::scripts::{ProtocolScript, SignMode, StackItem};
        use crate::types::output::AmountType;
        use bitcoin::{Amount, ScriptBuf};

        assert!(matches!(
            map_amount(&AmountType::from(1000u64)),
            StudioAmount::Sats(1000)
        ));
        assert!(
            matches!(map_amount(&AmountType::Auto), StudioAmount::Symbol(ref s) if s == "AUTO")
        );
        assert!(
            matches!(map_amount(&AmountType::Recover), StudioAmount::Symbol(ref s) if s == "RECOVER")
        );

        assert!(matches!(
            map_stack_item(&StackItem::WinternitzSig { size: 42 }),
            StudioStackItem::WinternitzSig { size: 42 }
        ));
        assert!(matches!(
            map_stack_item(&StackItem::SchnorrSig {
                non_default_sighash: true
            }),
            StudioStackItem::SchnorrSig {
                non_default_sighash: true
            }
        ));
        assert!(matches!(
            map_stack_item(&StackItem::EcdsaSig {
                non_default_sighash: true
            }),
            StudioStackItem::EcdsaSig
        ));
        assert!(matches!(
            map_stack_item(&StackItem::LamportSig { size: 32 }),
            StudioStackItem::LamportSig { size: 32 }
        ));
        let lamport_yaml =
            serde_yaml::to_string(&map_stack_item(&StackItem::LamportSig { size: 32 })).unwrap();
        assert!(lamport_yaml.contains("kind: lamportSig"));
        assert!(lamport_yaml.contains("size: 32"));
        assert!(matches!(
            map_stack_item(&StackItem::Raw { size: 5 }),
            StudioStackItem::Raw { size: 5 }
        ));

        let _ = Amount::from_sat(1); // touch import to keep example self-contained
        let mut b = DocBuilder::new();
        let key = bitcoin::PublicKey::from_slice(&[
            0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
            0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
            0xb9, 0x5c, 0x70, 0x9e, 0xe5,
        ])
        .unwrap();
        let ps = ProtocolScript::new(ScriptBuf::from(vec![0x51]), &key, SignMode::Single);
        let u1 = b.intern_script(&ps);
        let u2 = b.intern_script(&ps);
        assert_eq!(
            u1.script_ref, u2.script_ref,
            "identical scripts dedup to one def"
        );
        assert_eq!(b.scripts.len(), 1);
        assert!(matches!(u1.sign_mode, StudioSignMode::Single));
    }

    #[test]
    fn maps_all_output_variants() {
        use crate::scripts::op_return;
        use crate::types::output::OutputType;
        use bitcoin::ScriptBuf;

        let key = bitcoin::PublicKey::from_slice(&[
            0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
            0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
            0xb9, 0x5c, 0x70, 0x9e, 0xe5,
        ])
        .unwrap();

        let mut b = DocBuilder::new();

        // p2wpkh
        let out = OutputType::segwit_key(1000u64, &key).unwrap();
        assert!(matches!(b.map_output(&out), StudioOutput::P2wpkh { .. }));

        // op_return via segwit_unspendable
        let opret = OutputType::segwit_unspendable(op_return(vec![0xab, 0xcd])).unwrap();
        match b.map_output(&opret) {
            StudioOutput::OpReturn { data_hex } => assert_eq!(data_hex, "abcd"),
            other => panic!("expected opReturn, got {other:?}"),
        }

        // external unknown
        let ext = OutputType::segwit_unspendable(ScriptBuf::new()).unwrap();
        // empty script is not op_return -> p2wsh placeholder
        assert!(matches!(b.map_output(&ext), StudioOutput::P2wsh { .. }));
    }

    #[test]
    fn maps_taproot_and_segwit_script_outputs() {
        use crate::scripts::{ProtocolScript, SignMode};
        use crate::types::output::OutputType;
        use bitcoin::{Amount, ScriptBuf};

        let key = bitcoin::PublicKey::from_slice(&[
            0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
            0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
            0xb9, 0x5c, 0x70, 0x9e, 0xe5,
        ])
        .unwrap();

        let mut b = DocBuilder::new();

        // taproot: interns internal key + leaf script
        let leaf = ProtocolScript::new(ScriptBuf::from(vec![0x51]), &key, SignMode::Single);
        let taproot_out = OutputType::taproot(Amount::from_sat(2000), &key, &[leaf]).unwrap();
        match b.map_output(&taproot_out) {
            StudioOutput::Taproot {
                amount,
                internal_key,
                leaves,
            } => {
                assert!(matches!(amount, StudioAmount::Sats(2000)));
                assert_eq!(internal_key, "key_1");
                assert_eq!(leaves.len(), 1);
                assert_eq!(leaves[0].script_ref, "script_1");
            }
            other => panic!("expected taproot, got {other:?}"),
        }
        assert_eq!(b.keys.len(), 1, "internal key interned once");
        assert_eq!(b.scripts.len(), 1, "leaf script interned once");

        // segwit_script: maps to P2wsh
        let ws_script = ProtocolScript::new(ScriptBuf::from(vec![0x52]), &key, SignMode::Single);
        let segwit_out = OutputType::segwit_script(Amount::from_sat(3000), &ws_script).unwrap();
        match b.map_output(&segwit_out) {
            StudioOutput::P2wsh { amount, script } => {
                assert!(matches!(amount, StudioAmount::Sats(3000)));
                assert_eq!(script.script_ref, "script_2");
            }
            other => panic!("expected p2wsh, got {other:?}"),
        }
    }

    #[test]
    fn external_unknown_output_roundtrips_through_yaml() {
        let doc = StudioDoc {
            format_version: 1,
            name: "ext".into(),
            keys: vec![],
            scripts: vec![],
            transactions: vec![StudioTransaction {
                name: "ext_tx".into(),
                external: true,
                txid: "bb".repeat(32),
                external_txid: None,
                outputs: vec![StudioOutput::ExternalUnknown],
                inputs: vec![],
            }],
            connections: vec![],
        };
        let yaml = to_yaml(&doc).unwrap();
        assert!(yaml.contains("kind: externalUnknown"));
        let back: StudioDoc = serde_yaml::from_str(&yaml).unwrap();
        assert!(matches!(
            back.transactions[0].outputs[0],
            StudioOutput::ExternalUnknown
        ));
    }

    #[test]
    fn studio_yaml_path_uses_only_the_protocol_name() {
        let path = studio_yaml_path(Path::new("exports"), "demo");
        assert_eq!(path, Path::new("exports/demo.yaml"));
    }

    #[test]
    fn connection_names_are_unique_without_claiming_existing_suffixes() {
        fn connection(name: &str) -> StudioConnection {
            StudioConnection {
                name: name.to_string(),
                from: StudioEndpointFrom {
                    tx: "a".to_string(),
                    output_index: 0,
                },
                to: StudioEndpointTo {
                    tx: "b".to_string(),
                    input_index: 0,
                },
                timelock_blocks: None,
            }
        }

        let mut connections = vec![
            connection("claim"),
            connection("claim"),
            connection("claim_2"),
            connection("claim"),
            connection("claim_2"),
        ];

        make_connection_names_unique(&mut connections);

        let names: Vec<_> = connections
            .iter()
            .map(|connection| connection.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["claim", "claim_3", "claim_2", "claim_4", "claim_2_2"]
        );
    }

    #[test]
    fn maps_input_sighash_spendmode_sequence() {
        use crate::scripts::SignMode;
        use crate::types::input::{InputType, SighashType, SpendMode};
        use bitcoin::Sequence;

        let input = InputType::new(
            &SpendMode::All {
                key_path_sign: SignMode::Single,
            },
            &SighashType::taproot_all(),
        );

        let mapped = map_input(&input, Sequence::MAX);
        assert!(matches!(
            mapped.sighash_type.class,
            StudioSighashClass::Taproot
        ));
        assert!(matches!(mapped.sighash_type.flag, StudioSighashFlag::All));
        assert!(matches!(mapped.spend_mode, StudioSpendMode::All { .. }));
        assert_eq!(mapped.sequence, None, "MAX sequence is default -> omitted");

        let with_seq = map_input(&input, Sequence::from_consensus(100));
        assert_eq!(with_seq.sequence, Some(100));
    }
}
