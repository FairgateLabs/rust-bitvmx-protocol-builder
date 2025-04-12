use bitcoin::{
    key::Secp256k1, secp256k1::Scalar, taproot::TaprootSpendInfo, Amount, PublicKey, TxOut,
    XOnlyPublicKey,
};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use crate::scripts::{self, ProtocolScript};

const ALL_OUTPUT_TYPES: &[&str] = &[
    "taproot_untweaked_key",
    "taproot_tweaked_key",
    "taproot_script_unspendable_key",
    "taproot_script_and_key",
    "segwit_public_key",
    "segwit_script",
    "segwit_unspendable",
];

// Alias for the OutputType enum to minimized changes outside this crate. Eventually we will remove it.
pub type OutputSpendingType = OutputType;

#[derive(Debug, Clone)]
pub enum OutputType {
    TaprootUntweakedKey {
        key: PublicKey,
        prevouts: Vec<TxOut>,
    },
    TaprootTweakedKey {
        key: PublicKey,
        tweak: Scalar,
        prevouts: Vec<TxOut>,
    },
    TaprootScriptUnspendableKey {
        spending_scripts: Vec<ProtocolScript>,
        spend_info: TaprootSpendInfo,
        internal_key: XOnlyPublicKey,
        prevouts: Vec<TxOut>,
    },
    TaprootScriptAndKey {
        spending_scripts: Vec<ProtocolScript>,
        spend_info: TaprootSpendInfo,
        internal_key: XOnlyPublicKey,
        prevouts: Vec<TxOut>,
    },
    SegwitPublicKey {
        public_key: PublicKey,
        value: Amount,
    },
    SegwitScript {
        script: ProtocolScript,
        value: Amount,
    },
    SegwitUnspendable {},
}

impl Serialize for OutputType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            OutputType::TaprootUntweakedKey { key, prevouts } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 2)?;
                state.serialize_field("type", "taproot_untweaked_key")?;
                state.serialize_field("key", key)?;
                state.serialize_field("prevouts", prevouts)?;
                state.end()
            }
            OutputType::TaprootTweakedKey {
                key,
                tweak,
                prevouts,
            } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 3)?;
                state.serialize_field("type", "taproot_tweaked_key")?;
                state.serialize_field("key", key)?;
                state.serialize_field("tweak", &tweak.to_be_bytes())?;
                state.serialize_field("prevouts", prevouts)?;
                state.end()
            }
            OutputType::TaprootScriptUnspendableKey {
                spending_scripts,
                spend_info: _,
                internal_key,
                prevouts,
            } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 3)?;
                state.serialize_field("type", "taproot_script_unspendable_key")?;
                state.serialize_field("spending_scripts", spending_scripts)?;
                state.serialize_field("internal_key", internal_key)?;
                state.serialize_field("prevouts", prevouts)?;
                state.end()
            }
            OutputType::TaprootScriptAndKey {
                spending_scripts,
                spend_info: _,
                internal_key,
                prevouts,
            } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 3)?;
                state.serialize_field("type", "taproot_script_and_key")?;
                state.serialize_field("spending_scripts", spending_scripts)?;
                state.serialize_field("internal_key", internal_key)?;
                state.serialize_field("prevouts", prevouts)?;
                state.end()
            }
            OutputType::SegwitPublicKey { public_key, value } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 3)?;
                state.serialize_field("type", "segwit_public_key")?;
                state.serialize_field("public_key", public_key)?;
                state.serialize_field("value", value)?;
                state.end()
            }
            OutputType::SegwitScript { script, value } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 3)?;
                state.serialize_field("type", "segwit_script")?;
                state.serialize_field("script", script)?;
                state.serialize_field("value", value)?;
                state.end()
            }
            OutputType::SegwitUnspendable {} => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 1)?;
                state.serialize_field("type", "segwit_unspendable")?;
                state.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for OutputType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Type,
            Key,
            Tweak,
            Prevouts,
            SpendingScripts,
            InternalKey,
            PublicKey,
            Script,
            Value,
        }

        struct OutputSpendingTypeVisitor;

        impl<'de> serde::de::Visitor<'de> for OutputSpendingTypeVisitor {
            type Value = OutputType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct OutputSpendingType")
            }

            fn visit_map<V>(self, mut map: V) -> Result<OutputType, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut type_field: Option<String> = None;
                let mut key: Option<PublicKey> = None;
                let mut tweak: Option<[u8; 32]> = None;
                let mut prevouts: Option<Vec<TxOut>> = None;
                let mut spending_scripts: Option<Vec<ProtocolScript>> = None;
                let mut internal_key: Option<XOnlyPublicKey> = None;
                let mut public_key: Option<PublicKey> = None;
                let mut script: Option<ProtocolScript> = None;
                let mut value: Option<Amount> = None;

                while let Some(key_field) = map.next_key()? {
                    match key_field {
                        Field::Type => {
                            if type_field.is_some() {
                                return Err(serde::de::Error::duplicate_field("type"));
                            }
                            type_field = Some(map.next_value()?);
                        }
                        Field::Key => {
                            if key.is_some() {
                                return Err(serde::de::Error::duplicate_field("key"));
                            }
                            key = Some(map.next_value()?);
                        }
                        Field::Tweak => {
                            if tweak.is_some() {
                                return Err(serde::de::Error::duplicate_field("tweak"));
                            }
                            tweak = Some(map.next_value()?);
                        }
                        Field::Prevouts => {
                            if prevouts.is_some() {
                                return Err(serde::de::Error::duplicate_field("prevouts"));
                            }
                            prevouts = Some(map.next_value()?);
                        }
                        Field::SpendingScripts => {
                            if spending_scripts.is_some() {
                                return Err(serde::de::Error::duplicate_field("spending_scripts"));
                            }
                            spending_scripts = Some(map.next_value()?);
                        }
                        Field::InternalKey => {
                            if internal_key.is_some() {
                                return Err(serde::de::Error::duplicate_field("internal_key"));
                            }
                            internal_key = Some(map.next_value()?);
                        }
                        Field::PublicKey => {
                            if public_key.is_some() {
                                return Err(serde::de::Error::duplicate_field("public_key"));
                            }
                            public_key = Some(map.next_value()?);
                        }
                        Field::Script => {
                            if script.is_some() {
                                return Err(serde::de::Error::duplicate_field("script"));
                            }
                            script = Some(map.next_value()?);
                        }
                        Field::Value => {
                            if value.is_some() {
                                return Err(serde::de::Error::duplicate_field("value"));
                            }
                            value = Some(map.next_value()?);
                        }
                    }
                }

                let output_type =
                    type_field.ok_or_else(|| serde::de::Error::missing_field("type"))?;

                match output_type.as_str() {
                    "taproot_untweaked_key" => {
                        let key = key.ok_or_else(|| serde::de::Error::missing_field("key"))?;
                        let prevouts =
                            prevouts.ok_or_else(|| serde::de::Error::missing_field("prevouts"))?;
                        Ok(OutputType::TaprootUntweakedKey { key, prevouts })
                    }
                    "taproot_tweaked_key" => {
                        let key = key.ok_or_else(|| serde::de::Error::missing_field("key"))?;
                        let tweak =
                            tweak.ok_or_else(|| serde::de::Error::missing_field("tweak"))?;
                        let prevouts =
                            prevouts.ok_or_else(|| serde::de::Error::missing_field("prevouts"))?;
                        Ok(OutputType::TaprootTweakedKey {
                            key,
                            tweak: Scalar::from_be_bytes(tweak)
                                .map_err(|e| serde::de::Error::custom(e.to_string()))?,
                            prevouts,
                        })
                    }
                    "taproot_script_unspendable_key" => {
                        let spending_scripts = spending_scripts
                            .ok_or_else(|| serde::de::Error::missing_field("spending_scripts"))?;
                        let internal_key = internal_key
                            .ok_or_else(|| serde::de::Error::missing_field("internal_key"))?;
                        let prevouts =
                            prevouts.ok_or_else(|| serde::de::Error::missing_field("prevouts"))?;
                        let secp = Secp256k1::new();
                        let spend_info = scripts::build_taproot_spend_info(
                            &secp,
                            &internal_key,
                            &spending_scripts,
                        )
                        .map_err(|e| {
                            eprintln!("Error creating taproot spend info: {:?}", e);
                            serde::de::Error::custom("Error creating taproot spend info")
                        })?;
                        Ok(OutputType::TaprootScriptUnspendableKey {
                            spending_scripts,
                            spend_info,
                            internal_key,
                            prevouts,
                        })
                    }
                    "taproot_script_and_key" => {
                        let spending_scripts = spending_scripts
                            .ok_or_else(|| serde::de::Error::missing_field("spending_scripts"))?;
                        let internal_key = internal_key
                            .ok_or_else(|| serde::de::Error::missing_field("internal_key"))?;
                        let prevouts =
                            prevouts.ok_or_else(|| serde::de::Error::missing_field("prevouts"))?;
                        let secp = Secp256k1::new();
                        let spend_info = scripts::build_taproot_spend_info(
                            &secp,
                            &internal_key,
                            &spending_scripts,
                        )
                        .map_err(|e| {
                            eprintln!("Error creating taproot spend info: {:?}", e);
                            serde::de::Error::custom("Error creating taproot spend info")
                        })?;
                        Ok(OutputType::TaprootScriptAndKey {
                            spending_scripts,
                            spend_info,
                            internal_key,
                            prevouts,
                        })
                    }
                    "segwit_public_key" => {
                        let public_key = public_key
                            .ok_or_else(|| serde::de::Error::missing_field("public_key"))?;
                        let value =
                            value.ok_or_else(|| serde::de::Error::missing_field("value"))?;
                        Ok(OutputType::SegwitPublicKey { public_key, value })
                    }
                    "segwit_script" => {
                        let script =
                            script.ok_or_else(|| serde::de::Error::missing_field("script"))?;
                        let value =
                            value.ok_or_else(|| serde::de::Error::missing_field("value"))?;
                        Ok(OutputType::SegwitScript { script, value })
                    }
                    "segwit_unspendable" => Ok(OutputType::SegwitUnspendable {}),
                    _ => Err(serde::de::Error::unknown_variant(
                        &output_type,
                        ALL_OUTPUT_TYPES,
                    )),
                }
            }
        }

        deserializer.deserialize_struct(
            "OutputSpendingType",
            &[
                "type",
                "key",
                "tweak",
                "spending_scripts",
                "internal_key",
                "public_key",
                "script",
                "value",
            ],
            OutputSpendingTypeVisitor,
        )
    }
}

impl OutputType {
    pub fn new_taproot_tweaked_key_spend(
        public_key: &PublicKey,
        tweak: &Scalar,
        prevouts: Vec<TxOut>,
    ) -> Self {
        OutputType::TaprootTweakedKey {
            key: *public_key,
            tweak: *tweak,
            prevouts,
        }
    }

    pub fn new_taproot_key_spend(public_key: &PublicKey, prevouts: Vec<TxOut>) -> Self {
        OutputType::TaprootUntweakedKey {
            key: *public_key,
            prevouts,
        }
    }

    pub fn new_taproot_script_unspendable_key_spend(
        spending_scripts: &[ProtocolScript],
        spend_info: &TaprootSpendInfo,
        prevouts: Vec<TxOut>,
    ) -> OutputType {
        OutputType::TaprootScriptUnspendableKey {
            spending_scripts: spending_scripts.to_vec(),
            spend_info: spend_info.clone(),
            internal_key: spend_info.internal_key(),
            prevouts,
        }
    }

    pub fn new_taproot_script_and_key_spend(
        spending_scripts: &[ProtocolScript],
        spend_info: &TaprootSpendInfo,
        prevouts: Vec<TxOut>,
    ) -> OutputType {
        OutputType::TaprootScriptAndKey {
            spending_scripts: spending_scripts.to_vec(),
            spend_info: spend_info.clone(),
            internal_key: spend_info.internal_key(),
            prevouts,
        }
    }

    pub fn new_segwit_key_spend(public_key: &PublicKey, value: Amount) -> OutputType {
        OutputType::SegwitPublicKey {
            public_key: *public_key,
            value,
        }
    }

    pub fn new_segwit_script_spend(script: &ProtocolScript, value: Amount) -> OutputType {
        OutputType::SegwitScript {
            script: script.clone(),
            value,
        }
    }

    pub fn new_segwit_unspendable() -> OutputType {
        OutputType::SegwitUnspendable {}
    }

    pub fn get_name(&self) -> &str {
        match self {
            OutputType::TaprootUntweakedKey { .. } => "TaprootUntweakedKey",
            OutputType::TaprootTweakedKey { .. } => "TaprootTweakedKey",
            OutputType::TaprootScriptUnspendableKey { .. } => "TaprootScriptOnly",
            OutputType::TaprootScriptAndKey { .. } => "TaprootScriptAndKey",
            OutputType::SegwitPublicKey { .. } => "SegwitPublicKey",
            OutputType::SegwitScript { .. } => "SegwitScript",
            OutputType::SegwitUnspendable { .. } => "SegwitUnspendable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::{key::rand, secp256k1::Secp256k1};

    #[test]
    fn test_new_taproot_tweaked_key_spend() {
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let tweak = Scalar::random();

        let spending_type =
            OutputType::new_taproot_tweaked_key_spend(&public_key.into(), &tweak, vec![]);

        match spending_type {
            OutputType::TaprootTweakedKey {
                key,
                tweak: t,
                prevouts,
            } => {
                assert_eq!(key, public_key.into());
                assert_eq!(t, tweak);
                assert!(prevouts.is_empty());
            }
            _ => panic!("Wrong enum variant"),
        }
    }

    #[test]
    fn test_new_taproot_key_spend() {
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());

        let spending_type = OutputType::new_taproot_key_spend(&public_key.into(), vec![]);

        match spending_type {
            OutputType::TaprootUntweakedKey { key, prevouts } => {
                assert_eq!(key, public_key.into());
                assert!(prevouts.is_empty());
            }
            _ => panic!("Wrong enum variant"),
        }
    }

    #[test]
    fn test_new_segwit_key_spend() {
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let value = Amount::from_sat(1000);

        let spending_type = OutputType::new_segwit_key_spend(&public_key.into(), value);

        match spending_type {
            OutputType::SegwitPublicKey {
                public_key: key,
                value: v,
            } => {
                assert_eq!(key, public_key.into());
                assert_eq!(v, value);
            }
            _ => panic!("Wrong enum variant"),
        }
    }

    #[test]
    fn test_new_segwit_script_spend() {
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let script = ProtocolScript::new(bitcoin::ScriptBuf::new(), &public_key.into());
        let value = Amount::from_sat(1000);

        let spending_type = OutputType::new_segwit_script_spend(&script, value);

        match spending_type {
            OutputType::SegwitScript {
                script: s,
                value: v,
            } => {
                assert_eq!(s.get_script(), script.get_script());
                assert_eq!(v, value);
            }
            _ => panic!("Wrong enum variant"),
        }
    }
}
