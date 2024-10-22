use bitcoin::{key::Secp256k1, secp256k1::Scalar, taproot::TaprootSpendInfo, Amount, PublicKey, XOnlyPublicKey};
use serde::{ser::SerializeStruct, Deserialize, Serialize};

use crate::scripts::{self, ProtocolScript};

#[derive(Debug, Clone)]
pub enum OutputSpendingType {
    TaprootUntweakedKey{
        key: PublicKey,
    },
    TaprootTweakedKey{
        key: PublicKey,
        tweak: Scalar,
    },
    TaprootScript{
        spending_scripts: Vec<ProtocolScript>,
        spend_info: TaprootSpendInfo,
        internal_key: XOnlyPublicKey,
    },
    SegwitPublicKey{
        public_key: PublicKey,
        value: Amount, 
    },
    SegwitScript{
        script: ProtocolScript,
        value: Amount, 
    }
}

impl Serialize for OutputSpendingType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            OutputSpendingType::TaprootUntweakedKey { key } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 1)?;
                state.serialize_field("key", key)?;
                state.end()
            }
            OutputSpendingType::TaprootTweakedKey { key, tweak } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 2)?;
                state.serialize_field("key", key)?;
                state.serialize_field("tweak", &tweak.to_be_bytes())?;
                state.end()
            }
            OutputSpendingType::TaprootScript { spending_scripts, spend_info: _, internal_key } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 2)?;
                state.serialize_field("spending_scripts", spending_scripts)?;
                state.serialize_field("internal_key", internal_key)?;
                state.end()
            }
            OutputSpendingType::SegwitPublicKey { public_key, value } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 2)?;
                state.serialize_field("public_key", public_key)?;
                state.serialize_field("value", value)?;
                state.end()
            }
            OutputSpendingType::SegwitScript { script, value } => {
                let mut state = serializer.serialize_struct("OutputSpendingType", 2)?;
                state.serialize_field("script", script)?;
                state.serialize_field("value", value)?;
                state.end()
            }
        }
    }
}


impl<'de> Deserialize<'de> for OutputSpendingType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Key,
            Tweak,
            SpendingScripts,
            InternalKey,
            PublicKey,
            Script,
            Value,
        }

        struct OutputSpendingTypeVisitor;

        impl<'de> serde::de::Visitor<'de> for OutputSpendingTypeVisitor {
            type Value = OutputSpendingType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct OutputSpendingType")
            }

            fn visit_map<V>(self, mut map: V) -> Result<OutputSpendingType, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut key: Option<PublicKey> = None;
                let mut tweak: Option<[u8; 32]> = None;
                let mut spending_scripts: Option<Vec<ProtocolScript>> = None;
                let mut internal_key: Option<XOnlyPublicKey> = None;
                let mut public_key: Option<PublicKey> = None;
                let mut script: Option<ProtocolScript> = None;
                let mut value: Option<Amount> = None;

                while let Some(key_field) = map.next_key()? {
                    match key_field {
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
                if key.is_some() {
                    if tweak.is_none(){
                        let key = key.ok_or_else(|| serde::de::Error::missing_field("key"))?;
                        Ok(OutputSpendingType::TaprootUntweakedKey { key })
                    } else {
                        let key = key.ok_or_else(|| serde::de::Error::missing_field("key"))?;
                        let tweak = tweak.ok_or_else(|| serde::de::Error::missing_field("tweak"))?;
                        Ok(OutputSpendingType::TaprootTweakedKey { key, tweak: Scalar::from_be_bytes(tweak).map_err(|e| serde::de::Error::custom(e.to_string()))? })
                    }
                } else if spending_scripts.is_some() {
                    Ok(OutputSpendingType::TaprootScript {
                        spending_scripts: spending_scripts.clone().ok_or_else(|| serde::de::Error::missing_field("spending_scripts"))?,
                        spend_info: {
                            let secp = Secp256k1::new();
                            let internal_key_ok = internal_key.ok_or_else(|| serde::de::Error::missing_field("taproot_internal_key"))?;
                            let spending_scripts = spending_scripts.clone().ok_or_else(|| serde::de::Error::missing_field("spending_paths"))?;
                            match scripts::build_taproot_spend_info(&secp, &internal_key_ok, &spending_scripts){
                                Ok(taproot_spend_info) => taproot_spend_info,
                                Err(e) => {
                                    eprintln!("Error creating taproot spend info: {:?}", e);
                                    return Err(serde::de::Error::custom("Error creating taproot spend info"))
                                }
                            }
                        },
                        internal_key: internal_key.ok_or_else(|| serde::de::Error::missing_field("internal_key"))?,
                    })
                } else if public_key.is_some() {
                    let public_key = public_key.ok_or_else(|| serde::de::Error::missing_field("public_key"))?;
                    let value = value.ok_or_else(|| serde::de::Error::missing_field("value"))?;
                    Ok(OutputSpendingType::SegwitPublicKey { public_key, value })
                } else if script.is_some() {
                    let script = script.ok_or_else(|| serde::de::Error::missing_field("script"))?;
                    let value = value.ok_or_else(|| serde::de::Error::missing_field("value"))?;
                    Ok(OutputSpendingType::SegwitScript { script, value })
                } else {
                    Err(serde::de::Error::missing_field("key"))
                }
            }
        }

        deserializer.deserialize_struct(
            "OutputSpendingType",
            &["key", "tweak", "spending_scripts", "internal_key", "public_key", "script", "value"],
            OutputSpendingTypeVisitor,
        )
    }
}     

impl OutputSpendingType {
    pub fn new_taproot_tweaked_key_spend(public_key: &PublicKey, tweak: &Scalar) -> Self {
        OutputSpendingType::TaprootTweakedKey {
            key: *public_key,
            tweak: *tweak,
        }
    }

    pub fn new_taproot_key_spend(public_key: &PublicKey) -> Self {
        OutputSpendingType::TaprootUntweakedKey {
            key: *public_key,
        }
    }
    
    pub fn new_taproot_script_spend(spending_scripts: &[ProtocolScript], spend_info: &TaprootSpendInfo) -> OutputSpendingType {
        OutputSpendingType::TaprootScript {
            spending_scripts: spending_scripts.to_vec(),
            spend_info: spend_info.clone(),
            internal_key: spend_info.internal_key(),
        }
    }
    
    pub fn new_segwit_key_spend(public_key: &PublicKey, value: Amount) -> OutputSpendingType {
        OutputSpendingType::SegwitPublicKey { 
            public_key: *public_key, 
            value,
        } 
    }
    
    pub fn new_segwit_script_spend(script: &ProtocolScript, value: Amount) -> OutputSpendingType {
        OutputSpendingType::SegwitScript { 
            script: script.clone(),
            value,
        } 
    }
}
