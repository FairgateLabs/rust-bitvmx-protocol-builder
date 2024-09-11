pub mod builder;
pub mod cli;
pub mod config;
pub mod errors;
pub mod graph;
pub mod params;
pub mod scripts;
pub mod template;
pub mod unspendable;
pub mod taproot_spend_info_serde {
    use bitcoin::taproot::TaprootSpendInfo;
    use serde::Deserializer;

    use crate::errors::TemplateError;


    pub fn deserialize<'de, D>() -> Result<Option<TaprootSpendInfo>, TemplateError>
    where
        D: Deserializer<'de>,
    {
        Ok(None)
    }
}