use std::str::FromStr;

use bitcoin::{EcdsaSighashType, PublicKey, ScriptBuf, TapSighashType};

use crate::{config::Config, errors::ConfigError, scripts::{self, ScriptWithParams}};

#[derive(Clone, Debug)]
/// DefaultParams is a struct that holds the default parameters for the templates.
/// It is used by the template builder to create the templates when using TemplateBuilder's shortcut functions add_start(), add_connection(), and add_rounds().
pub struct DefaultParams { 
    protocol_amount: u64,                 // The amount of satoshis to be consumed in the protocol output for each template
    speedup_from_key: PublicKey,          // The public key to validate an input trying to spend the speedup output of each 'from' template
    speedup_to_key: PublicKey,            // The public key to validate an input trying to spend the speedup output of each 'to' template
    speedup_amount: u64,                  // The amount of satoshis to be consumed in the speedup output for each template
    timelock_from_key: PublicKey,         // The public key to validate an input trying to spend the timelock output of each 'from' template
    timelock_to_key: PublicKey,           // The public key to validate an input trying to spend the timelock output of each 'to' template
    timelock_renew_key: PublicKey,        // The public key to validate an input trying to renew the timelock output of each template
    locked_amount: u64,                   // The amount of satoshis to be consumed in the timelock output for each template
    locked_blocks: u16,                   // The number of blocks a transaction needs to wait to consume the timelock output of each template
    ecdsa_sighash_type: EcdsaSighashType, // The sighash type used to compute the sighash of a non-taproot input
    taproot_sighash_type: TapSighashType, // The sighash type used to compute the sighash of a taproot input
    graph_path: String,                   // The path to storage linked to the graph 
}


impl DefaultParams {
    pub fn new(protocol_amount: u64, speedup_from_key: &PublicKey, speedup_to_key: &PublicKey, speedup_amount: u64, timelock_from_key: &PublicKey, timelock_to_key: &PublicKey, timelock_renew_key: &PublicKey, locked_amount: u64, locked_blocks: u16, ecdsa_sighash_type: EcdsaSighashType, taproot_sighash_type: TapSighashType, graph_path: String) -> Result<Self, ConfigError> {
        let defaults = DefaultParams {
            protocol_amount,
            speedup_from_key: *speedup_from_key,
            speedup_to_key: *speedup_to_key,
            speedup_amount,
            timelock_from_key: *timelock_from_key,
            timelock_to_key: *timelock_to_key,
            timelock_renew_key: *timelock_renew_key,
            locked_amount,
            graph_path,
            locked_blocks,
            ecdsa_sighash_type,
            taproot_sighash_type,
        };

        Ok(defaults)
    }

    pub fn get_protocol_amount(&self) -> u64 {
        self.protocol_amount
    }

    pub fn get_locked_amount(&self) -> u64 {
        self.locked_amount
    }

    pub fn get_ecdsa_sighash_type(&self) -> EcdsaSighashType {
        self.ecdsa_sighash_type
    }

    pub fn get_taproot_sighash_type(&self) -> TapSighashType {
        self.taproot_sighash_type
    }

    pub fn speedup_from_script(&self) -> Result<ScriptBuf, ConfigError> {
        let speedup = scripts::speedup(&self.speedup_from_key)?;
        Ok(speedup)
    }

    pub fn speedup_to_script(&self) -> Result<ScriptBuf, ConfigError>  {
        let speedup = scripts::speedup(&self.speedup_to_key)?;
        Ok(speedup)
    }

    pub fn timelock_from_script(&self) -> Result<ScriptWithParams, ConfigError> {
        // Using the timelock_to_key here since in a given template send by the "from" participant, 
        // the timelock can be spent by the "to" participant.
        let timelock = scripts::timelock(self.locked_blocks, &self.timelock_to_key);
        Ok(timelock)
    }

    pub fn timelock_to_script(&self) -> Result<ScriptWithParams, ConfigError>  {
        // Using the timelock_from_key here since in a given template send by the "to" participant, 
        // the timelock can be spent by the "from" participant.
        let timelock = scripts::timelock(self.locked_blocks, &self.timelock_from_key);
        Ok(timelock)
    }

    pub fn timelock_renew_script(&self) -> Result<ScriptWithParams, ConfigError>  {
        let timelock = scripts::collaborative_spend(&self.timelock_renew_key);
        Ok(timelock)
    }

    pub fn template_from_params(&self) -> Result<TemplateParams, ConfigError> {
        Ok(TemplateParams::new(
            self.speedup_from_script()?,
            self.speedup_amount,
        ))
    }

    pub fn template_to_params(&self) -> Result<TemplateParams, ConfigError> {
        Ok(TemplateParams::new(
            self.speedup_to_script()?,
            self.speedup_amount,
        ))
    }

    pub fn connection_params(&self, spending_scripts: &[ScriptWithParams]) -> Result<ConnectionParams, ConfigError> {
        let template_from = self.template_from_params()?;
        let template_to = self.template_to_params()?;   
        let timelock_from = self.timelock_from_script()?;
        let timelock_renew = self.timelock_renew_script()?;
        let locked_amount = self.locked_amount;
        let locked_blocks = self.locked_blocks;

        Ok(ConnectionParams::new(
            template_from,
            template_to, 
            timelock_from,
            timelock_renew,
            locked_amount,
            locked_blocks,
            spending_scripts,
        ))
    }

    pub fn reverse_connection_params(&self, spending_scripts: &[ScriptWithParams]) -> Result<ConnectionParams, ConfigError> {
        let template_from = self.template_from_params()?;
        let template_to = self.template_to_params()?;  
        let timelock_to = self.timelock_from_script()?;
        let timelock_renew = self.timelock_renew_script()?;
        let locked_amount = self.locked_amount;
        let locked_blocks = self.locked_blocks;

        Ok(ConnectionParams::new(
            template_to,
            template_from, 
            timelock_to,
            timelock_renew,
            locked_amount,
            locked_blocks,
            spending_scripts,   
        ))
    }

    pub fn graph_path(&self)-> String {
        self.graph_path.clone()
    }
}

impl TryFrom<&Config> for DefaultParams {
    fn try_from(config: &Config) -> Result<Self, ConfigError> {
        let protocol_amount = config.template_builder.protocol_amount;
        let speedup_from_key = PublicKey::from_str(config.template_builder.speedup_from_key.as_str())?;
        let speedup_to_key = PublicKey::from_str(config.template_builder.speedup_to_key.as_str())?;
        let speedup_amount = config.template_builder.speedup_amount;
        let timelock_from_key = PublicKey::from_str(config.template_builder.timelock_from_key.as_str())?;
        let timelock_to_key = PublicKey::from_str(config.template_builder.timelock_to_key.as_str())?;
        let timelock_renew_key = PublicKey::from_str(config.template_builder.timelock_renew_key.as_str())?;
        let locked_amount = config.template_builder.locked_amount;
        let locked_blocks = config.template_builder.locked_blocks;
        let ecdsa_sighash_type = EcdsaSighashType::from_str(config.template_builder.ecdsa_sighash_type.as_str())?;
        let taproot_sighash_type = TapSighashType::from_str(config.template_builder.taproot_sighash_type.as_str())?;
        let graph_path = config.template_builder.graph_path.clone();
       
        let defaults = DefaultParams::new(
            protocol_amount, 
            &speedup_from_key, 
            &speedup_to_key, 
            speedup_amount,
            &timelock_from_key, 
            &timelock_to_key, 
            &timelock_renew_key,
            locked_amount, 
            locked_blocks,
            ecdsa_sighash_type,
            taproot_sighash_type,
            graph_path,
        )?;

        Ok(defaults)
    }
    
    type Error = ConfigError;
}

#[derive(Clone, Debug)]
/// TemplateParams is a struct that holds the parameters to create templates.
pub struct TemplateParams {
    speedup_script: ScriptBuf,
    speedup_amount: u64,
}

impl TemplateParams {
    pub fn new(speedup_script: ScriptBuf, speedup_amount: u64) -> Self {
        TemplateParams {
            speedup_script,
            speedup_amount,
        }
    }

    pub fn get_speedup_script(&self) -> ScriptBuf {
        self.speedup_script.clone()
    }

    pub fn get_speedup_amount(&self) -> u64 {
        self.speedup_amount
    }
}

#[derive(Clone, Debug)]
/// ConnectionParams is a struct that holds the parameters to create connections between templates.
/// It is used by the template builder to create the connections when using the TemplateBuilder's long version function connect.
pub struct ConnectionParams {
    template_from: TemplateParams,
    template_to: TemplateParams,
    timelock_script: ScriptWithParams, 
    timelock_renew: ScriptWithParams,
    locked_amount: u64,
    locked_blocks: u16,
    spending_scripts: Vec<ScriptWithParams>,
}

impl ConnectionParams {
    pub fn new(template_from: TemplateParams, template_to: TemplateParams, timelock_script: ScriptWithParams, timelock_renew: ScriptWithParams, locked_amount: u64, locked_blocks: u16, spending_scripts: &[ScriptWithParams]) -> Self {
        ConnectionParams {
            template_from,
            template_to,
            timelock_script, 
            timelock_renew,
            locked_amount,
            locked_blocks,
            spending_scripts: spending_scripts.to_vec(),
        } 
    }

    pub fn template_from(&self) -> TemplateParams {
        self.template_from.clone()
    }

    pub fn template_to(&self) -> TemplateParams {
        self.template_to.clone()
    }

    pub fn get_timelock_script(&self) -> ScriptWithParams {
        self.timelock_script.clone()
    }

    pub fn get_timelock_renew_script(&self) -> ScriptWithParams {
        self.timelock_renew.clone()
    }

    pub fn get_locked_amount(&self) -> u64 {
        self.locked_amount
    }

    pub fn get_lock_blocks(&self) -> u16 {
        self.locked_blocks
    }

    pub fn spending_scripts(&self) -> Vec<ScriptBuf> {
        self.spending_scripts.iter().map(|script| script.get_script().clone()).collect()
    }

    pub fn timelock_scripts(&self) -> Vec<ScriptWithParams> {
        vec![self.timelock_script.clone(), self.timelock_renew.clone()]
    }

    pub fn spending_scripts_with_params(&self) -> Vec<ScriptWithParams> {
        self.spending_scripts.clone()
    }
}

#[derive(Clone, Debug)]
/// RoundParams is a struct that holds the parameters to create rounds between templates.
/// It is used by the template builder to create the connections when using the TemplateBuilder's long version function connect_rounds.
pub struct RoundParams {
    direct_connection: ConnectionParams,
    reverse_connection: ConnectionParams,
}

impl RoundParams {
    pub fn new(connection: ConnectionParams, reverse_connection: ConnectionParams) -> Self {
        RoundParams {
            direct_connection: connection,
            reverse_connection,
        }
    }

    pub fn direct_connection(&self) -> ConnectionParams {
        self.direct_connection.clone()
    }

    pub fn reverse_connection(&self) -> ConnectionParams {
        self.reverse_connection.clone()
    }
}
