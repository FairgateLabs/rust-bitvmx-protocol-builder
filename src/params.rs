use bitcoin::{PublicKey, ScriptBuf, TapSighashType};

use crate::{errors::ConfigError, scripts::{self, ScriptWithParams}};

#[derive(Clone, Debug)]
pub struct DefaultParams { 
    protocol_amount: u64,
    speedup_from_key: PublicKey,
    speedup_to_key: PublicKey,
    speedup_amount: u64,
    timelock_blocks: u8,
    timelock_from_key: PublicKey,
    timelock_to_key: PublicKey,
    locked_amount: u64,
    sighash_type: TapSighashType,
}

impl DefaultParams {
    pub fn new(protocol_amount: u64, speedup_from_key: &PublicKey, speedup_to_key: &PublicKey, speedup_amount: u64, timelock_blocks: u8, timelock_from_key: &PublicKey, timelock_to_key: &PublicKey, locked_amount: u64, sighash_type: TapSighashType) -> Result<Self, ConfigError> {
        let defaults = DefaultParams {
            protocol_amount,
            speedup_from_key: *speedup_from_key,
            speedup_to_key: *speedup_to_key,
            speedup_amount,
            timelock_blocks,
            timelock_from_key: *timelock_from_key,
            timelock_to_key: *timelock_to_key,
            locked_amount,
            sighash_type,
        };

        Ok(defaults)
    }

    pub fn get_protocol_amount(&self) -> u64 {
        self.protocol_amount
    }

    pub fn get_sighash_type(&self) -> TapSighashType {
        self.sighash_type
    }

    pub fn speedup_from_script(&self) -> Result<ScriptBuf, ConfigError> {
        let speedup = scripts::speedup(&self.speedup_from_key)?;
        Ok(speedup)
    }

    pub fn speedup_to_script(&self) -> Result<ScriptBuf, ConfigError>  {
        let speedup = scripts::speedup(&self.speedup_to_key)?;
        Ok(speedup)
    }

    pub fn timelock_from_script(&self) -> Result<ScriptBuf, ConfigError> {
        // Using the timelock_to_key here since in a given template send by the "from" participant, 
        // the timelock can be spent by the "to" participant.
        let timelock = scripts::timelock(&self.timelock_to_key, self.timelock_blocks);
        Ok(timelock)
    }

    pub fn timelock_to_script(&self) -> Result<ScriptBuf, ConfigError>  {
        // Using the timelock_from_key here since in a given template send by the "to" participant, 
        // the timelock can be spent by the "from" participant.
        let timelock = scripts::timelock(&self.timelock_from_key, self.timelock_blocks);
        Ok(timelock)
    }

    pub fn template_from_params(&self) -> Result<TemplateParams, ConfigError> {
        Ok(TemplateParams::new(
            self.speedup_from_script()?,
            self.speedup_amount,
            self.timelock_from_script()?,
            self.locked_amount,
        ))
    }

    pub fn template_to_params(&self) -> Result<TemplateParams, ConfigError> {
        Ok(TemplateParams::new(
            self.speedup_to_script()?,
            self.speedup_amount,
            self.timelock_to_script()?,
            self.locked_amount,
        ))
    }

    pub fn connection_params(&self, spending_scripts: &[ScriptWithParams]) -> Result<ConnectionParams, ConfigError> {
        let template_from = self.template_from_params()?;
        let template_to = self.template_to_params()?;   

        Ok(ConnectionParams::new(
            template_from,
            template_to, 
            spending_scripts,
        ))
    }

    pub fn reverse_connection_params(&self, spending_scripts: &[ScriptWithParams]) -> Result<ConnectionParams, ConfigError> {
        let template_from = self.template_from_params()?;
        let template_to = self.template_to_params()?;   

        Ok(ConnectionParams::new(
            template_to,
            template_from, 
            spending_scripts,   
        ))
    }
}

#[derive(Clone, Debug)]
pub struct TemplateParams {
    speedup_script: ScriptBuf,
    speedup_amount: u64,
    timelock_script: ScriptBuf,
    locked_amount: u64,
}

impl TemplateParams {
    pub fn new(speedup_script: ScriptBuf, speedup_amount: u64, timelock_script: ScriptBuf, locked_amount: u64) -> Self {
        TemplateParams {
            speedup_script,
            speedup_amount,
            timelock_script,
            locked_amount,
        }
    }

    pub fn get_speedup_script(&self) -> ScriptBuf {
        self.speedup_script.clone()
    }

    pub fn get_speedup_amount(&self) -> u64 {
        self.speedup_amount
    }

    pub fn get_timelock_script(&self) -> ScriptBuf {
        self.timelock_script.clone()
    }

    pub fn get_locked_amount(&self) -> u64 {
        self.locked_amount
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionParams {
    template_from: TemplateParams,
    template_to: TemplateParams,
    spending_scripts: Vec<ScriptWithParams>,
}

impl ConnectionParams {
    pub fn new(template_from: TemplateParams, template_to: TemplateParams, spending_scripts: &[ScriptWithParams]) -> Self {
        ConnectionParams {
            template_from,
            template_to,
            spending_scripts: spending_scripts.to_vec(),
        }
    }

    pub fn template_from(&self) -> TemplateParams {
        self.template_from.clone()
    }

    pub fn template_to(&self) -> TemplateParams {
        self.template_to.clone()
    }

    pub fn spending_scripts(&self) -> Vec<ScriptBuf> {
        self.spending_scripts.iter().map(|script| script.script().clone()).collect()
    }

    pub fn spending_scripts_with_params(&self) -> Vec<ScriptWithParams> {
        self.spending_scripts.clone()
    }
}

#[derive(Clone, Debug)]
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
