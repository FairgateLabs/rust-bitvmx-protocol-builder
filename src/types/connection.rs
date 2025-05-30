use bitcoin::{hashes::Hash, Sequence, Txid};
use serde::{Deserialize, Serialize};

use super::{
    input::{SighashType, SpendMode},
    OutputType,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputSpec {
    Index(usize),
    Auto(SighashType, SpendMode),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputSpec {
    Index(usize),
    Auto(OutputType),
    Last,
}

impl Into<OutputSpec> for OutputType {
    fn into(self) -> OutputSpec {
        OutputSpec::Auto(self)
    }
}

impl Into<OutputSpec> for usize {
    fn into(self) -> OutputSpec {
        OutputSpec::Index(self)
    }
}

impl Into<InputSpec> for usize {
    fn into(self) -> InputSpec {
        InputSpec::Index(self)
    }
}

pub enum ConnectionType {
    Internal {
        from: String,
        output: OutputSpec,
        to: String,
        input: InputSpec,
        timelock: Option<u16>,
    },
    External {
        txid: Txid,
        from: String,
        output: OutputSpec,
        to: String,
        input: InputSpec,
        timelock: Option<u16>,
    },
}

impl ConnectionType {
    pub fn internal(
        from: &str,
        output: OutputSpec,
        to: &str,
        input: InputSpec,
        timelock: Option<u16>,
    ) -> Self {
        ConnectionType::Internal {
            from: from.to_string(),
            output,
            to: to.to_string(),
            input,
            timelock,
        }
    }

    pub fn external(
        txid: Txid,
        from: &str,
        output: OutputSpec,
        to: &str,
        input: InputSpec,
        timelock: Option<u16>,
    ) -> Self {
        ConnectionType::External {
            txid,
            from: from.to_string(),
            output,
            to: to.to_string(),
            input,
            timelock,
        }
    }

    pub fn txid(&self) -> Txid {
        match self {
            ConnectionType::External { txid, .. } => *txid,
            _ => Hash::all_zeros(),
        }
    }

    pub fn from(&self) -> &str {
        match self {
            ConnectionType::Internal { from, .. } | ConnectionType::External { from, .. } => from,
        }
    }

    pub fn to(&self) -> &str {
        match self {
            ConnectionType::Internal { to, .. } | ConnectionType::External { to, .. } => to,
        }
    }

    pub fn output(&self) -> &OutputSpec {
        match self {
            ConnectionType::Internal { output, .. } | ConnectionType::External { output, .. } => {
                output
            }
        }
    }

    pub fn input(&self) -> &InputSpec {
        match self {
            ConnectionType::Internal { input, .. } | ConnectionType::External { input, .. } => {
                input
            }
        }
    }

    pub fn sequence(&self) -> Sequence {
        match self {
            ConnectionType::Internal { timelock, .. }
            | ConnectionType::External { timelock, .. } => {
                if let Some(timelock) = timelock {
                    Sequence::from_height(*timelock)
                } else {
                    Sequence::ENABLE_RBF_NO_LOCKTIME
                }
            }
        }
    }

    pub fn external_connection(&self) -> bool {
        matches!(self, ConnectionType::External { .. })
    }
}
