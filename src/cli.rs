use anyhow::{Ok, Result};

use bitcoin::{hashes::Hash, Amount, EcdsaSighashType, ScriptBuf};
use clap::{Parser, Subcommand};
use tracing::info;

use crate::{builder::Builder, config::Config, graph::{OutputSpendingType, SighashType}};

pub struct Cli {
    pub config: Config,
}

#[derive(Parser)]
#[command(about = "Template Builder CLI", long_about = None)]
#[command(arg_required_else_help = true)]
pub struct Menu {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    AddStartTemplate,
}

impl Cli {
    pub fn new() -> Result<Self> {
        let config = Config::new()?;
        Ok(Self {
            config,
        })
    }

    pub fn run(&self) -> Result<()> {
        let menu = Menu::parse();

        match &menu.command {
            Commands::AddStartTemplate => {
                //self.add_start_template()?;
            }
        }

        Ok(())
    }

    // 
    // Commands
    //TODO: Implement CLI commands
    // }
}
