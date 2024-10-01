use bitcoin::{EcdsaSighashType, ScriptBuf, TapSighashType, Transaction, Txid};

use crate::{errors::TemplateBuilderError, graph::Graph, params::{ConnectionParams, DefaultParams, RoundParams, TemplateParams}, scripts::ScriptWithParams, template::{Output, Template}};

pub struct TemplateBuilder {
    graph: Graph,
    defaults: DefaultParams,
    finalized: bool,
}

impl TemplateBuilder {
    pub fn new(defaults: DefaultParams) -> Result<Self, TemplateBuilderError> {
        let graph =  match Graph::new(defaults.graph_path()) {
            Ok(graph) => graph,
            Err(e) => return Err(TemplateBuilderError::GraphBuildingError(e))
        };
        let builder = TemplateBuilder {
            graph,
            defaults,
            finalized: false,
        };

        Ok(builder)
    }

    /// Creates a new template as the starting point of the DAG. 
    /// Short version of the start method, it uses the seedup scripts from the config.
    pub fn add_start(&mut self, name: &str, previous_tx: Txid, vout: u32, amount: u64, script_pubkey: ScriptBuf) -> Result<(), TemplateBuilderError> {
        let template_params = self.defaults.template_from_params()?;
        let sighash_type = self.defaults.get_ecdsa_sighash_type();
        self.start(name, sighash_type, previous_tx, vout, amount, script_pubkey, template_params)
    }

    /// Creates a connection between two templates. 
    /// Short version of the connect method, it uses the seedup scripts from the config.
    pub fn add_connection(&mut self, from: &str, to: &str, spending_scripts: &[ScriptWithParams]) -> Result<(), TemplateBuilderError> {
        let connection_params = self.defaults.connection_params(spending_scripts)?;
        self.connect(from, to, self.defaults.get_protocol_amount(), self.defaults.get_taproot_sighash_type(), connection_params)
    }

    /// Creates a connection between two templates for a given number of rounds creating the intermediate templates to complete the DAG. 
    /// Short version of the connect_rounds method, it uses the seedup scripts from the config.
    pub fn add_rounds(&mut self, rounds: u32, from: &str, to: &str, spending_scripts_from: &[ScriptWithParams], spending_scripts_to: &[ScriptWithParams]) -> Result<(String, String), TemplateBuilderError> {         
        let direct_connection = self.defaults.connection_params(spending_scripts_from)?;
        let reverse_connection = self.defaults.reverse_connection_params(spending_scripts_to)?;

        let round_params = RoundParams::new(direct_connection, reverse_connection);
        
        self.connect_rounds(rounds, from, to, self.defaults.get_protocol_amount(), self.defaults.get_taproot_sighash_type(), round_params)
    }   

    /// Creates a new template as the starting point of the DAG.
    pub fn start(&mut self, name: &str, sighash_type: EcdsaSighashType, previous_tx: Txid, vout: u32, amount: u64, script_pubkey: ScriptBuf, template_params: TemplateParams) -> Result<(), TemplateBuilderError> {
        check_empty_template_name(name)?;

        self.finalized = false;

        if self.graph.contains_template(name)? {
            return Err(TemplateBuilderError::TemplateAlreadyExists(name.to_string()));
        }
        
        let mut 
        template = self.add_or_create_template(name, template_params)?;
        template.push_start_input(sighash_type, previous_tx, vout, amount, script_pubkey);
        self.graph.add_template(name, template)?;
        Ok(())
    }

    /// Creates a connection between two templates.
    pub fn connect(&mut self, from: &str, to: &str, protocol_amount: u64, sighash_type: TapSighashType, connection_params: ConnectionParams) -> Result<(), TemplateBuilderError> {
        check_empty_template_name(from)?;
        check_empty_template_name(to)?;
        check_empty_scripts(&connection_params.spending_scripts_with_params())?;
        
        self.finalized = false;

        if self.graph.is_ended(from) {
            return Err(TemplateBuilderError::TemplateEnded(from.to_string()));
        }
        
        if self.graph.is_ended(to) {
            return Err(TemplateBuilderError::TemplateEnded(to.to_string()));
        }

        // Add timelock connection
        self.connect_protocol(
            from, to, 
            connection_params.get_locked_amount(), 
            0,
            sighash_type, 
            connection_params.template_from(), 
            connection_params.template_to(), 
            &connection_params.timelock_scripts()
        )?;

        // Add protocol connection
        self.connect_protocol(
            from, to, 
            protocol_amount, 
            0,
            sighash_type, 
            connection_params.template_from(), 
            connection_params.template_to(), 
            &connection_params.spending_scripts_with_params()
        )?;

        Ok(())
    }

    fn connect_protocol(&mut self, from: &str, to: &str, connection_amount: u64, locked_blocks: u16, sighash_type: TapSighashType, from_params: TemplateParams, to_params: TemplateParams, spending_scripts: &[ScriptWithParams]) -> Result<(), TemplateBuilderError> {
        let mut from_template = self.add_or_create_template(from, from_params)?;
        let (output, taproot_spend_info) = from_template.push_output(connection_amount, spending_scripts)?;
        self.graph.add_template(from, from_template)?;
   
        // Create the to template if it doesn't exist and push the input that will spend the previously created output
        let mut to_template = self.add_or_create_template(to, to_params)?;
        let next_input = to_template.push_taproot_input(sighash_type, output, locked_blocks, taproot_spend_info, spending_scripts);
        self.graph.add_template(to, to_template)?;

        // Add to the from_template the recently created next input for later updates of the txid in connected inputs
        let mut template = self.get_template(from)?;
        template.push_next_input(next_input);
        self.graph.add_template(from, template)?;
      
        // Connect the templates in the graph
        self.graph.connect(from, to)?;

        Ok(())
    }

    /// Creates a connection between two templates for a given number of rounds creating the intermediate templates to complete the DAG.
    pub fn connect_rounds(&mut self, rounds: u32, from: &str, to: &str, protocol_amount: u64, sighash_type: TapSighashType, round_params: RoundParams) -> Result<(String, String), TemplateBuilderError> {
        check_zero_rounds(rounds)?;
        check_empty_template_name(from)?;
        check_empty_template_name(to)?;
        check_empty_scripts(&round_params.direct_connection().spending_scripts_with_params())?;
        check_empty_scripts(&round_params.reverse_connection().spending_scripts_with_params())?;
        
        // To create the names for the intermediate templates in the rounds. We will use the following format: {name}_{round}.
        let mut from_round;
        let mut to_round;

        // In each round we will connect the from template to the to template and then the to template to the from template.
        // we need to do this because the templates are connected in a DAG.
        for round in 0..rounds - 1{
            // Create the new names for the intermediate templates in the direct connection (from -> to).
            from_round = format!("{0}_{1}", from, round);
            to_round = format!("{0}_{1}", to, round);

            // Connection between the from and to templates using the spending_scripts_from.
            self.connect(&from_round, &to_round, protocol_amount, sighash_type, round_params.direct_connection())?;

            // Create the new names for the intermediate templates in the reverse connection (to -> from).
            from_round = format!("{0}_{1}", from, round + 1);
            to_round = format!("{0}_{1}", to, round);

            // Reverse connection between the to and from templates using the spending_scripts_to.
            self.connect(&to_round, &from_round, protocol_amount, sighash_type, round_params.reverse_connection())?;
        };

        // We don't need the last reverse connection, thus why we perform the last direct connection outside the loop.
        // Create the new names for the last direct connection (from -> to).
        from_round = format!("{0}_{1}", from, rounds - 1);
        to_round = format!("{0}_{1}", to, rounds - 1);

        // Last direct connection using spending_scripts_from.
        self.connect(&from_round, &to_round, protocol_amount, sighash_type, round_params.direct_connection())?;

        Ok((format!("{0}_{1}", from, 0), to_round))
    }

    /// Marks an existing template as one end of the DAG. It will create an output that later could be spent by any transaction outside the DAG.
    /// The end output should use the total funds from the transaction, minus fees, not just the protocol amount
    pub fn end(&mut self, name: &str, amount: u64, spending_scripts: &[ScriptWithParams]) -> Result<Output, TemplateBuilderError> {
        check_empty_template_name(name)?;
        check_empty_scripts(spending_scripts)?;
        
        self.finalized = false;
        
        if !self.graph.contains_template(name)? {
            return Err(TemplateBuilderError::MissingTemplate(name.to_string()));
        }

        if self.graph.is_ended(name) {
            return Err(TemplateBuilderError::TemplateAlreadyEnded(name.to_string()));
        }

        self.graph.end_template(name);

        let mut template = self.get_template(name)?;

        let (end_output, _) = template.push_output(amount, spending_scripts)?;
        self.graph.add_template(name, template)?;

        Ok(end_output)
    }
    
    /// It marks the DAG as finalized, and triggers an ordered update of the txids of each template in the DAG.
    pub fn finalize(&mut self) -> Result<(), TemplateBuilderError> {
        self.finalized = true;
        self.update_inputs()?;
        Ok(())
    }

    /// After marking the DAG as finalized with all the txids updated, it computes the spend signature hashes for each template.
    pub fn build_templates(&mut self) -> Result<Vec<Template>, TemplateBuilderError> {
        if !self.finalized {
            return Err(TemplateBuilderError::NotFinalized.into());
        }

        for (key,mut template) in self.graph.templates()? {
            template.compute_spend_signature_hashes()?;
            self.graph.add_template(&key, template)?;
        } 

        match self.graph.templates() {
            Ok(transactions) => {
                let transactions: Vec<Template> = transactions.into_iter().map(|(_, template)| template).collect();
                Ok(transactions)
            },
            Err(e) => Err(TemplateBuilderError::GraphBuildingError(e)),
            
        }
    }

    /// Finalizes the DAG and builds the templates in one step.
    pub fn finalize_and_build(&mut self) -> Result<Vec<Template>, TemplateBuilderError> {
        self.finalize()?;
        self.build_templates()
    }

    /// Returns the transactions of the finalized templates.
    pub fn get_transactions(&self) -> Result<Vec<Transaction>, TemplateBuilderError> {
        if !self.finalized {
            return Err(TemplateBuilderError::NotFinalized);
        }

        match self.graph.templates() {
            Ok(transactions) => {
                let transactions: Vec<Transaction> = transactions.into_iter().map(|(_, template)| template.get_transaction()).collect();
                Ok(transactions)
            },
            Err(e) => Err(TemplateBuilderError::GraphBuildingError(e)),
            
        }
    }

    /// Resets the builder to its initial state discarding all the templates and the graph.
    pub fn reset(&mut self) -> Result<(), TemplateBuilderError>{
        self.graph = match Graph::new(self.defaults.graph_path()) {
            Ok(graph) => graph,
            Err(e) => return Err(TemplateBuilderError::GraphBuildingError(e))
        };
        self.finalized = false;

        Ok(())
    }

    /// Adds a new template to the templates HashMap and the graph if it doesn't exist, otherwise it returns the existing template.

    fn add_or_create_template(&mut self, name: &str, template_params: TemplateParams) -> Result<Template, TemplateBuilderError> {
        if !self.graph.contains_template(name)? {
            let template = Template::new(
                name, 
                &template_params.get_speedup_script(), 
                template_params.get_speedup_amount(), 
            );

            self.graph.add_template(name, template)?;
        }

        self.get_template(name)
    }

    /// Updates the txids of each template in the DAG in topological order.
    /// It will update the txid of the template and the txid of the connected inputs.
    fn update_inputs(&mut self) -> Result <(), TemplateBuilderError> {
        let sorted_templates = self.graph.sort()?;

        for from in sorted_templates {
            let mut template = self.get_template(&from)?;
            let txid = template.compute_txid();
            
            for input in template.get_next_inputs(){
                let mut input_template = self.get_template(input.get_to())?;
                input_template.update_input(input.get_index(), txid);
                self.graph.add_template(input.get_to(), input_template)?;  
            }

            self.graph.add_template(&from, template)?;
        }

        Ok(())
    }

    pub fn get_template(&mut self, name: &str) -> Result<Template, TemplateBuilderError> {
        match self.graph.get_template(name)? {
            Some(template) => Ok(template),
            None => Err(TemplateBuilderError::MissingTemplate(name.to_string())),
        }
    }
}

fn check_empty_scripts(spending_scripts: &[ScriptWithParams]) -> Result<(), TemplateBuilderError> {
    if spending_scripts.is_empty() {
        return Err(TemplateBuilderError::EmptySpendingScripts);
    }
    
    Ok(())
}

fn check_empty_template_name(name: &str) -> Result<(), TemplateBuilderError> {
    if name.trim().is_empty() || name.chars().all(|c| c == '\t') {
        return Err(TemplateBuilderError::MissingTemplateName);
    }
    
    Ok(())
}

fn check_zero_rounds(rounds: u32) -> Result<(), TemplateBuilderError> {
    if rounds == 0 {
        return Err(TemplateBuilderError::InvalidZeroRounds);
    }
    Ok(())
}
