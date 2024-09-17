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
            connection_params.get_lock_blocks(),
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
    /// The end output should use the total funds from the transaction, not just the protocol amount
    pub fn end(&mut self, name: &str, spending_conditions: &[ScriptWithParams]) -> Result<Output, TemplateBuilderError> {
        self.finalized = false;
        
        if !self.graph.contains_template(name)? {
            return Err(TemplateBuilderError::MissingTemplate(name.to_string()));
        }

        if self.graph.is_ended(name) {
            return Err(TemplateBuilderError::TemplateAlreadyEnded(name.to_string()));
        }

        self.graph.end_template(name);

        let protocol_amount = self.defaults.get_protocol_amount();
        let mut template = self.get_template(name)?;

        let (end_output, _) = template.push_output(protocol_amount, spending_conditions)?;
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

    fn get_template(&mut self, name: &str) -> Result<Template, TemplateBuilderError> {
        match self.graph.get_template(name)? {
            Some(template) => Ok(template),
            None => Err(TemplateBuilderError::MissingTemplate(name.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use bitcoin::{absolute, bip32::Xpub, key::rand::RngCore, secp256k1::{self, Message}, transaction, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, Txid, hashes::Hash};
    use key_manager::{errors::KeyManagerError, key_manager::KeyManager, keystorage::database::DatabaseKeyStore, verifier::SignatureVerifier, winternitz::{WinternitzPublicKey, WinternitzType}};
    use serde_json::json;
    use json_diff;
    use crate::{errors::TemplateBuilderError, params::DefaultParams, scripts::{self, ScriptWithParams}, template::{InputType, Template}};
    use super::TemplateBuilder;

    #[test]
    fn test_single_connection() -> Result<(), TemplateBuilderError> {
        let protocol_amount = 2400000;
        let speedup_amount = 2400000;
        let locked_amount = 95000000;

        let mut key_manager = test_key_manager()?;
        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
        let mut builder = test_template_builder()?;

        builder.add_start("A", txid, vout, amount, script_pubkey)?;
        builder.add_connection("A", "B", &spending_scripts)?;
        builder.end("B", &spending_scripts)?;

        let mut templates = builder.finalize_and_build()?;

        let mut key_manager = test_key_manager()?;
        let signed_templates = sign_templates(&mut key_manager, &mut templates)?;

        assert!(signed_templates.len() == 2);

        let template_a = signed_templates.iter().find(|template| template.get_name() == "A").unwrap();
        let next_inputs = template_a.get_next_inputs();
        assert_eq!(next_inputs.len(), 2);
        assert_eq!(next_inputs[0].get_to(), "B");
        assert_eq!(next_inputs[0].get_index(), 0);
        assert_eq!(next_inputs[1].get_to(), "B");
        assert_eq!(next_inputs[1].get_index(), 1);

        // We should have 3 outputs in the transaction, the speedup output, the timelocked output and the protocol output.
        let transaction_a = template_a.get_transaction();
        assert_eq!(transaction_a.output.len(), 3);

        // The first output has the speedup amount
        let speedup_output = transaction_a.output.first().unwrap();
        assert_eq!(speedup_output.value, Amount::from_sat(speedup_amount));

        // The second output has the locked amount
        let locked_output = transaction_a.output.get(1).unwrap();
        assert_eq!(locked_output.value, Amount::from_sat(locked_amount));
        
        // The third output has the protocol amount
        let protocol_output = transaction_a.output.get(2).unwrap();
        assert_eq!(protocol_output.value, Amount::from_sat(protocol_amount));

        let template_b = signed_templates.iter().find(|template| template.get_name() == "B").unwrap();

        assert_eq!(template_b.get_inputs().len(), 2);

        // The third output from A is the protocol output we will be consuming in B
        let previous_outputs = template_b.get_previous_outputs();        
        assert_eq!(previous_outputs.len(), 2);
        assert_eq!(previous_outputs[0].get_from(), "A");
        assert_eq!(previous_outputs[0].get_index(), 1);
        assert_eq!(previous_outputs[1].get_from(), "A");
        assert_eq!(previous_outputs[1].get_index(), 2);

        for input in template_b.get_inputs() {
            let verifying_key = input.get_verifying_key().unwrap();

            match input.get_type() {
                InputType::Taproot { spending_paths, .. } => {
                    for spending_path in spending_paths.values() {
                        let sighash = spending_path.get_sighash().unwrap();
                        let message = &Message::from(sighash);

                        assert!(SignatureVerifier::default().verify_schnorr_signature(
                            &spending_path.get_signature().unwrap().signature, 
                            message, 
                            verifying_key)
                        );
                    }
                },
                InputType::P2WPKH { sighash, signature, .. } => {
                    let message = &Message::from(sighash.unwrap());

                    assert!(SignatureVerifier::default().verify_ecdsa_signature(
                        &signature.unwrap().signature, 
                        message, 
                        verifying_key)
                    );
                }
            }
        }

        let transaction_b = template_b.get_transaction();
        assert_eq!(transaction_b.input.len(), 2);
        
        let protocol_input = transaction_b.input.first().unwrap();
        assert_eq!(protocol_input.previous_output.txid, template_a.get_transaction().compute_txid());

        // We should have 3 outputs in the transaction, the speedup output, the timelocked output and the protocol output.
        assert_eq!(transaction_b.output.len(), 2);

        // The first output has the speedup amount
        let speedup_output = transaction_b.output.first().unwrap();
        assert_eq!(speedup_output.value, Amount::from_sat(speedup_amount));
        
        // The second output has the end protocol amount
        let protocol_output = transaction_b.output.get(1).unwrap();
        assert_eq!(protocol_output.value, Amount::from_sat(protocol_amount));

        Ok(())
    }
    
    #[test]
    fn test_rounds() -> Result<(), TemplateBuilderError> {
        let rounds = 3;

        let mut key_manager = test_key_manager()?;
        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
        let spending_scripts_from = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
        let spending_scripts_to = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);

        let mut builder = test_template_builder()?;
        
        let (from_rounds, to_rounds) = builder.add_rounds(rounds, "B", "C", &spending_scripts_from, &spending_scripts_to)?;
        
        builder.add_start("A", txid, vout, amount, script_pubkey)?;
        builder.add_connection("A", &from_rounds, &spending_scripts)?;
        builder.end(&to_rounds, &spending_scripts)?;

        let templates = builder.finalize_and_build()?;
    
        assert!(templates.len() as u32 == rounds * 2 + 1);

        let mut template_names: Vec<String> = templates.iter().map(|t| t.get_name().to_string()).collect();
        template_names.sort();

        assert_eq!(&template_names, &["A", "B_0", "B_1", "B_2", "C_0", "C_1", "C_2"]);
        
        Ok(())
    }

    #[test]
    fn test_multiple_connections() -> Result<(), TemplateBuilderError> {
        let rounds = 3;

        let mut key_manager = test_key_manager()?;
        let master_xpub = key_manager.generate_master_xpub()?;
        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
        let spending_scripts_from = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
        let spending_scripts_to = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);

        let mut builder = test_template_builder()?;    

        builder.add_start("A", txid, vout, amount, script_pubkey)?;
        builder.add_connection("A", "B", &spending_scripts)?;
        builder.add_connection("A", "C", &spending_scripts)?;
        builder.add_connection("B", "D", &spending_scripts)?;
        builder.add_connection("C", "D", &spending_scripts)?;
        builder.add_connection("D", "E", &spending_scripts)?;
        builder.add_connection("A", "F", &spending_scripts)?;
        builder.add_connection("D", "F", &spending_scripts)?;
        builder.add_connection("F", "G", &spending_scripts)?;

        let (from_rounds, to_rounds) = builder.add_rounds(rounds, "H", "I", &spending_scripts_from, &spending_scripts_to)?;

        builder.add_connection("G", &from_rounds, &spending_scripts)?;
        builder.end(&to_rounds, &spending_scripts)?;
        builder.end("E", &spending_scripts)?;
    
        let mut templates = builder.finalize_and_build()?;
        let signed_templates = sign_templates(&mut key_manager, &mut templates)?;

        assert!(signed_templates.len() == 13);

        let mut template_names: Vec<String> = signed_templates.iter().map(|t| t.get_name().to_string()).collect();

        assert!(verify_templates_signatures(master_xpub, signed_templates)?);
        
        template_names.sort();

        assert_eq!(&template_names, &["A", "B", "C", "D", "E", "F", "G", "H_0", "H_1", "H_2", "I_0", "I_1", "I_2"]);

        Ok(())
    }

    #[test]
    fn test_starting_ending_templates() -> Result<(), TemplateBuilderError> {
        let mut key_manager = test_key_manager()?;
        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;
        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let mut builder = test_template_builder()?;

        builder.add_start("A", txid, vout, amount, script_pubkey.clone())?;
        builder.add_connection("A", "B", &spending_scripts)?;
        builder.end("B", &spending_scripts)?;

        // Ending a template twice should fail
        let result = builder.end("B", &spending_scripts);
        assert!(matches!(result, Err(TemplateBuilderError::TemplateAlreadyEnded(_))));

        // Adding a connection to an ended template should fail
        let result = builder.add_connection("C", "B", &spending_scripts);
        assert!(matches!(result, Err(TemplateBuilderError::TemplateEnded(_))));

        let result = builder.add_connection("B", "C", &spending_scripts);
        assert!(matches!(result, Err(TemplateBuilderError::TemplateEnded(_))));

        // Cannot end a template that doesn't exist in the graph
        let result = builder.end("C", &spending_scripts);
        assert!(matches!(result, Err(TemplateBuilderError::MissingTemplate(_))));

        // Cannot mark an existing template in the graph as the starting point
        let result = builder.add_start("B", txid, vout, amount, script_pubkey.clone());
        assert!(matches!(result, Err(TemplateBuilderError::TemplateAlreadyExists(_))));

        // Cannot start a template twice
        builder.add_start("D", txid, vout, amount, script_pubkey.clone())?;
        let result = builder.add_start("D", txid, vout, amount, script_pubkey);
        assert!(matches!(result, Err(TemplateBuilderError::TemplateAlreadyExists(_))));

        Ok(())
    }

    #[test]
    fn test_db() -> Result<(), TemplateBuilderError> {
        let mut key_manager = test_key_manager()?;
        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;
        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let mut builder = test_template_builder()?;

        builder.add_start("A", txid, vout, amount, script_pubkey)?;

        let template_a = builder.graph.get_template("A")?.unwrap();

        assert_eq!(template_a.get_transaction().input.len(),1);
        assert_eq!(template_a.get_transaction().output.len(),1);
        assert_eq!(template_a.get_previous_outputs().len(),0);
        assert_eq!(template_a.get_next_inputs().len(),0);

        builder.add_connection("A", "B", &spending_scripts)?;

        let template_a = builder.graph.get_template("A")?.unwrap();
        assert_eq!(template_a.get_transaction().input.len(),1);
        assert_eq!(template_a.get_transaction().output.len(),3);
        assert_eq!(template_a.get_previous_outputs().len(),0);
        assert_eq!(template_a.get_next_inputs().len(),2);

        let template_b = builder.graph.get_template("B")?.unwrap();
        assert_eq!(template_b.get_transaction().input.len(),2);
        assert_eq!(template_b.get_transaction().output.len(),1);
        assert_eq!(template_b.get_previous_outputs().len(),2);
        assert_eq!(template_b.get_next_inputs().len(),0);

        builder.end("B", &spending_scripts)?;

        let template_b = builder.graph.get_template("B")?.unwrap();
        match template_b.get_inputs()[0].get_type() {
            InputType::Taproot { spending_paths, .. } => {
                assert_eq!(spending_paths.len(), 2);
            },
            _ => panic!("Invalid input type"),
        }

        match template_b.get_inputs()[1].get_type() {
            InputType::Taproot { spending_paths, .. } => {
                assert_eq!(spending_paths.len(), 3);
            },
            _ => panic!("Invalid input type"),
        }

        builder.finalize_and_build()?;

        let mut template_a = builder.graph.get_template("A")?.unwrap();

        assert!(template_a.compute_txid() != Hash::all_zeros());

        match template_a.get_inputs()[0].get_type() {
            InputType::Taproot { spending_paths, .. } => {
                spending_paths.values().for_each(|spending_path| {
                    assert!(spending_path.get_sighash().is_some());
                });
            },
            _ => panic!("Invalid input type"),
            
        }

        let mut template_b = builder.graph.get_template("B")?.unwrap();

        assert!(template_b.compute_txid() != Hash::all_zeros());

        match template_b.get_inputs()[0].get_type() {
            InputType::Taproot { spending_paths, .. } => {
                spending_paths.values().for_each(|spending_path| {
                    assert!(spending_path.get_sighash().is_some());
                });
            },
            _ => panic!("Invalid input type"),
        }

        let mut templates: Vec<Template> = builder.graph.templates()?.into_iter().map(|(_, template)| template).collect();
        let signed_templates = sign_templates(&mut key_manager, &mut templates)?;

        builder.graph.add_template("A", signed_templates[0].clone())?;
        builder.graph.add_template("B", signed_templates[1].clone())?;

        let template_a = builder.graph.get_template("A")?.unwrap();

        match template_a.get_inputs()[0].get_type() {
            InputType::Taproot { spending_paths, .. } => {
                spending_paths.values().for_each(|spending_path| {
                    assert!(spending_path.get_signature().is_some());
                });
            },
            _ => panic!("Invalid input type"),
            
        }

        let template_b = builder.graph.get_template("B")?.unwrap();

        match template_b.get_inputs()[0].get_type() {
            InputType::Taproot { spending_paths, .. } => {
                spending_paths.values().for_each(|spending_path| {
                    assert!(spending_path.get_signature().is_some());
                });
            },
            _ => panic!("Invalid input type"),
        }


        Ok(())
    }

    #[test]
    fn test_json_diff()-> Result<(), TemplateBuilderError>  {
        let mut key_manager = test_key_manager()?;
        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
        let mut builder = test_template_builder()?;

        builder.add_start("A", txid, vout, amount, script_pubkey)?;
        builder.add_connection("A", "B", &spending_scripts)?;
        builder.end("B", &spending_scripts)?;

        builder.finalize_and_build()?;

        let binding = serde_json::to_string(&builder.graph.get_template("A")?).unwrap();
        let serialized_template = binding.as_str();

        let expected_output = json!({
            "name": "A",
            "txid": "13cc433a86a274f0a67382327b81a00f2afcb3e66c9c82d462e988026cdb3318",
            "transaction": {
                "version": 2,
                "lock_time": 0,
                "input": [
                    {
                        "previous_output": "4ebd325a4b394cff8c57e8317ccf5a8d0e2bdf1b8526f8aad6c8e43d8240621a:0",
                        "script_sig": "",
                        "sequence": 4294967293usize,
                        "witness": []
                    }
                ],
                "output": [
                    {
                        "value": 2400000,
                        "script_pubkey": "0014ff8136c7c37e32079002fc11cc6c921bc8213992"
                    },
                    {
                        "value": 95000000,
                        "script_pubkey": "5120cf5c6d2e754202ed30b22ba95bda9e59370dd7a5223258550e2c7b13a10d0d22"
                    },
                    {
                        "value": 2400000,
                        "script_pubkey": "51201b158a9163a2b24937004d426606596a005233288fe0147e7d1c4ad89613f10e"
                    }
                ]
            },
            "inputs": [
                {
                    "to": "A",
                    "index": 0,
                    "input_type": {
                        "ecdsa_sighash_type": "SIGHASH_ALL",
                        "script_pubkey": "0014ded2dc5803b2482dcdc2217c442a9f53a41f9785",
                        "sighash": "6d49070daeb02d4a073904ce10d22ae6281e7e3d617a10bfd4be4dae47e2cd2d",
                        "signature": null,
                        "amount": 100000
                    },
                    "signature_verifying_key": null
                }
            ],
            "previous_outputs": [],
            "next_inputs": [
                {
                    "to": "B",
                    "index": 0,
                    "input_type": {
                        "tap_sighash_type": "SIGHASH_ALL",
                        "spending_paths": {
                            "699f82e30ce44f8898497c2d0126525300d360063a7295aaa935553bef132ac9": {
                                "sighash": null,
                                "signature": null,
                                "script": "21022818a0495844fec90e7520732db6c970899c692b6e64e720f700f23309cb9fcbac",
                                "script_params": [
                                    {
                                        "name": "aggregated_signature",
                                        "verifying_key_index": 0,
                                        "verifying_key_type": "EcdsaPublicKey",
                                        "param_position": 0
                                    }
                                ]
                            },
                            "158e6db0f01e6e29875a5167a0f70a854c8c37391d07bfe7754a60aa074fedeb": {
                                "sighash": null,
                                "signature": null,
                                "script": "02c800b2752102e12df529c6015a45e1158bfc2fbf7e6b9c850a2c840e26323829afa66f50a764ac",
                                "script_params": [
                                    {
                                        "name": "timelock_expired_signature",
                                        "verifying_key_index": 0,
                                        "verifying_key_type": "EcdsaPublicKey",
                                        "param_position": 0
                                    }
                                ]
                            }
                        },
                        "taproot_internal_key": "0308674a40e681bbd5643ca981449f2c5d25960e516da7d724396929c838468d81"
                    },
                    "signature_verifying_key": null
                },
                {
                    "to": "B",
                    "index": 1,
                    "input_type": {
                        "tap_sighash_type": "SIGHASH_ALL",
                        "spending_paths": {
                            "a52a6b4c8110610f2ad7fe588db38517fa39ffb7921c56f14e40c689a536e394": {
                                "sighash": null,
                                "signature": null,
                                "script": "5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c79207b7a3d733842dd4bf54a64649138da1aa9b7a314f1386a56c233127fdfe97553886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920f53bf6edbdf299fe2d9a280327978279de592b55f395f1793910d03e66095917886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c79206832ac64d9158e5e16536d4aaa11369630cefafb819d129df67a0533a58c86d1886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920222e06fdcdb3ec72e86eb756c3ded738ac166160e539b5603e173be979c50acd886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c79202ece404a5a048b749a8a57fc9e38ab359a68819ed6eaec6bbfd5932859576a04886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920569dd55ebcc9f32410419a24ce059a0d72e312f6f0eeff3dff61fb11ac21f906886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920f17544dc4977e43adebb189d421f42ed80326279e3239996404ed3fbbf4c6a63886d6d6d6d6d6d6d6d6c768f6c7d946c7d946c7d94013c936c76937693769376936c9376937693769376936c93887c7693769376937693936b7c7693769376937693936c",
                                "script_params": [
                                    {
                                        "name": "z",
                                        "verifying_key_index": 0,
                                        "verifying_key_type": "WinternitzPublicKey",
                                        "param_position": 0
                                    }
                                ]
                            },
                            "6c03a78ecf45d05b1f92f2deb4edfe266028cf3bc94d4fc9af16626da4a616d7": {
                                "sighash": null,
                                "signature": null,
                                "script": "5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c792072815f71b0432df1a2afc8c7621f9fede3676af2edfe90f6fbc594103b7ad54b886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920aa4cfdd333780dbee07cff6b15bb0c3a9a9c6cc0c80991755006f494b55f8058886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920b59921c7a6966fe86ccd31e777ea32c840a8e2b4351260d6d10eb38e31419353886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c792046b451abc13dd00081fda115fea85f8004459f58bfe21dcbf97da2544c591b15886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920f64f67c9b0834a05300e03c241eadfe8da719d0c97d9965a6ee971815f2ffe7c886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920e0a37839669c5354e390183dcefa19a13212e116ebc29e484dfc7628a421c4c5886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c79202f90a86ae05401b54684d885b6f61fdb26f5ad8147bfc9939b3b0ba6e78b9f11886d6d6d6d6d6d6d6d6c768f6c7d946c7d946c7d94013c936c76937693769376936c9376937693769376936c93887c7693769376937693936b7c7693769376937693936c",
                                "script_params": [
                                    {
                                        "name": "y",
                                        "verifying_key_index": 0,
                                        "verifying_key_type": "WinternitzPublicKey",
                                        "param_position": 0
                                    }
                                ]
                            },
                            "c25bc6ac17d18935c34807a9637deaffcaf9a9df4879eed4c437825e73a4a270": {
                                "sighash": null,
                                "signature": null,
                                "script": "5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920b2b2715c53a3ad78feb4c124e57607cb49ad88ababcc0bbdcd57bbba77bdc6a7886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c79201709b8aa7fa3bf35e8c6d68186d4ee78930554639b67b61959014559e0dfd90a886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920b2b9d72a098c6869d3e10b4593d622b53183e6625d781e3d096c83c4392265b2886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920d94e6886033953e8ce87f1ac10ec1f10b28b211aae58d976595b3c4906583842886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920a5fa50a9ac3aeb30870a7e0b76bb9c9dba327f7cbe1d8f260c414999e8332b68886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c79206156ad251b72dbb6ab47bd68365f4d2b06f69ee43d611de9189676f14bf9eb10886d6d6d6d6d6d6d6d5fa3766b6b76a976a976a976a976a976a976a976a976a976a976a976a976a976a976a96c7920c8e1b538f0d3185dfd8b21bcff79a93158fea02db56821b0e2f14c08a9bda397886d6d6d6d6d6d6d6d6c768f6c7d946c7d946c7d94013c936c76937693769376936c9376937693769376936c93887c7693769376937693936b7c7693769376937693936c",
                                "script_params": [
                                    {
                                        "name": "x",
                                        "verifying_key_index": 0,
                                        "verifying_key_type": "WinternitzPublicKey",
                                        "param_position": 0
                                    }
                                ]
                            }
                        },
                        "taproot_internal_key": "0322e516c829231f61948e3b9e8187f22e9e9d5a840ca4ca6c1e48bba3a0193ccb"
                    },
                    "signature_verifying_key": null
                }
            ]
        }).to_string();

        assert!(json_diff::compare_jsons(&expected_output, &serialized_template).is_ok());

        Ok(())
    }
    
    fn test_template_builder() -> Result<TemplateBuilder, TemplateBuilderError> {
        let mut key_manager = test_key_manager()?;

        let master_xpub = key_manager.generate_master_xpub()?;

        let speedup_from_key = &key_manager.derive_public_key(master_xpub, 0)?;
        let speedup_to_key = &key_manager.derive_public_key(master_xpub, 1)?;
        let timelock_from_key = &key_manager.derive_public_key(master_xpub, 2)?;
        let timelock_to_key = &key_manager.derive_public_key(master_xpub, 3)?;
        // TODO This needs to be an aggregated key
        let timelock_renew_key = &key_manager.derive_public_key(master_xpub, 4)?;

        let protocol_amount = 2_400_000;
        let speedup_amount = 2_400_000;
        let locked_amount = 95_000_000;
        let locked_blocks: u16 = 200;
        let taproot_sighash_type = TapSighashType::All;
        let ecdsa_sighash_type = EcdsaSighashType::All;
        let graph_path = temp_storage_path();

        let defaults = DefaultParams::new(
            protocol_amount,
            speedup_from_key,
            speedup_to_key,
            speedup_amount,
            timelock_from_key,
            timelock_to_key,
            timelock_renew_key,
            locked_amount,
            locked_blocks,
            ecdsa_sighash_type,
            taproot_sighash_type,
            graph_path, 
        )?;

        let builder = TemplateBuilder::new(defaults)?;
        Ok(builder)
    }
    
    fn test_key_manager() -> Result<KeyManager<DatabaseKeyStore>, KeyManagerError> {
        let network = Network::Regtest;
        let keystore_path = temp_storage_path();
        let keystore_password = b"secret password".to_vec(); 
        let key_derivation_path: &str = "m/101/1/0/0/";
        let key_derivation_seed = random_bytes(); 
        let winternitz_seed = random_bytes();

        let database_keystore = DatabaseKeyStore::new(keystore_path, keystore_password, network)?;
        let key_manager = KeyManager::new(
            network,
            key_derivation_path,
            key_derivation_seed,
            winternitz_seed,
            database_keystore,
        )?;
    
        Ok(key_manager)
    }

    fn sign_templates<'a>(key_manager: &'a mut KeyManager<DatabaseKeyStore>, templates: &'a mut Vec<Template>) -> Result<&'a mut Vec<Template>, TemplateBuilderError> {
        for (index, template) in templates.iter_mut().enumerate() {
            let public_key = key_manager.derive_keypair(index as u32)?;
    
            for (input_index, input) in template.get_inputs().iter().enumerate() {
                match input.get_type() {
                    InputType::Taproot { sighash_type, spending_paths, .. } => {
                        for spending_path in spending_paths.values() {
                            let signature: secp256k1::schnorr::Signature = key_manager.sign_schnorr_message(&Message::from(spending_path.get_sighash().unwrap()), &public_key)?;
                            let taproot_signature = bitcoin::taproot::Signature{ signature, sighash_type: *sighash_type };
    
                            template.push_taproot_signature(input_index, &spending_path.get_taproot_leaf(), taproot_signature, &public_key)?;
                        }
                    },
                    InputType::P2WPKH { sighash, sighash_type, .. } => {
                        let signature: secp256k1::ecdsa::Signature = key_manager.sign_ecdsa_message(&Message::from(sighash.unwrap()), public_key)?;
                        let segwit_signature = bitcoin::ecdsa::Signature{ signature, sighash_type: *sighash_type };
    
                        template.push_ecdsa_signature(input_index, segwit_signature, &public_key)?;
                    }
                }
            }
        }
    
        Ok(templates)
    
        //taproot_signature.serialize().to_vec();
        //let mut sig_ser = signature.serialize_der().to_vec();
        //sig_ser.push(sighash_type as u8);
    }

    fn verify_templates_signatures(master_xpub: Xpub, signed_templates: &[Template]) -> Result<bool, TemplateBuilderError> {
        let  mut key_manager = test_key_manager()?;

        for (index, template) in signed_templates.iter().enumerate() {
            let public_key = key_manager.derive_public_key(master_xpub, index as u32)?;
    
            for input in template.get_inputs().iter() {
                match input.get_type() {
                    InputType::Taproot { spending_paths, .. } => {
                        for spending_path in spending_paths.values() {
                            let message = &Message::from(spending_path.get_sighash().unwrap());
                            if !SignatureVerifier::default().verify_schnorr_signature(&spending_path.get_signature().unwrap().signature, message, public_key) {
                                return Ok(false);
                            }
                        }
                    },
                    InputType::P2WPKH { sighash, signature, .. } => {
                        let message = &Message::from(sighash.unwrap());
                        if !SignatureVerifier::default().verify_ecdsa_signature(&signature.unwrap().signature, message, public_key) {
                            return Ok(false);
                        }
                    }
                }
            }
        }
    
        Ok(true)
    }

    fn previous_tx_info(pk: PublicKey) -> (Txid, u32, u64, ScriptBuf) {
        let amount = 100000;
        let wpkh = pk.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        let previous_tx = Transaction {
            version: transaction::Version::TWO, 
            lock_time: absolute::LockTime::ZERO, 
            input: vec![],             
            output: vec![],          
        };

        (previous_tx.compute_txid(), 0, amount, script_pubkey)
    }

    fn random_bytes() -> [u8; 32] {
        let mut seed = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut seed);
        seed
    }

    fn random_u32() -> u32 {
        secp256k1::rand::thread_rng().next_u32()
    }

    fn temp_storage_path() -> String {
        let dir = env::temp_dir();

        let storage_path = dir.join(format!("secure_storage_{}.db", random_u32()));
        storage_path.to_str().expect("Failed to get path to temp file").to_string()
    }

    fn test_spending_scripts(verifying_key0: &WinternitzPublicKey, verifying_key1: &WinternitzPublicKey, verifying_key2: &WinternitzPublicKey) -> Vec<ScriptWithParams> {
        vec![
            scripts::verify_single_value("x", verifying_key0),
            scripts::verify_single_value("y", verifying_key1),
            scripts::verify_single_value("z", verifying_key2),
        ]
    }
}
