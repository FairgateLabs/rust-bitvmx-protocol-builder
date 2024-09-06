use bitcoin::{TapSighashType, Transaction};

use crate::{errors::TemplateBuilderError, graph::Graph, params::{ConnectionParams, DefaultParams, RoundParams, TemplateParams}, scripts::ScriptWithParams, template::{PreviousOutput, Template}, templates::Templates};

pub struct TemplateBuilder {
    graph: Graph,
    templates: Templates,
    defaults: DefaultParams,
    finalized: bool,
}

impl TemplateBuilder {
    pub fn new(defaults: DefaultParams) -> Result<Self, TemplateBuilderError> {
        let builder = TemplateBuilder {
            graph: Graph::new(),
            templates: Templates::new(),
            defaults,
            finalized: false,
        };

        Ok(builder)
    }

    /// Creates a new template as the starting point of the DAG. 
    /// Short version of the start method, it uses the seedup scripts from the config.
    pub fn add_start(&mut self, name: &str) -> Result<(), TemplateBuilderError> {
        let template_params = self.defaults.template_from_params()?;
        self.start(name, template_params)
    }

    /// Creates a connection between two templates. 
    /// Short version of the connect method, it uses the seedup scripts from the config.
    pub fn add_connection(&mut self, from: &str, to: &str, spending_scripts: &[ScriptWithParams]) -> Result<(), TemplateBuilderError> {
        let connection_params = self.defaults.connection_params(spending_scripts)?;
        self.connect(from, to, self.defaults.get_protocol_amount(), self.defaults.get_sighash_type(), connection_params)
    }

    /// Creates a connection between two templates for a given number of rounds creating the intermediate templates to complete the DAG. 
    /// Short version of the connect_rounds method, it uses the seedup scripts from the config.
    pub fn add_rounds(&mut self, rounds: u32, from: &str, to: &str, spending_scripts_from: &[ScriptWithParams], spending_scripts_to: &[ScriptWithParams]) -> Result<(String, String), TemplateBuilderError> { 
        let direct_connection = self.defaults.connection_params(spending_scripts_from)?;
        let reverse_connection = self.defaults.reverse_connection_params(spending_scripts_to)?;

        let round_params = RoundParams::new(direct_connection, reverse_connection);
        
        self.connect_rounds(rounds, from, to, self.defaults.get_protocol_amount(), self.defaults.get_sighash_type(), round_params)
    }   

    /// Creates a new template as the starting point of the DAG.
    pub fn start(&mut self, name: &str, template_params: TemplateParams) -> Result<(), TemplateBuilderError> {
        self.finalized = false;

        if self.templates.contains_template(name) {
            return Err(TemplateBuilderError::TemplateAlreadyExists(name.to_string()));
        }
        
        self.add_or_create_template(name, template_params)?;
        Ok(())
    }

    /// Creates a connection between two templates.
    pub fn connect(&mut self, from: &str, to: &str, protocol_amount: u64, sighash_type: TapSighashType, connection_params: ConnectionParams) -> Result<(), TemplateBuilderError> {
        self.finalized = false;

        if self.templates.is_ended(from) {
            return Err(TemplateBuilderError::TemplateEnded(from.to_string()));
        }
        
        if self.templates.is_ended(to) {
            return Err(TemplateBuilderError::TemplateEnded(to.to_string()));
        }

        // Create the from template if it doesn't exist and push the output that will be spent
        let from_template = self.add_or_create_template(from, connection_params.template_from())?;
        let output = from_template.push_output(protocol_amount, &connection_params.spending_scripts_with_params())?;

        // Create the to template if it doesn't exist and push the input that will spend the previously created output
        let to_template = self.add_or_create_template(to, connection_params.template_to())?;
        let next_input = to_template.push_input(sighash_type, output, &connection_params.spending_scripts_with_params());

        // Add to the from_template the recently created next input for later updates of the txid in connected inputs
        self.get_template_mut(from)?.push_next_input(next_input);

        // Connect the templates in the graph
        self.graph.add_edge(from, to);

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
    pub fn end(&mut self, name: &str, spending_conditions: &[ScriptWithParams]) -> Result<PreviousOutput, TemplateBuilderError> {
        self.finalized = false;
        
        if !self.templates.contains_template(name) {
            return Err(TemplateBuilderError::MissingTemplate(name.to_string()));
        }

        if self.templates.is_ended(name) {
            return Err(TemplateBuilderError::TemplateAlreadyEnded(name.to_string()));
        }

        self.templates.end_template(name);

        let protocol_amount = self.defaults.get_protocol_amount();
        let template = self.get_template_mut(name)?;

        Ok(template.push_output(protocol_amount, spending_conditions)?)
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
            return Err(TemplateBuilderError::NotFinalized);
        }

        for template in self.templates.templates_mut() {
            template.compute_spend_signature_hashes()?;
        } 

        Ok(self.templates.templates().cloned().collect())
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
        
        Ok(self.templates.templates().map(|template| template.get_transaction()).collect())
    }

    /// Resets the builder to its initial state discarding all the templates and the graph.
    pub fn reset(&mut self) {
        self.graph = Graph::new();
        self.templates = Templates::new();
        self.finalized = false;
    }

    /// Adds a new template to the templates HashMap and the graph if it doesn't exist, otherwise it returns the existing template.
    fn add_or_create_template(&mut self, name: &str, template_params: TemplateParams) -> Result<&mut Template, TemplateBuilderError> {
        if !self.templates.contains_template(name) {
            let template = Template::new(
                name, 
                &template_params.get_speedup_script(), 
                template_params.get_speedup_amount(), 
                &template_params.get_timelock_script(), 
                template_params.get_locked_amount()
            );

            self.templates.add_template(name, template);
            self.graph.add_node(name);
        }

        self.get_template_mut(name)
    }

    /// Updates the txids of each template in the DAG in topological order.
    /// It will update the txid of the template and the txid of the connected inputs.
    fn update_inputs(&mut self) -> Result <(), TemplateBuilderError> {
        let sorted_templates = self.graph.topological_sort()?;

        for from in sorted_templates {
            let template = self.get_template_mut(&from)?;
            let txid = template.compute_txid();
            
            for input in template.get_next_inputs(){
                let template = self.get_template_mut(input.get_to())?;
                template.update_input(input.get_index(), txid);   
            }
        }

        Ok(())
    }

    fn get_template_mut(&mut self, name: &str) -> Result<&mut Template, TemplateBuilderError> {
        match self.templates.get_template_mut(name) {
            Some(template) => Ok(template),
            None => Err(TemplateBuilderError::MissingTemplate(name.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use bitcoin::{bip32::Xpub, key::rand::{random, RngCore}, secp256k1::{self, Message}, taproot::Signature, Amount, Network, TapSighashType};
    use key_manager::{errors::KeyManagerError, key_manager::KeyManager, keystorage::database::DatabaseKeyStore, verifier::SignatureVerifier, winternitz::{WinternitzPublicKey, WinternitzType}};
    use crate::{errors::TemplateBuilderError, params::DefaultParams, scripts::{self, ScriptWithParams}, template::Template};
    use super::TemplateBuilder;

    #[test]
    fn test_single_connection() -> Result<(), TemplateBuilderError> {
        let protocol_amount = 200;
        let speedup_amount = 9_999_859;
        let locked_amount = 5_000_000_000;

        let mut key_manager = test_key_manager()?;
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;

        let spending_scripts = dummy_spending_scripts(&verifying_key);

        let mut builder = test_template_builder()?;

        builder.add_start("A")?;
        builder.add_connection("A", "B", &spending_scripts)?;
        builder.end("B", &spending_scripts)?;

        let mut templates = builder.finalize_and_build()?;

        let mut key_manager = test_key_manager()?;
        let signed_templates = sign_templates(&mut key_manager, &mut templates)?;

        assert!(signed_templates.len() == 2);

        let template_a = signed_templates.iter().find(|template| template.get_name() == "A").unwrap();
        let next_inputs = template_a.get_next_inputs();
        assert_eq!(next_inputs.len(), 1);
        assert_eq!(next_inputs[0].get_to(), "B");
        assert_eq!(next_inputs[0].get_index(), 0);

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

        assert_eq!(template_b.get_inputs().len(), 1);

        // The third output from A is the protocol output we will be consuming in B
        let previous_outputs = template_b.get_previous_outputs();        
        assert_eq!(previous_outputs.len(), 1);
        assert_eq!(previous_outputs[0].get_from(), "A");
        assert_eq!(previous_outputs[0].get_index(), 2);

        for spending_info in template_b.get_inputs() {
            let verifying_key = spending_info.get_verifying_key().unwrap();
            for spending_path in spending_info.get_spending_paths() {
                let sighash = spending_path.get_sighash().unwrap();
                let message = &Message::from(sighash);

                assert!(SignatureVerifier::default().verify_schnorr_signature(
                    &spending_path.get_signature().unwrap().signature, 
                    message, 
                    verifying_key)
                );
            }
        }

        let transaction_b = template_b.get_transaction();
        assert_eq!(transaction_b.input.len(), 1);
        
        let protocol_input = transaction_b.input.first().unwrap();
        assert_eq!(protocol_input.previous_output.txid, template_a.get_transaction().compute_txid());

        // We should have 3 outputs in the transaction, the speedup output, the timelocked output and the protocol output.
        assert_eq!(transaction_b.output.len(), 3);

        // The first output has the speedup amount
        let speedup_output = transaction_b.output.first().unwrap();
        assert_eq!(speedup_output.value, Amount::from_sat(speedup_amount));

        // The second output has the locked amount
        let locked_output = transaction_b.output.get(1).unwrap();
        assert_eq!(locked_output.value, Amount::from_sat(locked_amount));
        
        // The third output has the protocol amount
        let protocol_output = transaction_b.output.get(2).unwrap();
        assert_eq!(protocol_output.value, Amount::from_sat(protocol_amount));

        Ok(())
    }

    #[test]
    fn test_rounds() -> Result<(), TemplateBuilderError> {
        let rounds = 3;

        let mut key_manager = test_key_manager()?;
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;

        let spending_scripts = dummy_spending_scripts(&verifying_key);
        let spending_scripts_from = dummy_spending_scripts(&verifying_key);
        let spending_scripts_to = dummy_spending_scripts(&verifying_key);

        let mut builder = test_template_builder()?;
        
        let (from_rounds, to_rounds) = builder.add_rounds(rounds, "B", "C", &spending_scripts_from, &spending_scripts_to)?;
        
        builder.add_start("A")?;
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
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
     
        let spending_scripts = dummy_spending_scripts(&verifying_key);
        let spending_scripts_from = dummy_spending_scripts(&verifying_key);
        let spending_scripts_to = dummy_spending_scripts(&verifying_key);

        let mut builder = test_template_builder()?;    

        builder.add_start("A")?;
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
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let spending_scripts = dummy_spending_scripts(&verifying_key);

        let mut builder = test_template_builder()?;

        builder.add_start("A")?;
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
        let result = builder.add_start("B");
        assert!(matches!(result, Err(TemplateBuilderError::TemplateAlreadyExists(_))));

        // Cannot start a template twice
        builder.add_start("D")?;
        let result = builder.add_start("D");
        assert!(matches!(result, Err(TemplateBuilderError::TemplateAlreadyExists(_))));

        Ok(())
    }

    fn test_template_builder() -> Result<TemplateBuilder, TemplateBuilderError> {
        let mut key_manager = test_key_manager()?;

        let master_xpub = key_manager.generate_master_xpub()?;

        let speedup_from_key = &key_manager.derive_public_key(master_xpub, 0)?;
        let speedup_to_key = &key_manager.derive_public_key(master_xpub, 1)?;
        let timelock_from_key = &key_manager.derive_public_key(master_xpub, 2)?;
        let timelock_to_key = &key_manager.derive_public_key(master_xpub, 2)?;

        let protocol_amount = 200;
        let speedup_amount = 9_999_859;
        let timelock_blocks: u8 = 100;
        let locked_amount = 5_000_000_000;
        let sighash_type = TapSighashType::All;

        let defaults = DefaultParams::new(
            protocol_amount, 
            speedup_from_key, 
            speedup_to_key, 
            speedup_amount, 
            timelock_blocks, 
            timelock_from_key, 
            timelock_to_key, 
            locked_amount, 
            sighash_type
        )?;

        let builder = TemplateBuilder::new(defaults)?;
        Ok(builder)
    }
    
    fn test_key_manager() -> Result<KeyManager<DatabaseKeyStore>, KeyManagerError> {
        let network = Network::Regtest;
        let keystore_path = temp_storage_path();
        let keystore_password = b"secret password".to_vec(); 
        let key_derivation_path: &str = "m/101/1/0/0/";
        let key_derivation_seed = random(); 
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
    
            for (input_index, spending_info) in template.get_inputs().iter().enumerate() {
                for spending_path in spending_info.get_spending_paths() {
                    let signature: secp256k1::schnorr::Signature = key_manager.sign_schnorr_message(&Message::from(spending_path.get_sighash().unwrap()), &public_key)?;
                    let taproot_signature = Signature{ signature, sighash_type: spending_path.get_sighash_type() };

                    template.push_signature(input_index, spending_path, taproot_signature, &public_key);
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
    
            for spending_info in template.get_inputs().iter() {
                for spending_path in spending_info.get_spending_paths() {
                    let message = &Message::from(spending_path.get_sighash().unwrap());
                    if !SignatureVerifier::default().verify_schnorr_signature(&spending_path.get_signature().unwrap().signature, message, public_key) {
                        return Ok(false);
                    }
                }
            }
        }
    
        Ok(true)
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

    fn dummy_spending_scripts(verifying_key: &WinternitzPublicKey) -> Vec<ScriptWithParams> {
        vec![
            scripts::verify_single_value("x", verifying_key),
            scripts::verify_single_value("y", verifying_key),
            scripts::verify_single_value("z", verifying_key),
        ]
    }
}
