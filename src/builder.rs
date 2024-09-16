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

        // Create the from template if it doesn't exist and push the output that will be spent
        let mut from_template = self.add_or_create_template(from, connection_params.template_from())?;
        let (output, taproot_spend_info) = from_template.push_output(protocol_amount, &connection_params.spending_scripts_with_params())?;
        self.graph.add_template(from, from_template)?;

        // Create the to template if it doesn't exist and push the input that will spend the previously created output
        let mut to_template = self.add_or_create_template(to, connection_params.template_to())?;
        let next_input = to_template.push_taproot_input(sighash_type, output, taproot_spend_info,&connection_params.spending_scripts_with_params());
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

        let (output, _) = template.push_output(protocol_amount, spending_conditions)?;

        self.graph.add_template(name, template)?;

        Ok(output)
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
            self.graph.add_template(key.trim_start_matches("template_"), template)?;
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
                &template_params.get_timelock_script(), 
                template_params.get_locked_amount()
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
    use bitcoin::{absolute, bip32::Xpub, consensus, key::rand::{random, RngCore}, secp256k1::{self, Message}, transaction, Address, Amount, CompressedPublicKey, EcdsaSighashType, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, Txid};
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use key_manager::{errors::KeyManagerError, key_manager::KeyManager, keystorage::database::DatabaseKeyStore, verifier::SignatureVerifier, winternitz::{WinternitzPublicKey, WinternitzType}};
    use crate::{errors::{TemplateBuilderError, TestClientError}, params::DefaultParams, scripts::{self, ScriptWithParams}, template::{InputType, SpendingParams, Template}};
    use super::TemplateBuilder;

    const ONE_BTC: Amount = Amount::from_sat(100_000_000); // 1 BTC

    struct TestClient {
        network: Network,
        client: Client,
        wallet_address: Address,
    }
    
    impl TestClient {
        fn new(network: Network, url: &str, user: &str, pass: &str, wallet_name: &str) -> Result<Self, TestClientError> {
            let client = Client::new(
                url,
                Auth::UserPass(
                    user.to_string(),
                    pass.to_string(),
                ),
            ).map_err(|e| TestClientError::FailedToCreateClient{ error: e.to_string() })?;
    
            let wallet_address = Self::init_wallet(network, wallet_name, &client)?;
    
            Ok(Self {
                network,
                client,
                wallet_address,
            })
        }   
    
        pub fn fund_address(&self, address: &Address, amount: Amount) -> Result<(Txid, u32), TestClientError> {
            // send BTC to address
            let txid = self.client.send_to_address(
                address,
                amount,
                None,
                None,
                None,
                None,
                None,
                None,
            ).map_err(|e| TestClientError::FailedToFundAddress{ error: e.to_string() })?;
        
            // mine a block to confirm transaction
            self.client.generate_to_address(1, &self.wallet_address)
                .map_err(|e| TestClientError::FailedToMineBlocks{ error: e.to_string() })?;
        
            // get transaction details
            let tx_info = self.client.get_transaction(&txid, Some(true))
                .map_err(|e| TestClientError::FailedToGetTransactionDetails{ error: e.to_string() })?;
    
            let vout = tx_info
            .details
            .first()
            .expect("No details found for transaction")
            .vout;

            let txid = tx_info.info.txid;

            Ok((txid, vout))
        }
    
        pub fn send_transaction(&self, tx: Transaction) -> Result<(), TestClientError> {
            let serialized_tx = consensus::encode::serialize_hex(&tx);
            self.client.send_raw_transaction(serialized_tx)
                .map_err(|e| TestClientError::FailedToSendTransaction { error: e.to_string() })?;
    
            Ok(())
        }

        pub fn get_new_address(&self, pk: PublicKey) -> Address {
            let compressed = CompressedPublicKey::try_from(pk).unwrap();
            let address = Address::p2wpkh(&compressed, self.network).as_unchecked().clone();
            address.clone().require_network(self.network).unwrap()
        }
    
        fn init_wallet(network: Network, wallet_name: &str, rpc: &Client) -> Result<Address, TestClientError> {
            let _ = match rpc.create_wallet(wallet_name, None, None, None, None) {
                Ok(r) => r,
                Err(e) => return Err(TestClientError::FailedToCreateWallet{ error: e.to_string() }),
            };
        
            let wallet = rpc
                .get_new_address(None, None)
                .map_err(|e| TestClientError::FailedToGetNewAddress{ error: e.to_string() })?
                .require_network(network)
                .map_err(|e| TestClientError::FailedToGetNewAddress{ error: e.to_string() })?;
        
            rpc.generate_to_address(105, &wallet)
                .map_err(|e| TestClientError::FailedToMineBlocks{ error: e.to_string() })?;
        
            Ok(wallet)
        }
    }

    #[test]
    fn test_single_connection() -> Result<(), TemplateBuilderError> {
        let protocol_amount = 200;
        let speedup_amount = 9_999_859;
        let locked_amount = 5_000_000_000;

        let mut key_manager = test_key_manager()?;
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = dummy_spending_scripts(&verifying_key);

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

        for input in template_b.get_inputs() {
            let verifying_key = input.get_verifying_key().unwrap();

            match input.get_type() {
                InputType::Taproot { spending_paths, .. } => {
                    for spending_info in spending_paths.values() {
                        let sighash = spending_info.get_sighash().unwrap();
                        let message = &Message::from(sighash);

                        assert!(SignatureVerifier::default().verify_schnorr_signature(
                            &spending_info.get_signature().unwrap().signature, 
                            message, 
                            verifying_key)
                        );
                    }
                },
                InputType::Segwit { sighash, signature, .. } => {
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
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = dummy_spending_scripts(&verifying_key);
        let spending_scripts_from = dummy_spending_scripts(&verifying_key);
        let spending_scripts_to = dummy_spending_scripts(&verifying_key);

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
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = dummy_spending_scripts(&verifying_key);
        let spending_scripts_from = dummy_spending_scripts(&verifying_key);
        let spending_scripts_to = dummy_spending_scripts(&verifying_key);

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
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let spending_scripts = dummy_spending_scripts(&verifying_key);
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
    fn test() -> Result<(), TemplateBuilderError>{
        let network = Network::Regtest;

        let mut key_manager = test_key_manager()?;
        let mut builder = test_template_builder()?;

        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let spending_scripts = dummy_spending_scripts(&verifying_key);
        
        let pk = key_manager.derive_keypair(0)?;
        let wpkh = pk.wpubkey_hash().expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&wpkh);

        let client = test_client(network)?;
        let user_address = client.get_new_address(pk);
        let (previous_tx, vout) = client.fund_address(&user_address, ONE_BTC).unwrap();

        builder.add_start("start", previous_tx, vout, ONE_BTC.to_sat(), script_pubkey)?;
        builder.add_connection("start", "end", &spending_scripts)?;
        builder.end("end", &spending_scripts)?;

        let mut templates = builder.finalize_and_build()?;
        let signed_templates = sign_templates(&mut key_manager, &mut templates)?;

        for template in signed_templates {
            let param: Vec<u8> = vec![32, 33, 34, 35];
            let spending_leaf = spending_scripts[0].get_script();
            let params = SpendingParams::new(0, spending_leaf.clone(), vec![param]);

            let tx = template.get_transaction_for_spending_path(params)?;
            let _ = client.send_transaction(tx);
        }
    
        Ok(())
    } 

    fn test_client(network: Network) -> Result<TestClient, TestClientError> {
        let url = "http://127.0.0.1:18443";
        let user = "foo";
        let pass = "rpcpassword";
        let wallet = "test_wallet";

        TestClient::new(network, url, user, pass, wallet)
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
        let taproot_sighash_type = TapSighashType::All;
        let ecdsa_sighash_type = EcdsaSighashType::All;
        let graph_path = temp_storage_path();

        println!("graph_path: {}", graph_path);

        let defaults = DefaultParams::new(
            protocol_amount, 
            speedup_from_key, 
            speedup_to_key, 
            speedup_amount, 
            timelock_blocks, 
            timelock_from_key, 
            timelock_to_key, 
            locked_amount, 
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
    
            for (input_index, input) in template.get_inputs().iter().enumerate() {
                match input.get_type() {
                    InputType::Taproot { sighash_type, spending_paths, .. } => {
                        for spending_info in spending_paths.values() {
                            let signature: secp256k1::schnorr::Signature = key_manager.sign_schnorr_message(&Message::from(spending_info.get_sighash().unwrap()), &public_key)?;
                            let taproot_signature = bitcoin::taproot::Signature{ signature, sighash_type: *sighash_type };
    
                            template.push_taproot_signature(input_index, &spending_info.get_taproot_leaf(), taproot_signature, &public_key)?;
                        }
                    },
                    InputType::Segwit { sighash, sighash_type, .. } => {
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
                        for spending_info in spending_paths.values() {
                            let message = &Message::from(spending_info.get_sighash().unwrap());
                            if !SignatureVerifier::default().verify_schnorr_signature(&spending_info.get_signature().unwrap().signature, message, public_key) {
                                return Ok(false);
                            }
                        }
                    },
                    InputType::Segwit { sighash, signature, .. } => {
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

    fn dummy_spending_scripts(verifying_key: &WinternitzPublicKey) -> Vec<ScriptWithParams> {
        vec![
            scripts::verify_single_value("x", verifying_key),
            scripts::verify_single_value("y", verifying_key),
            scripts::verify_single_value("z", verifying_key),
        ]
    }
}
