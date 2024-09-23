#[cfg(test)]
mod tests {
    use std::env;
    use bitcoin::{absolute, key::rand::RngCore, secp256k1, transaction, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, Txid};
    use key_manager::{errors::KeyManagerError, key_manager::KeyManager, keystorage::database::DatabaseKeyStore, winternitz::{WinternitzPublicKey, WinternitzType}};
    use crate::{builder::TemplateBuilder, errors::TemplateBuilderError, params::DefaultParams, scripts::{self, ScriptWithParams}};

    #[test]
    fn test_single_connection() -> Result<(), TemplateBuilderError> {
        let protocol_amount = 2400000;
        let speedup_amount = 2400000;
        let locked_amount = 95000000;
        let end_amount = protocol_amount + locked_amount;

        let mut key_manager = test_key_manager()?;
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = test_spending_scripts(&verifying_key);

        let mut builder = test_template_builder()?;

        builder.add_start("A", txid, vout, amount, script_pubkey)?;
        builder.add_connection("A", "B", &spending_scripts)?;
        builder.end("B", end_amount, &spending_scripts)?;

        let templates = builder.finalize_and_build()?;

        let template_a = templates.iter().find(|template| template.get_name() == "A").unwrap();
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

        let template_b = templates.iter().find(|template| template.get_name() == "B").unwrap();

        assert_eq!(template_b.get_inputs().len(), 2);

        // The third output from A is the protocol output we will be consuming in B
        let previous_outputs = template_b.get_previous_outputs();        
        assert_eq!(previous_outputs.len(), 2);
        assert_eq!(previous_outputs[0].get_from(), "A");
        assert_eq!(previous_outputs[0].get_index(), 1);
        assert_eq!(previous_outputs[1].get_from(), "A");
        assert_eq!(previous_outputs[1].get_index(), 2);

        let transaction_b = template_b.get_transaction();
        assert_eq!(transaction_b.input.len(), 2);
        
        let protocol_input = transaction_b.input.first().unwrap();
        assert_eq!(protocol_input.previous_output.txid, template_a.get_transaction().compute_txid());

        // We should have 3 outputs in the transaction, the speedup output, the timelocked output and the protocol output.
        assert_eq!(transaction_b.output.len(), 2);

        // The first output has the speedup amount
        let speedup_output = transaction_b.output.first().unwrap();
        assert_eq!(speedup_output.value, Amount::from_sat(speedup_amount));
        
        println!("{:#?}", transaction_b);

        // The second output has the total end amount
        let end_output = transaction_b.output.get(1).unwrap();
        assert_eq!(end_output.value, Amount::from_sat(end_amount));

        Ok(())
    }

    #[test]
    fn test_cyclic_template_connection() -> Result<(), TemplateBuilderError> {       
        let mut key_manager = test_key_manager()?;
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;

        let spending_scripts = test_spending_scripts(&verifying_key);

        let mut builder = test_template_builder()?;

        builder.add_connection("A", "A", &spending_scripts)?;

        let result = builder.finalize_and_build();

        match result {
            Err(TemplateBuilderError::GraphBuildingError(_graph_error)) => {
            }
            Err(_) => {
                panic!("Expected GraphCycleDetected error, got a different error");
            }
            Ok(_) => {
                panic!("Expected an error, but got Ok");
            }
        }    

        Ok(())
    }

    #[test]
    fn test_multiples_templates_cyclic_connection() -> Result<(), TemplateBuilderError> {
        let end_amount = 98000000;
        let mut key_manager = test_key_manager()?;
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = test_spending_scripts(&verifying_key);

        let mut builder = test_template_builder()?;

        builder.add_start("A", txid, vout, amount, script_pubkey)?;
        builder.add_connection("A", "B", &spending_scripts)?;
        builder.add_connection("B", "C", &spending_scripts)?;
        builder.add_connection("C", "A", &spending_scripts)?;
        builder.end("C", end_amount, &spending_scripts)?;

        let result = builder.finalize_and_build();

        match result {
            Err(TemplateBuilderError::GraphBuildingError(_graph_error)) => {
            }
            Err(_) => {
                panic!("Expected GraphCycleDetected error, got a different error");
            }
            Ok(_) => {
                panic!("Expected an error, but got Ok");
            }
        }    
        
        Ok(())
    }

    #[test]
    fn test_single_node_no_connections() -> Result<(), TemplateBuilderError> {
        let mut key_manager = test_key_manager()?;
        let pk = key_manager.derive_keypair(0)?;
        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);
        let mut builder = test_template_builder()?;
        
        builder.add_start("A", txid, vout, amount, script_pubkey)?;
        let templates = builder.finalize_and_build()?;

        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].get_name(), "A");
        assert_eq!(templates[0].get_previous_outputs().is_empty(), true);
        assert_eq!(templates[0].get_next_inputs().is_empty(), true);
        
        Ok(())
    }
    
    #[test]
    fn test_rounds() -> Result<(), TemplateBuilderError> {
        let rounds = 3;
        let end_amount = 98000000;

        let mut key_manager = test_key_manager()?;
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = test_spending_scripts(&verifying_key);
        let spending_scripts_from = test_spending_scripts(&verifying_key);
        let spending_scripts_to = test_spending_scripts(&verifying_key);

        let mut builder = test_template_builder()?;
        
        let (from_rounds, to_rounds) = builder.add_rounds(rounds, "B", "C", &spending_scripts_from, &spending_scripts_to)?;
        
        builder.add_start("A", txid, vout, amount, script_pubkey)?;
        builder.add_connection("A", &from_rounds, &spending_scripts)?;
        builder.end(&to_rounds, end_amount, &spending_scripts)?;

        let templates = builder.finalize_and_build()?;
    
        assert!(templates.len() as u32 == rounds * 2 + 1);

        let mut template_names: Vec<String> = templates.iter().map(|t| t.get_name().to_string()).collect();
        template_names.sort();

        assert_eq!(&template_names, &["A", "B_0", "B_1", "B_2", "C_0", "C_1", "C_2"]);
        
        Ok(())
    }

    #[test]
    fn test_zero_rounds() -> Result<(), TemplateBuilderError> {
        let mut key_manager = test_key_manager()?;
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;

        let spending_scripts = test_spending_scripts(&verifying_key);
        let mut builder = test_template_builder()?;

        let result = builder.add_rounds(0, "A", "B", &spending_scripts, &spending_scripts);

        match result {
            Err(TemplateBuilderError::InvalidZeroRounds) => {
            }
            Err(_) => {
                panic!("Expected InvalidZeroRounds error, got a different error");
            }
            Ok(_) => {
                panic!("Expected an error, but got Ok");
            }
        }
        Ok(())
    }

    #[test]
    fn test_multiple_connections() -> Result<(), TemplateBuilderError> {
        let rounds = 3;
        let end_amount = 98000000;

        let mut key_manager = test_key_manager()?;
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = test_spending_scripts(&verifying_key);
        let spending_scripts_from = test_spending_scripts(&verifying_key);
        let spending_scripts_to = test_spending_scripts(&verifying_key);

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
        builder.end(&to_rounds, end_amount, &spending_scripts)?;
        builder.end("E", end_amount, &spending_scripts)?;
    
        let templates = builder.finalize_and_build()?;
        let mut template_names: Vec<String> = templates.iter().map(|t| t.get_name().to_string()).collect();
        template_names.sort();

        assert_eq!(&template_names, &["A", "B", "C", "D", "E", "F", "G", "H_0", "H_1", "H_2", "I_0", "I_1", "I_2"]);

        Ok(())
    }

    #[test]
    fn test_starting_ending_templates() -> Result<(), TemplateBuilderError> {
        let mut key_manager = test_key_manager()?;
        let verifying_key = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let spending_scripts = test_spending_scripts(&verifying_key);
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let end_amount = 98000000;

        let mut builder = test_template_builder()?;

        builder.add_start("A", txid, vout, amount, script_pubkey.clone())?;
        builder.add_connection("A", "B", &spending_scripts)?;
        builder.end("B", end_amount, &spending_scripts)?;

        // Ending a template twice should fail
        let result = builder.end("B", end_amount, &spending_scripts);
        assert!(matches!(result, Err(TemplateBuilderError::TemplateAlreadyEnded(_))));

        // Adding a connection to an ended template should fail
        let result = builder.add_connection("C", "B", &spending_scripts);
        assert!(matches!(result, Err(TemplateBuilderError::TemplateEnded(_))));

        let result = builder.add_connection("B", "C", &spending_scripts);
        assert!(matches!(result, Err(TemplateBuilderError::TemplateEnded(_))));

        // Cannot end a template that doesn't exist in the graph
        let result = builder.end("C", end_amount, &spending_scripts);
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

    fn test_spending_scripts(verifying_key: &WinternitzPublicKey) -> Vec<ScriptWithParams> {
        vec![
            scripts::verify_single_value("x", verifying_key),
            scripts::verify_single_value("y", verifying_key),
            scripts::verify_single_value("z", verifying_key),
        ]
    }
}