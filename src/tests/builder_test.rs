#[cfg(test)]
mod tests {
    use std::env;
    use bitcoin::{absolute, hashes::Hash, key::rand::RngCore, secp256k1, transaction, Amount, EcdsaSighashType, Network, PublicKey, ScriptBuf, TapSighashType, Transaction, Txid};
    use key_manager::{errors::KeyManagerError, key_manager::KeyManager, keystorage::database::DatabaseKeyStore, winternitz::{WinternitzPublicKey, WinternitzType}};
    use crate::{builder::TemplateBuilder, errors::TemplateBuilderError, params::DefaultParams, scripts::{self, ScriptWithParams}, template::InputType};
    use serde_json::json;
    #[test]
    fn test_single_connection() -> Result<(), TemplateBuilderError> {
        let protocol_amount = 2400000;
        let speedup_amount = 2400000;
        let locked_amount = 95000000;
        let end_amount = protocol_amount + locked_amount;

        let mut key_manager = test_key_manager()?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;
        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);

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

        // The second output has the total end amount
        let end_output = transaction_b.output.get(1).unwrap();
        assert_eq!(end_output.value, Amount::from_sat(end_amount));

        Ok(())
    }

    #[test]
    fn test_cyclic_template_connection() -> Result<(), TemplateBuilderError> {       
        let mut key_manager = test_key_manager()?;
        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;

        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);

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
        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;
        let pk = key_manager.derive_keypair(0)?;

        let (txid, vout, amount, script_pubkey) = previous_tx_info(pk);

        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
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
        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;
        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
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
        let verifying_key_0 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 0)?;
        let verifying_key_1 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 1)?;
        let verifying_key_2 = key_manager.derive_winternitz(4, WinternitzType::SHA256, 2)?;
        let spending_scripts = test_spending_scripts(&verifying_key_0, &verifying_key_1, &verifying_key_2);
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

    fn test_spending_scripts(verifying_key_1: &WinternitzPublicKey, verifying_key_2: &WinternitzPublicKey, verifying_key_3: &WinternitzPublicKey) -> Vec<ScriptWithParams> {
        vec![
            scripts::verify_single_value("x", verifying_key_1),
            scripts::verify_single_value("y", verifying_key_2),
            scripts::verify_single_value("z", verifying_key_3),
        ]
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

        let template_a = builder.get_template("A")?;

        assert_eq!(template_a.get_transaction().input.len(),1);
        assert_eq!(template_a.get_transaction().output.len(),1);
        assert_eq!(template_a.get_previous_outputs().len(),0);
        assert_eq!(template_a.get_next_inputs().len(),0);

        builder.add_connection("A", "B", &spending_scripts)?;

        let template_a = builder.get_template("A")?;
        assert_eq!(template_a.get_transaction().input.len(),1);
        assert_eq!(template_a.get_transaction().output.len(),3);
        assert_eq!(template_a.get_previous_outputs().len(),0);
        assert_eq!(template_a.get_next_inputs().len(),2);

        let template_b = builder.get_template("B")?;
        assert_eq!(template_b.get_transaction().input.len(),2);
        assert_eq!(template_b.get_transaction().output.len(),1);
        assert_eq!(template_b.get_previous_outputs().len(),2);
        assert_eq!(template_b.get_next_inputs().len(),0);

        builder.end("B", amount, &spending_scripts)?;

        let template_b = builder.get_template("B")?;

        assert_eq!(template_b.get_transaction().output.len(),2);

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

        let mut template_a = builder.get_template("A")?;

        assert!(template_a.compute_txid() != Hash::all_zeros());

        match template_a.get_inputs()[0].get_type() {
            InputType::P2WPKH {sighash, ..} => {
                assert!(sighash.is_some());
            },
            _ => panic!("Invalid input type"),
            
        }

        let mut template_b = builder.get_template("B")?;

        assert!(template_b.compute_txid() != Hash::all_zeros());

        match template_b.get_inputs()[0].get_type() {
            InputType::Taproot { spending_paths, .. } => {
                spending_paths.into_iter().for_each(|spending_path| {
                    assert!(spending_path.get_sighash().is_some());
                });
            },
            _ => panic!("Invalid input type"),
        }

        //let mut templates: Vec<Template> = builder.graph().templates()?.into_iter().map(|(_, template)| template).collect();
        // let signed_templates = sign_templates(&mut key_manager, &mut templates)?;

        // builder.graph().add_template("A", signed_templates[0].clone())?;
        // builder.graph().add_template("B", signed_templates[1].clone())?;

        // let template_a = builder.graph().get_template("A")?.unwrap();

        // match template_a.get_inputs()[0].get_type() {
        //     InputType::Taproot { spending_paths, .. } => {
        //         spending_paths.into_iter().for_each(|spending_path| {
        //             assert!(spending_path.get_signature().is_some());
        //         });
        //     },
        //     _ => panic!("Invalid input type"),
            
        // }

        // let template_b = builder.graph().get_template("B")?.unwrap();

        // match template_b.get_inputs()[0].get_type() {
        //     InputType::Taproot { spending_paths, .. } => {
        //         spending_paths.into_iter().for_each(|spending_path| {
        //             assert!(spending_path.get_signature().is_some());
        //         });
        //     },
        //     _ => panic!("Invalid input type"),
        // }


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
        builder.end("B", amount, &spending_scripts)?;

        builder.finalize_and_build()?;

        let binding = serde_json::to_string(&builder.get_template("A")?).unwrap();
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
}