#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, secp256k1, Amount, EcdsaSighashType, ScriptBuf, TapSighashType};

    use crate::{builder::{Builder, SpendingArgs}, errors::ProtocolBuilderError, graph::{OutputSpendingType, SighashType}, unspendable::unspendable_key};

    #[test]
    fn test_single_connection() -> Result<(), ProtocolBuilderError> {
        let mut rng = secp256k1::rand::thread_rng();
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let internal_key = unspendable_key(&mut rng)?;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let blocks = 100;

        let expired_from = ScriptBuf::from(vec![0x00]);
        let renew_from = ScriptBuf::from(vec![0x01]);
        let expired_to = ScriptBuf::from(vec![0x00]);
        let renew_to = ScriptBuf::from(vec![0x01]);
        let script = ScriptBuf::from(vec![0x00]);

        let output_spending_type = OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let scripts_from = vec![ScriptBuf::from(vec![0x00]), ScriptBuf::from(vec![0x00])];
        let scripts_to = vec![ScriptBuf::from(vec![0x00]), ScriptBuf::from(vec![0x00])];

        let mut builder = Builder::new("single_connection"); 
        let protocol = builder.connect_with_external_transaction(txid, output_index, output_spending_type, "start", &ecdsa_sighash_type)?
            .add_taproot_script_spend_connection("protocol", "start", value, &internal_key, &scripts_from, "challenge", &sighash_type)?
            .add_timelock_connection("start", value, &internal_key, &expired_from, &renew_from, "challenge", blocks, &sighash_type)?
            .add_taproot_script_spend_connection("protocol", "challenge", value, &internal_key, &scripts_to, "response", &sighash_type)?
            .add_timelock_connection("challenge", value, &internal_key, &expired_to, &renew_to, "response", blocks, &sighash_type)?
            .build()?;

        let start = protocol.get_transaction_to_send("start", &[SpendingArgs::new_args()])?;
        let challenge = protocol.get_transaction_to_send("challenge", &[SpendingArgs::new_taproot_args(&script), SpendingArgs::new_taproot_args(&script)])?;
        let response = protocol.get_transaction_to_send("response", &[SpendingArgs::new_taproot_args(&script), SpendingArgs::new_taproot_args(&script)])?;

        assert_eq!(start.input.len(), 1);
        assert_eq!(challenge.input.len(), 2);
        assert_eq!(response.input.len(), 2);

        assert_eq!(start.output.len(), 2);
        assert_eq!(challenge.output.len(), 2);
        assert_eq!(response.output.len(), 0);

        let sighashes_start = protocol.get_sighashes("start")?;
        let sighashes_challenge = protocol.get_sighashes("challenge")?;
        let sighashes_response = protocol.get_sighashes("response")?;

        assert_eq!(sighashes_start.len(), 1);
        assert_eq!(sighashes_challenge.len(), 2);
        assert_eq!(sighashes_response.len(), 2);

        Ok(())
    }

    #[test]
    fn test_single_cyclic_connection() -> Result<(), ProtocolBuilderError> {       
        let mut rng = secp256k1::rand::thread_rng();
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let internal_key = unspendable_key(&mut rng)?;
        let spending_scripts = vec![ScriptBuf::from(vec![0x00]), ScriptBuf::from(vec![0x00])];

        let mut builder = Builder::new("cycle");
            builder.add_taproot_script_spend_connection("cycle", "A", value, &internal_key, &spending_scripts, "A", &sighash_type)?;

        let result = builder.build();

        match result {
            Err(ProtocolBuilderError::GraphBuildingError(_graph_error)) => {
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
    fn test_multiple_cyclic_connection() -> Result<(), ProtocolBuilderError> {
        let mut rng = secp256k1::rand::thread_rng();
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let internal_key = unspendable_key(&mut rng)?;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let script = ScriptBuf::from(vec![0x00]);

        let output_spending_type = OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let scripts_from = vec![ScriptBuf::from(vec![0x00]), ScriptBuf::from(vec![0x00])];
        let scripts_to = vec![ScriptBuf::from(vec![0x00]), ScriptBuf::from(vec![0x00])];

        let mut builder = Builder::new("cycle"); 
        let result = builder.connect_with_external_transaction(txid, output_index, output_spending_type, "A", &ecdsa_sighash_type)?
            .add_taproot_script_spend_connection("protocol", "A", value, &internal_key, &scripts_from, "B", &sighash_type)?
            .add_taproot_script_spend_connection("protocol", "B", value, &internal_key, &scripts_to, "C", &sighash_type)?
            .add_taproot_script_spend_connection("protocol", "C", value, &internal_key, &scripts_to, "A", &sighash_type)?
            .build();

        match result {
            Err(ProtocolBuilderError::GraphBuildingError(_graph_error)) => {
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
    fn test_single_node_no_connections() -> Result<(), ProtocolBuilderError> {
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let script = ScriptBuf::from(vec![0x00]);
        let output_spending_type = OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let mut builder = Builder::new("single_connection"); 
        let protocol = builder
            .connect_with_external_transaction(txid, output_index, output_spending_type, "start", &ecdsa_sighash_type)?
            .build()?;

        let start = protocol.get_transaction_to_send("start", &[SpendingArgs::new_args()])?;

        assert_eq!(start.input.len(), 1);
        assert_eq!(start.output.len(), 0);

        let sighashes_start = protocol.get_sighashes("start")?;

        assert_eq!(sighashes_start.len(), 1);
        
        Ok(())
    }

    #[test]
    fn test_rounds() -> Result<(), ProtocolBuilderError> {
        let rounds = 3;
        let mut rng = secp256k1::rand::thread_rng();
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let internal_key = unspendable_key(&mut rng)?;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let script = ScriptBuf::from(vec![0x00]);
        let output_spending_type = OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let mut builder = Builder::new("rounds");
        let (from_rounds, _) = builder.connect_rounds("rounds", rounds, "B", "C", value, &[script.clone()], &[script.clone()], &sighash_type)?;

        let protocol = builder
            .connect_with_external_transaction(txid, output_index, output_spending_type, "A", &ecdsa_sighash_type)?
            .add_taproot_script_spend_connection("protocol", "A", value, &internal_key, &[script.clone()], &from_rounds, &sighash_type)?
            .build()?;

        let a = protocol.get_transaction_to_send("A", &[SpendingArgs::new_args()])?;
        let b0 = protocol.get_transaction_to_send("B_0", &[SpendingArgs::new_taproot_args(&script), SpendingArgs::new_taproot_args(&script)])?;
        let b1 = protocol.get_transaction_to_send("B_1", &[SpendingArgs::new_taproot_args(&script), SpendingArgs::new_taproot_args(&script)])?;
        let b2 = protocol.get_transaction_to_send("B_2", &[SpendingArgs::new_taproot_args(&script), SpendingArgs::new_taproot_args(&script)])?;
        let c0 = protocol.get_transaction_to_send("C_0", &[SpendingArgs::new_taproot_args(&script), SpendingArgs::new_taproot_args(&script)])?;
        let c1 = protocol.get_transaction_to_send("C_1", &[SpendingArgs::new_taproot_args(&script), SpendingArgs::new_taproot_args(&script)])?;
        let c2 = protocol.get_transaction_to_send("C_2", &[SpendingArgs::new_taproot_args(&script), SpendingArgs::new_taproot_args(&script)])?;

        assert_eq!(a.input.len(), 1);
        assert_eq!(b0.input.len(), 1);
        assert_eq!(b1.input.len(), 1);
        assert_eq!(b2.input.len(), 1);

        assert_eq!(a.output.len(), 1);
        assert_eq!(c0.output.len(), 1);
        assert_eq!(c1.output.len(), 1);
        assert_eq!(c2.output.len(), 0);

        let sighashes_a = protocol.get_sighashes("A")?;
        let sighashes_b0 = protocol.get_sighashes("B_0")?;
        let sighashes_b1 = protocol.get_sighashes("B_1")?;
        let sighashes_b2 = protocol.get_sighashes("B_2")?;
        let sighashes_c0 = protocol.get_sighashes("C_0")?;
        let sighashes_c1 = protocol.get_sighashes("C_1")?;
        let sighashes_c2 = protocol.get_sighashes("C_2")?;

        assert_eq!(sighashes_a.len(), 1);
        assert_eq!(sighashes_b0.len(), 1);
        assert_eq!(sighashes_b1.len(), 1);
        assert_eq!(sighashes_b2.len(), 1);
        assert_eq!(sighashes_c0.len(), 1);
        assert_eq!(sighashes_c1.len(), 1);
        assert_eq!(sighashes_c2.len(), 1);
        
        Ok(())
    }

    #[test]
    fn test_zero_rounds() -> Result<(), ProtocolBuilderError> {
        let rounds = 0;
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let script = ScriptBuf::from(vec![0x00]);

        let mut builder = Builder::new("rounds");
        let result = builder.connect_rounds("rounds", rounds, "B", "C", value, &[script.clone()], &[script.clone()], &sighash_type);

        match result {
            Err(ProtocolBuilderError::InvalidZeroRounds) => {
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
    fn test_multiple_connections() -> Result<(), ProtocolBuilderError> {
        let rounds = 3;
        let mut rng = secp256k1::rand::thread_rng();
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let internal_key = unspendable_key(&mut rng)?;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let script = ScriptBuf::from(vec![0x00]);
        let output_spending_type = OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let mut builder = Builder::new("rounds");
        builder
            .connect_with_external_transaction(txid, output_index, output_spending_type, "A", &ecdsa_sighash_type)?
            .add_taproot_script_spend_connection("protocol", "A", value, &internal_key, &[script.clone()], "B", &sighash_type)?
            .add_taproot_script_spend_connection("protocol", "A", value, &internal_key, &[script.clone()], "C", &sighash_type)?
            .add_taproot_script_spend_connection("protocol", "B", value, &internal_key, &[script.clone()], "D", &sighash_type)?
            .add_taproot_script_spend_connection("protocol", "C", value, &internal_key, &[script.clone()], "D", &sighash_type)?
            .add_taproot_script_spend_connection("protocol", "D", value, &internal_key, &[script.clone()], "E", &sighash_type)?
            .add_taproot_script_spend_connection("protocol", "A", value, &internal_key, &[script.clone()], "F", &sighash_type)?
            .add_taproot_script_spend_connection("protocol", "D", value, &internal_key, &[script.clone()], "F", &sighash_type)?
            .add_taproot_script_spend_connection("protocol", "F", value, &internal_key, &[script.clone()], "G", &sighash_type)?;

        let (from_rounds, to_rounds) = builder.connect_rounds("rounds", rounds, "H", "I", value, &[script.clone()], &[script.clone()], &sighash_type)?;
        
        builder.add_taproot_script_spend_connection("protocol", "G", value, &internal_key, &[script.clone()], &from_rounds, &sighash_type)?
            .add_p2wpkh_output(&to_rounds, value, &internal_key)?;

        let protocol = builder.build()?;
        let mut transaction_names = protocol.get_transaction_names();
        transaction_names.sort();

        assert_eq!(&transaction_names, &["A", "B", "C", "D", "E", "F", "G", "H_0", "H_1", "H_2", "I_0", "I_1", "I_2"]);

        Ok(())
    }


}