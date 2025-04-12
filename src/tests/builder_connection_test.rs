#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::Hash, Amount, EcdsaSighashType, ScriptBuf, TapSighashType, XOnlyPublicKey,
    };
    use std::rc::Rc;
    use storage_backend::storage::Storage;

    use crate::{
        builder::{ProtocolBuilder, SpendingArgs},
        errors::ProtocolBuilderError,
        graph::{input::SighashType, output::OutputType},
        scripts::ProtocolScript,
        tests::utils::{new_key_manager, TemporaryDir},
    };

    #[test]
    fn test_single_connection() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_single_connection");

        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let blocks = 100;

        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let public_key = key_manager.derive_keypair(0).unwrap();
        let internal_key = XOnlyPublicKey::from(public_key);

        let expired_from = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key);
        let renew_from = ProtocolScript::new(ScriptBuf::from(vec![0x01]), &public_key);
        let expired_to = ProtocolScript::new(ScriptBuf::from(vec![0x02]), &public_key);
        let renew_to = ProtocolScript::new(ScriptBuf::from(vec![0x03]), &public_key);
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let script_a = ProtocolScript::new(ScriptBuf::from(vec![0x05]), &public_key);
        let script_b = ProtocolScript::new(ScriptBuf::from(vec![0x06]), &public_key);

        let output_spending_type =
            OutputType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let scripts_from = vec![script_a.clone(), script_b.clone()];
        let scripts_to = scripts_from.clone();

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        let mut builder = ProtocolBuilder::new("single_connection", storage)?;
        let protocol = builder
            .connect_with_external_transaction(
                txid,
                output_index,
                output_spending_type,
                "start",
                &ecdsa_sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "start",
                value,
                &internal_key,
                &scripts_from,
                "challenge",
                &sighash_type,
            )?
            .add_timelock_connection(
                "start",
                value,
                &internal_key,
                &expired_from,
                &renew_from,
                "challenge",
                blocks,
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "challenge",
                value,
                &internal_key,
                &scripts_to,
                "response",
                &sighash_type,
            )?
            .add_timelock_connection(
                "challenge",
                value,
                &internal_key,
                &expired_to,
                &renew_to,
                "response",
                blocks,
                &sighash_type,
            )?
            .build_and_sign(&key_manager)?;

        let challenge_spending_args = &[
            SpendingArgs::new_taproot_args(script_a.get_script()),
            SpendingArgs::new_taproot_args(renew_from.get_script()),
        ];
        let response_spending_args = &[
            SpendingArgs::new_taproot_args(script_a.get_script()),
            SpendingArgs::new_taproot_args(renew_to.get_script()),
        ];

        let start = protocol.transaction_to_send("start", &[SpendingArgs::new_args()])?;
        let challenge = protocol.transaction_to_send("challenge", challenge_spending_args)?;
        let response = protocol.transaction_to_send("response", response_spending_args)?;

        assert_eq!(start.input.len(), 1);
        assert_eq!(challenge.input.len(), 2);
        assert_eq!(response.input.len(), 2);

        assert_eq!(start.output.len(), 2);
        assert_eq!(challenge.output.len(), 2);
        assert_eq!(response.output.len(), 0);

        let sighashes_start = protocol.spending_info("start")?;
        let sighashes_challenge = protocol.spending_info("challenge")?;
        let sighashes_response = protocol.spending_info("response")?;

        assert_eq!(sighashes_start.len(), 1);
        assert_eq!(sighashes_challenge.len(), 2);
        assert_eq!(sighashes_response.len(), 2);

        Ok(())
    }

    #[test]
    fn test_single_cyclic_connection() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_single_cyclic_connection");

        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let public_key = key_manager.derive_keypair(0).unwrap();
        let internal_key = XOnlyPublicKey::from(public_key);

        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let spending_scripts = vec![script.clone(), script.clone()];

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        let mut builder = ProtocolBuilder::new("cycle", storage)?;
        builder.add_taproot_script_spend_connection(
            "cycle",
            "A",
            value,
            &internal_key,
            &spending_scripts,
            "A",
            &sighash_type,
        )?;

        let result = builder.build_and_sign(&key_manager);

        match result {
            Err(ProtocolBuilderError::GraphBuildingError(_graph_error)) => {}
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
        let test_dir = TemporaryDir::new("test_multiple_cyclic_connection");

        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let public_key = key_manager.derive_keypair(0).unwrap();
        let internal_key = XOnlyPublicKey::from(public_key);

        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;

        let txid = Hash::all_zeros();
        let output_index = 0;
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);

        let output_spending_type =
            OutputType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let scripts_from = vec![script.clone(), script.clone()];
        let scripts_to = scripts_from.clone();

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        let mut builder = ProtocolBuilder::new("cycle", storage)?;
        let result = builder
            .connect_with_external_transaction(
                txid,
                output_index,
                output_spending_type,
                "A",
                &ecdsa_sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "A",
                value,
                &internal_key,
                &scripts_from,
                "B",
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "B",
                value,
                &internal_key,
                &scripts_to,
                "C",
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "C",
                value,
                &internal_key,
                &scripts_to,
                "A",
                &sighash_type,
            )?
            .build_and_sign(&key_manager);

        match result {
            Err(ProtocolBuilderError::GraphBuildingError(_graph_error)) => {}
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
        let test_dir = TemporaryDir::new("test_single_node_no_connections");

        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let public_key = key_manager.derive_keypair(0).unwrap();

        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_spending_type =
            OutputType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        let mut builder = ProtocolBuilder::new("single_connection", storage)?;
        let protocol = builder
            .connect_with_external_transaction(
                txid,
                output_index,
                output_spending_type,
                "start",
                &ecdsa_sighash_type,
            )?
            .build_and_sign(&key_manager)?;

        let start = protocol.transaction_to_send("start", &[SpendingArgs::new_args()])?;

        assert_eq!(start.input.len(), 1);
        assert_eq!(start.output.len(), 0);

        let sighashes_start = protocol.spending_info("start")?;

        assert_eq!(sighashes_start.len(), 1);

        Ok(())
    }

    #[test]
    fn test_rounds() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_rounds");

        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let public_key = key_manager.derive_keypair(0).unwrap();
        let internal_key = XOnlyPublicKey::from(public_key);

        let rounds = 3;
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_spending_type =
            OutputType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        let mut builder = ProtocolBuilder::new("rounds", storage)?;
        let (from_rounds, _) = builder.connect_rounds(
            "rounds",
            rounds,
            "B",
            "C",
            value,
            &internal_key,
            &[script.clone()],
            &[script.clone()],
            &sighash_type,
        )?;

        let protocol = builder
            .connect_with_external_transaction(
                txid,
                output_index,
                output_spending_type,
                "A",
                &ecdsa_sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "A",
                value,
                &internal_key,
                &[script.clone()],
                &from_rounds,
                &sighash_type,
            )?
            .build_and_sign(&key_manager)?;

        let spending_args = [
            SpendingArgs::new_taproot_args(script.get_script()),
            SpendingArgs::new_taproot_args(script.get_script()),
        ];

        let a = protocol.transaction_to_send("A", &[SpendingArgs::new_args()])?;
        let b0 = protocol.transaction_to_send("B_0", &spending_args)?;
        let b1 = protocol.transaction_to_send("B_1", &spending_args)?;
        let b2 = protocol.transaction_to_send("B_2", &spending_args)?;
        let c0 = protocol.transaction_to_send("C_0", &spending_args)?;
        let c1 = protocol.transaction_to_send("C_1", &spending_args)?;
        let c2 = protocol.transaction_to_send("C_2", &spending_args)?;

        assert_eq!(a.input.len(), 1);
        assert_eq!(b0.input.len(), 1);
        assert_eq!(b1.input.len(), 1);
        assert_eq!(b2.input.len(), 1);

        assert_eq!(a.output.len(), 1);
        assert_eq!(c0.output.len(), 1);
        assert_eq!(c1.output.len(), 1);
        assert_eq!(c2.output.len(), 0);

        let sighashes_a = protocol.spending_info("A")?;
        let sighashes_b0 = protocol.spending_info("B_0")?;
        let sighashes_b1 = protocol.spending_info("B_1")?;
        let sighashes_b2 = protocol.spending_info("B_2")?;
        let sighashes_c0 = protocol.spending_info("C_0")?;
        let sighashes_c1 = protocol.spending_info("C_1")?;
        let sighashes_c2 = protocol.spending_info("C_2")?;

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
        let test_dir = TemporaryDir::new("test_zero_rounds");

        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let public_key = key_manager.derive_keypair(0).unwrap();
        let internal_key = XOnlyPublicKey::from(public_key);

        let rounds = 0;
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        let mut builder = ProtocolBuilder::new("rounds", storage)?;
        let result = builder.connect_rounds(
            "rounds",
            rounds,
            "B",
            "C",
            value,
            &internal_key,
            &[script.clone()],
            &[script.clone()],
            &sighash_type,
        );

        match result {
            Err(ProtocolBuilderError::InvalidZeroRounds) => {}
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
        let test_dir = TemporaryDir::new("test_multiple_connections");

        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let public_key = key_manager.derive_keypair(0).unwrap();
        let internal_key = XOnlyPublicKey::from(public_key);

        let rounds = 3;
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_spending_type =
            OutputType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        let mut builder = ProtocolBuilder::new("rounds", storage)?;
        builder
            .connect_with_external_transaction(
                txid,
                output_index,
                output_spending_type,
                "A",
                &ecdsa_sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "A",
                value,
                &internal_key,
                &[script.clone()],
                "B",
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "A",
                value,
                &internal_key,
                &[script.clone()],
                "C",
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "B",
                value,
                &internal_key,
                &[script.clone()],
                "D",
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "C",
                value,
                &internal_key,
                &[script.clone()],
                "D",
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "D",
                value,
                &internal_key,
                &[script.clone()],
                "E",
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "A",
                value,
                &internal_key,
                &[script.clone()],
                "F",
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "D",
                value,
                &internal_key,
                &[script.clone()],
                "F",
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "F",
                value,
                &internal_key,
                &[script.clone()],
                "G",
                &sighash_type,
            )?;

        let (from_rounds, to_rounds) = builder.connect_rounds(
            "rounds",
            rounds,
            "H",
            "I",
            value,
            &internal_key,
            &[script.clone()],
            &[script.clone()],
            &sighash_type,
        )?;

        builder
            .add_taproot_script_spend_connection(
                "protocol",
                "G",
                value,
                &internal_key,
                &[script.clone()],
                &from_rounds,
                &sighash_type,
            )?
            .add_p2wsh_output(&to_rounds, value, &script)?;

        let protocol = builder.build_and_sign(&key_manager)?;
        let mut transaction_names = protocol.transaction_names();
        transaction_names.sort();

        assert_eq!(
            &transaction_names,
            &["A", "B", "C", "D", "E", "F", "G", "H_0", "H_1", "H_2", "I_0", "I_1", "I_2"]
        );

        let graph = protocol.visualize()?;
        println!("{}", graph);

        Ok(())
    }
}
