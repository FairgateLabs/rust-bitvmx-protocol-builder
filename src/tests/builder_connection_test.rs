#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::Hash,
        key::rand,
        secp256k1::{Message, Secp256k1},
        ScriptBuf,
    };

    use crate::{
        builder::{Protocol, ProtocolBuilder},
        errors::{GraphError, ProtocolBuilderError},
        graph::graph::GraphOptions,
        scripts::{ProtocolScript, SignMode},
        tests::utils::TestContext,
        types::{
            connection::{InputSpec, OutputSpec},
            input::{InputArgs, Signature, SpendMode},
            output::OutputType,
        },
    };

    use key_manager::key_type::BitcoinKeyType;

    #[test]
    fn test_single_connection() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_single_connection").unwrap();

        // Taproot key for Schnorr signatures
        let internal_taproot_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();

        // ECDSA key for Segwit operations
        let internal_ecdsa_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2wpkh, 1)
            .unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let blocks = 100;

        let expired_from = ProtocolScript::new(
            ScriptBuf::from(vec![0x00]),
            &internal_taproot_key,
            SignMode::Single,
        );
        let renew_from = ProtocolScript::new(
            ScriptBuf::from(vec![0x01]),
            &internal_taproot_key,
            SignMode::Single,
        );
        let expired_to = ProtocolScript::new(
            ScriptBuf::from(vec![0x02]),
            &internal_taproot_key,
            SignMode::Single,
        );
        let renew_to = ProtocolScript::new(
            ScriptBuf::from(vec![0x03]),
            &internal_taproot_key,
            SignMode::Single,
        );
        let script = ProtocolScript::new(
            ScriptBuf::from(vec![0x04]),
            &internal_ecdsa_key,
            SignMode::Single,
        );
        let script_a = ProtocolScript::new(
            ScriptBuf::from(vec![0x05]),
            &internal_taproot_key,
            SignMode::Single,
        );
        let script_b = ProtocolScript::new(
            ScriptBuf::from(vec![0x06]),
            &internal_taproot_key,
            SignMode::Single,
        );

        let output_type = OutputType::segwit_script(value, &script)?;

        let scripts_from = vec![script_a.clone(), script_b.clone()];
        let scripts_to = scripts_from.clone();

        let mut protocol = Protocol::new("single_connection");

        let builder = ProtocolBuilder {};

        builder
            .add_external_connection(
                &mut protocol,
                "ext",
                txid,
                OutputSpec::Auto(output_type),
                "start",
                InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "start",
                value,
                &internal_taproot_key,
                &scripts_from,
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "challenge",
                &tc.tr_sighash_type(),
            )?
            .add_timelock_connection(
                &mut protocol,
                "start",
                value,
                &internal_taproot_key,
                &expired_from,
                &renew_from,
                &SpendMode::ScriptsOnly,
                "challenge",
                blocks,
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "challenge",
                value,
                &internal_taproot_key,
                &scripts_to,
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "response",
                &tc.tr_sighash_type(),
            )?
            .add_timelock_connection(
                &mut protocol,
                "challenge",
                value,
                &internal_taproot_key,
                &expired_to,
                &renew_to,
                &SpendMode::ScriptsOnly,
                "response",
                blocks,
                &tc.tr_sighash_type(),
            )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        let challenge_args = &[
            InputArgs::new_taproot_script_args(0),
            InputArgs::new_taproot_script_args(1),
        ];
        let response_args = &[
            InputArgs::new_taproot_script_args(0),
            InputArgs::new_taproot_script_args(1),
        ];

        let start = protocol.transaction_to_send("start", &[InputArgs::new_segwit_args()])?;
        let challenge = protocol.transaction_to_send("challenge", challenge_args)?;
        let response = protocol.transaction_to_send("response", response_args)?;

        assert_eq!(start.input.len(), 1);
        assert_eq!(challenge.input.len(), 2);
        assert_eq!(response.input.len(), 2);

        assert_eq!(start.output.len(), 2);
        assert_eq!(challenge.output.len(), 2);
        assert_eq!(response.output.len(), 0);

        let start_inputs = protocol.inputs("start")?;
        let challenge_inputs = protocol.inputs("challenge")?;
        let response_inputs = protocol.inputs("response")?;

        assert_eq!(start_inputs.len(), 1);
        assert_eq!(challenge_inputs.len(), 2);
        assert_eq!(response_inputs.len(), 2);

        // Check hashed messages for all transactions
        assert_eq!(start_inputs[0].hashed_messages().len(), 1);
        match start_inputs[0].hashed_messages().as_slice() {
            [Some(m)] => assert_eq!(m[..].len(), 32),
            _ => panic!("Start hashed messages for input {} does not contain the expected hashes. Hashed messages are: {:?}", 0, start_inputs[0].hashed_messages()),
        }

        assert_eq!(challenge_inputs[0].hashed_messages().len(), 3);
        match challenge_inputs[0].hashed_messages().as_slice() {
            [Some(m1), Some(m2), Some(m3)] => {
                assert_eq!(m1[..].len(), 32);
                assert_eq!(m2[..].len(), 32);
                assert_eq!(m3[..].len(), 32);
            }
            _ => panic!("Challenge hashed messages for input {} does not contain the expected hashes. Hashed messages are: {:?}", 0, challenge_inputs[0].hashed_messages()),
        }

        // Input was created with a taproot script spend connection that doesn't generate the hash for the key path. Hence the None in the last position of the hashed messages.
        assert_eq!(challenge_inputs[1].hashed_messages().len(), 3);
        match challenge_inputs[1].hashed_messages().as_slice() {
            [Some(m1), Some(m2), None] => {
                assert_eq!(m1[..].len(), 32);
                assert_eq!(m2[..].len(), 32);
            }
            _ => panic!("Challenge hashed messages for input {} does not contain the expected hashes. Hashed messages are: {:?}", 1, challenge_inputs[1].hashed_messages()),
        }

        assert_eq!(response_inputs[0].hashed_messages().len(), 3);
        match response_inputs[0].hashed_messages().as_slice() {
            [Some(m1), Some(m2), Some(m3)] => {
                assert_eq!(m1[..].len(), 32);
                assert_eq!(m2[..].len(), 32);
                assert_eq!(m3[..].len(), 32);
            }
            _ => panic!("Response hashed messages for input {} does not contain the expected hashes. Hashed messages are: {:?}", 0, response_inputs[0].hashed_messages()),
        }

        // Input was created with a taproot script spend connection that doesn't generate the hash for the key path. Hence the None in the last position of the hashed messages.
        assert_eq!(response_inputs[1].hashed_messages().len(), 3);
        match response_inputs[1].hashed_messages().as_slice() {
            [Some(m1), Some(m2), None] => {
                assert_eq!(m1[..].len(), 32);
                assert_eq!(m2[..].len(), 32);
            }
            _ => panic!("Response hashed messages for input {} does not contain the expected hashes. Hashed messages are: {:?}", 1, response_inputs[1].hashed_messages()),
        }

        // Check signatures for all transactions
        assert_eq!(start_inputs[0].signatures().len(), 1);
        match start_inputs[0].signatures().as_slice() {
            [Some(_)] => {},
            _ => panic!("Start signatures for input {} does not contain the expected signatures. Signatures are: {:?}", 0, start_inputs[0].signatures()),
        }

        assert_eq!(challenge_inputs[0].signatures().len(), 3);
        match challenge_inputs[0].signatures().as_slice() {
            [Some(_), Some(_), Some(_)] => {},
            _ => panic!("Challenge signatures for input {} does not contain the expected signatures. Signatures are: {:?}", 0, challenge_inputs[0].signatures()),
        }

        // Input was created with a taproot script spend connection that doesn't generate the signature for the key path. Hence the None in the last position of the signatures.
        assert_eq!(challenge_inputs[1].signatures().len(), 3);
        match challenge_inputs[1].signatures().as_slice() {
            [Some(_), Some(_), None] => {},
            _ => panic!("Challenge signatures for input {} does not contain the expected signatures. Signatures are: {:?}", 1, challenge_inputs[1].signatures()),
        }

        assert_eq!(response_inputs[0].signatures().len(), 3);
        match response_inputs[0].signatures().as_slice() {
            [Some(_), Some(_), Some(_)] => {},
            _ => panic!("Response signatures for input {} does not contain the expected signatures. Signatures are: {:?}", 0, response_inputs[0].signatures()),
        }

        // Input was created with a taproot script spend connection that doesn't generate the signature for the key path. Hence the None in the last position of the signatures.
        assert_eq!(response_inputs[1].signatures().len(), 3);
        match response_inputs[1].signatures().as_slice() {
            [Some(_), Some(_), None] => {},
            _ => panic!("Response signatures for input {} does not contain the expected signatures. Signaturess are: {:?}", 1, response_inputs[1].signatures()),
        }

        Ok(())
    }

    #[test]
    fn test_single_cyclic_connection() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_single_cyclic_connection").unwrap();
        let internal_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();

        let value = 1000;
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &internal_key, SignMode::Single);
        let scripts = vec![script.clone(), script.clone()];

        let mut protocol = Protocol::new("cycle");
        let builder = ProtocolBuilder {};

        builder.add_taproot_connection(
            &mut protocol,
            "cycle",
            "A",
            value,
            &internal_key,
            &scripts,
            &SpendMode::All {
                key_path_sign: SignMode::Single,
            },
            "A",
            &tc.tr_sighash_type(),
        )?;

        let result = protocol.build_and_sign(tc.key_manager(), "");

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
        let tc = TestContext::new("test_multiple_cyclic_connection").unwrap();
        let internal_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &internal_key, SignMode::Single);

        let output_type = OutputType::segwit_script(value, &script)?;

        let scripts_from = vec![script.clone(), script.clone()];
        let scripts_to = scripts_from.clone();

        let mut protocol = Protocol::new("cycle");
        let builder = ProtocolBuilder {};

        builder
            .add_external_connection(
                &mut protocol,
                "ext",
                txid,
                OutputSpec::Auto(output_type),
                "A",
                InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "A",
                value,
                &internal_key,
                &scripts_from,
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "B",
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "B",
                value,
                &internal_key,
                &scripts_to,
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "C",
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "C",
                value,
                &internal_key,
                &scripts_to,
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "A",
                &tc.tr_sighash_type(),
            )?;

        let result = protocol.build_and_sign(tc.key_manager(), "");

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
        let tc = TestContext::new("test_single_node_no_connections").unwrap();
        let public_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2wpkh, 0)
            .unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key, SignMode::Single);
        let output_type = OutputType::segwit_script(value, &script)?;

        let mut protocol = Protocol::new("single_connection");
        let builder = ProtocolBuilder {};

        builder.add_external_connection(
            &mut protocol,
            "ext",
            txid,
            OutputSpec::Auto(output_type),
            "start",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
        )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        let start = protocol.transaction_to_send("start", &[InputArgs::new_segwit_args()])?;

        assert_eq!(start.input.len(), 1);
        assert_eq!(start.output.len(), 0);

        let sighashes_start = protocol.inputs("start")?;

        assert_eq!(sighashes_start.len(), 1);

        Ok(())
    }

    #[test]
    fn test_rounds() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_rounds").unwrap();
        let internal_taproot_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();

        // Use ECDSA key for segwit_script output
        let internal_segwit_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2wpkh, 1)
            .unwrap();

        let rounds = 3;
        let value = 1000;
        let txid = Hash::all_zeros();
        let script = ProtocolScript::new(
            ScriptBuf::from(vec![0x04]),
            &internal_taproot_key,
            SignMode::Single,
        );

        let segwit_script = ProtocolScript::new(
            ScriptBuf::from(vec![0x04]),
            &internal_segwit_key,
            SignMode::Single,
        );
        let output_type = OutputType::segwit_script(value, &segwit_script)?;

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        let (from_rounds, _) = builder.connect_taproot_rounds(
            &mut protocol,
            "rounds",
            rounds,
            "B",
            "C",
            value,
            &internal_taproot_key,
            &[script.clone()],
            &[script.clone()],
            &SpendMode::All {
                key_path_sign: SignMode::Single,
            },
            &tc.tr_sighash_type(),
        )?;

        builder
            .add_external_connection(
                &mut protocol,
                "ext",
                txid,
                OutputSpec::Auto(output_type),
                "A",
                InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "A",
                value,
                &internal_taproot_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                &from_rounds,
                &tc.tr_sighash_type(),
            )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        let args = [InputArgs::new_taproot_script_args(0)];

        let a = protocol.transaction_to_send("A", &[InputArgs::new_segwit_args()])?;
        let b0 = protocol.transaction_to_send("B_0", &args)?;
        let b1 = protocol.transaction_to_send("B_1", &args)?;
        let b2 = protocol.transaction_to_send("B_2", &args)?;
        let c0 = protocol.transaction_to_send("C_0", &args)?;
        let c1 = protocol.transaction_to_send("C_1", &args)?;
        let c2 = protocol.transaction_to_send("C_2", &args)?;

        assert_eq!(a.input.len(), 1);
        assert_eq!(b0.input.len(), 1);
        assert_eq!(b1.input.len(), 1);
        assert_eq!(b2.input.len(), 1);

        assert_eq!(a.output.len(), 1);
        assert_eq!(c0.output.len(), 1);
        assert_eq!(c1.output.len(), 1);
        assert_eq!(c2.output.len(), 0);

        let sighashes_a = protocol.inputs("A")?;
        let sighashes_b0 = protocol.inputs("B_0")?;
        let sighashes_b1 = protocol.inputs("B_1")?;
        let sighashes_b2 = protocol.inputs("B_2")?;
        let sighashes_c0 = protocol.inputs("C_0")?;
        let sighashes_c1 = protocol.inputs("C_1")?;
        let sighashes_c2 = protocol.inputs("C_2")?;

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
        let tc = TestContext::new("test_zero_rounds").unwrap();
        let internal_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();

        let rounds = 0;
        let value = 1000;
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &internal_key, SignMode::Single);

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        let result = builder.connect_taproot_rounds(
            &mut protocol,
            "rounds",
            rounds,
            "B",
            "C",
            value,
            &internal_key,
            &[script.clone()],
            &[script.clone()],
            &SpendMode::All {
                key_path_sign: SignMode::Single,
            },
            &tc.tr_sighash_type(),
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
        let tc = TestContext::new("test_multiple_connections").unwrap();
        let internal_taproot_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();
        // Use ECDSA key for segwit_script output
        let internal_segwit_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2wpkh, 1)
            .unwrap();

        let rounds = 3;
        let value = 1000;
        let txid = Hash::all_zeros();
        let script = ProtocolScript::new(
            ScriptBuf::from(vec![0x04]),
            &internal_taproot_key,
            SignMode::Single,
        );

        let segwit_script = ProtocolScript::new(
            ScriptBuf::from(vec![0x04]),
            &internal_segwit_key,
            SignMode::Single,
        );
        let output_type = OutputType::segwit_script(value, &segwit_script)?;

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder
            .add_external_connection(
                &mut protocol,
                "external",
                txid,
                OutputSpec::Auto(output_type),
                "A",
                InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "A",
                value,
                &internal_taproot_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "B",
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "A",
                value,
                &internal_taproot_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "C",
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "B",
                value,
                &internal_taproot_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "D",
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "C",
                value,
                &internal_taproot_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "D",
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "D",
                value,
                &internal_taproot_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "E",
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "A",
                value,
                &internal_taproot_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "F",
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "D",
                value,
                &internal_taproot_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "F",
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "F",
                value,
                &internal_taproot_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                "G",
                &tc.tr_sighash_type(),
            )?;

        let (from_rounds, to_rounds) = builder.connect_taproot_rounds(
            &mut protocol,
            "rounds",
            rounds,
            "H",
            "I",
            value,
            &internal_taproot_key,
            &[script.clone()],
            &[script.clone()],
            &SpendMode::All {
                key_path_sign: SignMode::Single,
            },
            &tc.tr_sighash_type(),
        )?;

        builder
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "G",
                value,
                &internal_taproot_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                &from_rounds,
                &tc.tr_sighash_type(),
            )?
            .add_p2wsh_output(&mut protocol, &to_rounds, value, &script)?;

        protocol.build_and_sign(tc.key_manager(), "")?;
        let mut transaction_names = protocol.transaction_names();
        transaction_names.sort();

        assert_eq!(
            &transaction_names,
            &[
                "A", "B", "C", "D", "E", "F", "G", "H_0", "H_1", "H_2", "I_0", "I_1", "I_2",
                "external"
            ]
        );

        let graph = protocol.visualize(GraphOptions::Default)?;
        println!("{}", graph);

        Ok(())
    }

    #[test]
    fn test_connect_missing_output_index() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_connect_missing_output_index").unwrap();

        let mut protocol = Protocol::new("missing_output_test");

        protocol.add_transaction("A")?;

        protocol.add_transaction("B")?;

        // Try to connect to output index 0 of transaction A when it doesn't exist
        let result = protocol.add_connection(
            "c",
            "A",
            OutputSpec::Index(0),
            "B",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            None,
            None,
        );

        // Verify it returns the expected error
        match result {
            Err(ProtocolBuilderError::MissingOutput(tx_name, index)) => {
                assert_eq!(tx_name, "A");
                assert_eq!(index, 0);
            }
            Err(other_error) => {
                panic!("Expected MissingOutput error, got: {:?}", other_error);
            }
            Ok(_) => {
                panic!("Expected an error, but got Ok");
            }
        }

        Ok(())
    }

    #[test]
    fn test_get_transaction_by_unknown_txid() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_get_transaction_by_unknown_txid").unwrap();
        let internal_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2wpkh, 0)
            .unwrap();

        let value = 1000;
        let existing_txid = Hash::all_zeros();
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &internal_key, SignMode::Single);
        let output_type = OutputType::segwit_script(value, &script)?;

        let mut protocol = Protocol::new("txid_lookup_test");
        let builder = ProtocolBuilder {};

        builder.add_external_connection(
            &mut protocol,
            "ext",
            existing_txid,
            OutputSpec::Auto(output_type),
            "start",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
        )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        // Create a different txid that doesn't exist in the protocol
        let unknown_txid = bitcoin::Txid::from_byte_array([0xff; 32]);

        // Try to get transaction by unknown txid
        let result = protocol.transaction_by_id(&unknown_txid);

        match result {
            Err(ProtocolBuilderError::GraphBuildingError(graph_error)) => match graph_error {
                crate::errors::GraphError::TransactionNotFound(txid_str) => {
                    assert_eq!(txid_str, unknown_txid.to_string());
                }
                other_graph_error => {
                    panic!(
                        "Expected GraphError::TransactionNotFound, got: {:?}",
                        other_graph_error
                    );
                }
            },
            Err(other_error) => {
                panic!(
                    "Expected GraphBuildingError containing TransactionNotFound, got: {:?}",
                    other_error
                );
            }
            Ok(_) => {
                panic!("Expected an error, but got Ok");
            }
        }

        Ok(())
    }

    #[test]
    fn test_taproot_rounds_valid_endpoints() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_taproot_rounds_valid_endpoints").unwrap();
        let external_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();
        let internal_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();

        let rounds = 3;
        let value = 1000;
        let txid = Hash::all_zeros();
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &external_key, SignMode::Single);
        let output_type = OutputType::taproot(value, &external_key, &[script.clone()])?;

        let mut protocol = Protocol::new("taproot_rounds_endpoints");
        let builder = ProtocolBuilder {};

        let (from_endpoint, to_endpoint) = builder.connect_taproot_rounds(
            &mut protocol,
            "rounds",
            rounds,
            "B",
            "C",
            value,
            &internal_key,
            &[script.clone()],
            &[script.clone()],
            &SpendMode::All {
                key_path_sign: SignMode::Single,
            },
            &tc.tr_sighash_type(),
        )?;

        assert_eq!(from_endpoint, "B_0", "Expected from_endpoint to be 'B_0'");
        assert_eq!(
            to_endpoint, "C_2",
            "Expected to_endpoint to be 'C_2' (last round, index 2)"
        );

        builder
            .add_external_connection(
                &mut protocol,
                "ext",
                txid,
                OutputSpec::Auto(output_type),
                "A",
                InputSpec::Auto(
                    tc.tr_sighash_type(),
                    SpendMode::KeyOnly {
                        key_path_sign: SignMode::Single,
                    },
                ),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "A",
                value,
                &internal_key,
                &[script.clone()],
                &SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
                &from_endpoint,
                &tc.tr_sighash_type(),
            )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        // Verify that all expected transactions were created by checking transaction_names
        let tx_names = protocol.transaction_names();
        assert!(
            tx_names.contains(&"B_0".to_string()),
            "Protocol should contain B_0"
        );
        assert!(
            tx_names.contains(&"B_1".to_string()),
            "Protocol should contain B_1"
        );
        assert!(
            tx_names.contains(&"B_2".to_string()),
            "Protocol should contain B_2"
        );
        assert!(
            tx_names.contains(&"C_0".to_string()),
            "Protocol should contain C_0"
        );
        assert!(
            tx_names.contains(&"C_1".to_string()),
            "Protocol should contain C_1"
        );
        assert!(
            tx_names.contains(&"C_2".to_string()),
            "Protocol should contain C_2"
        );

        for i in 0..rounds {
            let b_tx = protocol.transaction_to_send(
                &format!("B_{}", i),
                &[InputArgs::new_taproot_script_args(0)],
            )?;
            let c_tx = protocol.transaction_to_send(
                &format!("C_{}", i),
                &[InputArgs::new_taproot_script_args(0)],
            )?;

            assert_eq!(b_tx.input.len(), 1, "B_{} should have exactly 1 input", i);
            assert_eq!(c_tx.input.len(), 1, "C_{} should have exactly 1 input", i);
        }

        let c_last =
            protocol.transaction_to_send("C_2", &[InputArgs::new_taproot_script_args(0)])?;
        assert_eq!(
            c_last.output.len(),
            0,
            "C_2 (last round) should have 0 outputs (no reverse connection)"
        );

        let c_0 = protocol.transaction_to_send("C_0", &[InputArgs::new_taproot_script_args(0)])?;
        let c_1 = protocol.transaction_to_send("C_1", &[InputArgs::new_taproot_script_args(0)])?;
        assert_eq!(
            c_0.output.len(),
            1,
            "C_0 should have 1 output (connects to next round)"
        );
        assert_eq!(
            c_1.output.len(),
            1,
            "C_1 should have 1 output (connects to next round)"
        );

        Ok(())
    }

    #[test]
    fn test_timelock_connection_sequence() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_timelock_connection_sequence").unwrap();
        let internal_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();

        let value = 1000;
        let blocks = 200;
        let expired_script =
            ProtocolScript::new(ScriptBuf::from(vec![0x01]), &internal_key, SignMode::Single);
        let renew_script =
            ProtocolScript::new(ScriptBuf::from(vec![0x02]), &internal_key, SignMode::Single);

        let mut protocol = Protocol::new("timelock_sequence_test");
        let builder = ProtocolBuilder {};

        // Add a simple timelock connection from A to B with blocks=200
        builder.add_timelock_connection(
            &mut protocol,
            "A",
            value,
            &internal_key,
            &expired_script,
            &renew_script,
            &SpendMode::ScriptsOnly,
            "B",
            blocks,
            &tc.tr_sighash_type(),
        )?;

        // Build the protocol
        protocol.build_and_sign(tc.key_manager(), "")?;

        // Read the transaction B and verify the sequence field
        let tx_b = protocol.transaction_by_name("B")?;

        assert_eq!(
            tx_b.input.len(),
            1,
            "Transaction B should have exactly 1 input"
        );

        // Verify that the sequence is set from the timelock height (as per specification)
        let expected_sequence = bitcoin::Sequence::from_height(blocks);
        assert_eq!(
            tx_b.input[0].sequence, expected_sequence,
            "Input sequence should equal Sequence::from_height({}). \
             Expected {:?}, got {:?}",
            blocks, expected_sequence, tx_b.input[0].sequence
        );

        Ok(())
    }

    #[test]
    fn test_add_transaction_with_empty_name() {
        let mut protocol = Protocol::new("empty_name_test");

        let result = protocol.add_transaction("");

        match result {
            Err(ProtocolBuilderError::MissingTransactionName) => {
                // Expected error
            }
            Err(other_error) => {
                panic!(
                    "Expected MissingTransactionName error, got: {:?}",
                    other_error
                );
            }
            Ok(_) => {
                panic!("Expected an error, but got Ok");
            }
        }
    }

    #[test]
    fn test_add_connection_with_empty_name() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_add_connection_with_empty_name").unwrap();

        let mut protocol = Protocol::new("empty_connection_name_test");

        protocol.add_transaction("A")?;
        protocol.add_transaction("B")?;

        let result = protocol.add_connection(
            "", // Empty connection name
            "A",
            OutputSpec::Index(0),
            "B",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            None,
            None,
        );

        match result {
            Err(ProtocolBuilderError::MissingConnectionName) => {
                // Expected error
            }
            Err(other_error) => {
                panic!(
                    "Expected MissingConnectionName error, got: {:?}",
                    other_error
                );
            }
            Ok(_) => {
                panic!("Expected an error, but got Ok");
            }
        }

        Ok(())
    }

    #[test]
    fn test_visualize_dot_format() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_visualize_dot_format").unwrap();
        let internal_key = tc.key_manager().derive_keypair(0).unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &internal_key, SignMode::Single);
        let output_type = OutputType::segwit_script(value, &script)?;

        let mut protocol = Protocol::new("visualize_test");
        let builder = ProtocolBuilder {};

        // Create minimal protocol: external -> A -> B with ECDSA connection
        builder.add_external_connection(
            &mut protocol,
            "ext",
            txid,
            OutputSpec::Auto(output_type.clone()),
            "A",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
        )?;

        builder.add_p2wsh_output(&mut protocol, "A", value, &script)?;

        protocol.add_transaction("B")?;

        protocol.add_connection(
            "connection_ab",
            "A",
            OutputSpec::Index(0),
            "B",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            None,
            None,
        )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        let dot_output = protocol.visualize(GraphOptions::Default)?;

        assert!(
            dot_output.contains("digraph {"),
            "DOT output must contain 'digraph {{'"
        );

        assert!(
            dot_output.contains("A [label="),
            "DOT output must contain node A"
        );
        assert!(
            dot_output.contains("B [label="),
            "DOT output must contain node B"
        );

        assert!(
            dot_output.contains("A -> B:i0"),
            "DOT output must contain edge 'A -> B:i0'"
        );

        assert!(
            dot_output.contains("[label=connection_ab]"),
            "DOT output must contain connection label"
        );

        assert!(
            dot_output.ends_with("}") || dot_output.ends_with("}\n"),
            "DOT output must end with closing brace"
        );

        Ok(())
    }

    #[test]
    fn test_visualize_dot_with_edge_arrows() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_visualize_edge_arrows").unwrap();
        let internal_key = tc.key_manager().derive_keypair(0).unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &internal_key, SignMode::Single);
        let output_type = OutputType::segwit_script(value, &script)?;

        let mut protocol = Protocol::new("edge_arrows_test");
        let builder = ProtocolBuilder {};

        builder.add_external_connection(
            &mut protocol,
            "ext",
            txid,
            OutputSpec::Auto(output_type),
            "A",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
        )?;

        builder.add_p2wsh_output(&mut protocol, "A", value, &script)?;

        protocol.add_transaction("B")?;

        protocol.add_connection(
            "conn",
            "A",
            OutputSpec::Index(0),
            "B",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            None,
            None,
        )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        let dot_output = protocol.visualize(GraphOptions::EdgeArrows)?;

        assert!(
            dot_output.contains(":o0:e ->") && dot_output.contains(":i0:w"),
            "EdgeArrows format must include output and input port specifications"
        );

        Ok(())
    }

    #[test]
    fn test_visualize_multiple_nodes_and_edges() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_visualize_multi").unwrap();
        let internal_key = tc.key_manager().derive_keypair(0).unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &internal_key, SignMode::Single);
        let output_type = OutputType::segwit_script(value, &script)?;

        let mut protocol = Protocol::new("multi_node_test");
        let builder = ProtocolBuilder {};

        // Create A -> B -> C chain
        builder.add_external_connection(
            &mut protocol,
            "ext",
            txid,
            OutputSpec::Auto(output_type),
            "A",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
        )?;

        builder.add_p2wsh_output(&mut protocol, "A", value, &script)?;

        protocol.add_transaction("B")?;

        protocol.add_connection(
            "ab",
            "A",
            OutputSpec::Index(0),
            "B",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            None,
            None,
        )?;

        builder.add_p2wsh_output(&mut protocol, "B", value, &script)?;

        protocol.add_transaction("C")?;

        protocol.add_connection(
            "bc",
            "B",
            OutputSpec::Index(0),
            "C",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            None,
            None,
        )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        let dot_output = protocol.visualize(GraphOptions::Default)?;

        assert!(dot_output.contains("A [label="), "Must contain node A");
        assert!(dot_output.contains("B [label="), "Must contain node B");
        assert!(dot_output.contains("C [label="), "Must contain node C");

        assert!(dot_output.contains("A -> B:i0"), "Must contain edge A -> B");
        assert!(dot_output.contains("B -> C:i0"), "Must contain edge B -> C");

        assert!(
            dot_output.contains("[label=ab]"),
            "Must contain connection label 'ab'"
        );
        assert!(
            dot_output.contains("[label=bc]"),
            "Must contain connection label 'bc'"
        );

        Ok(())
    }

    #[test]
    fn test_visualize_empty_protocol() -> Result<(), ProtocolBuilderError> {
        let protocol = Protocol::new("empty_test");

        let dot_output = protocol.visualize(GraphOptions::Default)?;

        assert!(
            dot_output.contains("digraph {"),
            "Empty protocol must still produce valid DOT"
        );
        assert!(
            dot_output.ends_with("}") || dot_output.ends_with("}\n"),
            "Empty protocol must close DOT properly"
        );

        assert!(
            !dot_output.contains(" -> "),
            "Empty protocol should not have edges"
        );

        Ok(())
    }

    #[test]
    fn test_update_input_signature_out_of_range() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_update_input_signature_out_of_range").unwrap();
        let internal_key = tc.key_manager().derive_keypair(0).unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &internal_key, SignMode::Single);
        let output_type = OutputType::segwit_script(value, &script)?;

        let mut protocol = Protocol::new("signature_index_test");
        let builder = ProtocolBuilder {};

        builder.add_external_connection(
            &mut protocol,
            "external",
            txid,
            OutputSpec::Auto(output_type),
            "A",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
        )?;

        protocol.add_transaction("B")?;

        protocol.add_connection(
            "conn",
            "A",
            OutputSpec::Auto(OutputType::segwit_key(value, &internal_key)?),
            "B",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            None,
            None,
        )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        // Transaction B has one input with one signature slot (index 0)
        // Trying to update signature_index 1 should fail
        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&[0; 32]).unwrap();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let ecdsa_sig = secp.sign_ecdsa(&msg, &secret_key);
        let signature = bitcoin::ecdsa::Signature::sighash_all(ecdsa_sig);

        let result = protocol.update_input_signature(
            "B",
            0,
            Some(Signature::Ecdsa(signature)),
            1, // Out of range - only index 0 exists
        );

        match result {
            Err(ProtocolBuilderError::GraphBuildingError(GraphError::InvalidSignatureIndex(1))) => {
                // Expected error
            }
            Err(e) => {
                panic!("Expected InvalidSignatureIndex(1), but got: {:?}", e);
            }
            Ok(_) => {
                panic!("Expected an error, but got Ok");
            }
        }

        Ok(())
    }

    #[test]
    fn test_sign_ecdsa_on_taproot_input() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_sign_ecdsa_on_taproot_input").unwrap();
        let internal_key = tc.key_manager().derive_keypair(0).unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &internal_key, SignMode::Single);
        let output_type = OutputType::segwit_script(value, &script)?;

        let mut protocol = Protocol::new("sign_type_mismatch_test");
        let builder = ProtocolBuilder {};

        // Create external connection with ECDSA
        builder.add_external_connection(
            &mut protocol,
            "external",
            txid,
            OutputSpec::Auto(output_type),
            "A",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
        )?;

        protocol.add_transaction("B")?;

        // Add a Taproot connection from A to B
        builder.add_taproot_connection(
            &mut protocol,
            "taproot_conn",
            "A",
            value,
            &internal_key,
            &[script.clone()],
            &SpendMode::All {
                key_path_sign: SignMode::Single,
            },
            "B",
            &tc.tr_sighash_type(),
        )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        // Transaction B has a Taproot input at index 0
        // Trying to sign with ECDSA should fail with type mismatch
        let result = protocol.sign_ecdsa_input("B", 0, tc.key_manager());

        match result {
            Err(ProtocolBuilderError::InvalidSighashType(tx_name, input_idx, expected, actual)) => {
                assert_eq!(tx_name, "B");
                assert_eq!(input_idx, 0);
                assert_eq!(expected, "SighashType::Ecdsa");
                assert!(
                    actual.contains("Taproot"),
                    "Expected Taproot in actual type, got: {}",
                    actual
                );
            }
            Err(e) => {
                panic!("Expected InvalidSighashType error, but got: {:?}", e);
            }
            Ok(_) => {
                panic!("Expected an error, but got Ok");
            }
        }

        Ok(())
    }
}
