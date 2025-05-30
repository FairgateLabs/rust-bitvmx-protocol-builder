#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, ScriptBuf};

    use crate::{
        builder::Protocol,
        errors::ProtocolBuilderError,
        scripts::{self, ProtocolScript, SignMode},
        tests::utils::TestContext,
        types::{
            connection::{InputSpec, OutputSpec},
            input::SpendMode,
            OutputType,
        },
    };

    #[test]
    fn test_single_scripts_generation() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_single_scripts_generation").unwrap();
        let mut protocol = Protocol::new("single_scripts");

        let value = 1000;
        let txid = Hash::all_zeros();

        // Create the public keys
        let public_key = tc.key_manager().derive_keypair(0).unwrap();
        let internal_key = tc.key_manager().derive_keypair(1).unwrap();

        // Create the leaves
        let challenge_leaves = vec![
            ProtocolScript::new(
                ScriptBuf::from_bytes(vec![0x00]),
                &internal_key,
                SignMode::Single,
            ),
            ProtocolScript::new(
                ScriptBuf::from_bytes(vec![0x01]),
                &internal_key,
                SignMode::Single,
            ),
            ProtocolScript::new(
                ScriptBuf::from_bytes(vec![0x02]),
                &internal_key,
                SignMode::Single,
            ),
        ];

        let timeout_leaves = vec![
            ProtocolScript::new(
                ScriptBuf::from_bytes(vec![0x03]),
                &internal_key,
                SignMode::Single,
            ),
            ProtocolScript::new(
                ScriptBuf::from_bytes(vec![0x04]),
                &internal_key,
                SignMode::Single,
            ),
        ];

        // Add the transactions
        protocol.add_transaction("start")?;
        protocol.add_transaction("challenge")?;
        protocol.add_transaction("response_op1")?;
        protocol.add_transaction("response_op2")?;
        protocol.add_transaction("response_op3")?;
        protocol.add_transaction("end")?;

        // Avoid generating the hashes and signatures for all the spend paths of the challenge output
        let challenge_output = OutputType::taproot(value, &internal_key, &challenge_leaves)?;
        protocol.add_transaction_output("challenge", &challenge_output)?;

        // Create the transaction output types
        let external_output = OutputType::segwit_key(value, &public_key)?;
        let start_challenge_output = OutputType::taproot(value, &internal_key, &timeout_leaves)?;

        // Add the

        // Connect the start transaction with an external transaction
        protocol.add_connection(
            "protocol",
            "ext",
            external_output.into(),
            "start",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            None,
            Some(txid),
        )?;

        // Connect the start transaction with the challenge transaction
        protocol.add_connection(
            "protocol",
            "start",
            OutputSpec::Auto(start_challenge_output),
            "challenge",
            InputSpec::Auto(
                tc.tr_sighash_type(),
                SpendMode::All {
                    key_path_sign: SignMode::Single,
                },
            ),
            None,
            None,
        )?;

        // Connect each challenge response option with the challenge transaction
        protocol.add_connection(
            "protocol_op1",
            "challenge",
            OutputSpec::Index(0),
            "response_op1",
            InputSpec::Auto(tc.tr_sighash_type(), SpendMode::Script { leaf: 0 }),
            None,
            None,
        )?;

        protocol.add_connection(
            "protocol_op2",
            "challenge",
            OutputSpec::Index(0),
            "response_op2",
            InputSpec::Auto(tc.tr_sighash_type(), SpendMode::Script { leaf: 1 }),
            None,
            None,
        )?;

        protocol.add_connection(
            "protocol_op3",
            "challenge",
            OutputSpec::Index(0),
            "response_op3",
            InputSpec::Auto(tc.tr_sighash_type(), SpendMode::Script { leaf: 2 }),
            None,
            None,
        )?;

        // Add one extra non-spendable output to each challenge response transaction to ensure different txids
        let script_op1 = scripts::op_return_script(vec![0x00])?.get_script().clone();
        let script_op2 = scripts::op_return_script(vec![0x01])?.get_script().clone();
        let script_op3 = scripts::op_return_script(vec![0x02])?.get_script().clone();

        protocol
            .add_transaction_output("response_op1", &OutputType::segwit_unspendable(script_op1)?)?;
        protocol
            .add_transaction_output("response_op2", &OutputType::segwit_unspendable(script_op2)?)?;
        protocol
            .add_transaction_output("response_op3", &OutputType::segwit_unspendable(script_op3)?)?;

        // End the challenge avoiding the generation of the hashes and signatures for the response challenge output
        let end_challenge_output = OutputType::taproot(value, &internal_key, &timeout_leaves)?;

        // Connect the response transaction from op1 to the end transaction
        protocol.add_connection(
            "protocol_op1",
            "response_op1",
            OutputSpec::Auto(end_challenge_output.clone()),
            "end",
            InputSpec::Auto(tc.tr_sighash_type(), SpendMode::Script { leaf: 0 }),
            None,
            None,
        )?;

        // Connect the response transaction from op2 to the end transaction
        protocol.add_connection(
            "protocol_op2",
            "response_op2",
            OutputSpec::Auto(end_challenge_output.clone()),
            "end",
            InputSpec::Auto(tc.tr_sighash_type(), SpendMode::Script { leaf: 0 }),
            None,
            None,
        )?;

        // Connect the response transaction from op3 to the end transaction
        protocol.add_connection(
            "protocol_op3",
            "response_op3",
            OutputSpec::Auto(end_challenge_output),
            "end",
            InputSpec::Auto(tc.tr_sighash_type(), SpendMode::Script { leaf: 0 }),
            None,
            None,
        )?;

        protocol.build(tc.key_manager(), "")?;

        Ok(())
    }
}
