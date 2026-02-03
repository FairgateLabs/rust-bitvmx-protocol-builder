#[cfg(test)]
mod tests {
    use std::vec;

    use bitcoin::{
        hashes::Hash,
        opcodes::all::{OP_PUSHNUM_1, OP_RETURN},
        Amount, PublicKey, ScriptBuf, Sequence,
    };

    use crate::{
        builder::{Protocol, ProtocolBuilder},
        errors::ProtocolBuilderError,
        scripts::{self, ProtocolScript, SignMode},
        tests::utils::TestContext,
        types::{
            connection::{InputSpec, OutputSpec},
            input::{InputArgs, SpendMode},
            output::OutputType,
        },
    };

    use key_manager::key_type::BitcoinKeyType;

    #[test]
    fn test_op_return_output_script() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_op_return_output_script").unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key, SignMode::Single);
        let output_type = OutputType::segwit_script(value.into(), &script)?;

        // Arrange
        let number: u64 = 0;
        let decoded_address = hex::decode("7ac5496aee77c1ba1f0854206a26dda82a81d6d8").unwrap();
        let address = decoded_address.as_slice();
        let decoded_xpubkey =
            hex::decode("741976f972e9aa5e226eae26289b794aac9bbe702f378aa64c6104f16b79298c")
                .unwrap();
        let xpubkey = decoded_xpubkey.as_slice();

        // Push different kind of data
        let data = [
            b"RSK_PEGIN".as_slice(),
            &number.to_be_bytes(),
            address,
            xpubkey,
        ]
        .concat();

        // Act
        let mut protocol = Protocol::new("op_return");
        let builder = ProtocolBuilder {};

        builder
            .add_external_connection(
                &mut protocol,
                "ext",
                txid,
                OutputSpec::Auto(output_type),
                "op_return",
                InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            )?
            .add_op_return_output(&mut protocol, "op_return", data.clone())?;

        protocol.build(tc.key_manager(), "")?;
        let tx = protocol.transaction_by_name("op_return")?;

        // Assert
        let script_op_return = tx.output[0].script_pubkey.clone();
        assert_eq!(hex::encode(script_op_return.to_bytes()), "6a4552534b5f504547494e00000000000000007ac5496aee77c1ba1f0854206a26dda82a81d6d8741976f972e9aa5e226eae26289b794aac9bbe702f378aa64c6104f16b79298c");

        let instructions = script_op_return
            .instructions()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(instructions.len(), 2, "Script should have 2 instructions");
        assert_eq!(
            instructions[0].opcode(),
            Some(OP_RETURN),
            "First instruction should be OP_RETURN"
        );
        assert_eq!(
            instructions[1].push_bytes().unwrap().as_bytes(),
            &data,
            "Second instruction should be data we sent"
        );

        Ok(())
    }

    #[test]
    fn test_taproot_keypath_and_signature() -> Result<(), anyhow::Error> {
        // Arrange
        let tc = TestContext::new("test_taproot_keypath_and_signature").unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let public_taproot_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();

        // Use ECDSA key for segwit_script output
        let public_segwit_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2wpkh, 1)
            .unwrap();
        let script = ProtocolScript::new(
            ScriptBuf::from(vec![0x04]),
            &public_segwit_key,
            SignMode::Single,
        );
        let output_type = OutputType::segwit_script(value.into(), &script)?;

        let speedup_value = 2450000;
        let pubkey_alice = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 2)
            .unwrap();

        let unspendable_script = scripts::op_return_script(vec![0x04, 0x05, 0x06])?;

        // Act
        let mut protocol = Protocol::new("tap_keypath");
        let builder = ProtocolBuilder {};

        builder
            .add_external_connection(
                &mut protocol,
                "ext",
                txid,
                OutputSpec::Auto(output_type),
                "keypath_origin",
                InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            )?
            // This connection creates the output and input scripts for the taprootkeypath spend
            .add_taproot_connection(
                &mut protocol,
                "connection",
                "keypath_origin",
                value,
                &public_taproot_key,
                &[unspendable_script],
                &SpendMode::KeyOnly {
                    key_path_sign: SignMode::Single,
                },
                "keypath_spend",
                &tc.tr_sighash_type(),
            )?
            .add_speedup_output(
                &mut protocol,
                "keypath_origin",
                speedup_value,
                &pubkey_alice,
            )?
            .add_p2wpkh_output(&mut protocol, "keypath_spend", value, &pubkey_alice)?;

        protocol.build_and_sign(tc.key_manager(), "")?;

        let signature = protocol
            .input_taproot_key_spend_signature("keypath_spend", 0)
            .unwrap()
            .unwrap();
        let mut args = InputArgs::new_taproot_key_args();
        args.push_taproot_signature(signature)?;
        // This methods adds the witness and other impiortant information to the transaction
        let transaction = protocol.transaction_to_send("keypath_spend", &[args])?;

        let tx_origin = protocol.transaction_by_name("keypath_origin")?;
        let tx_spend = protocol.transaction_by_name("keypath_spend")?;

        // Assert
        assert_eq!(
            tx_origin.output.len(),
            2,
            "Origin transaction should have 2 outputs"
        );
        let script_taproot_output = tx_origin.output[0].script_pubkey.clone();
        let taproot_output_instructions = script_taproot_output
            .instructions()
            .flatten()
            .collect::<Vec<_>>();
        // Check Origin Outputs
        assert_eq!(
            tx_origin.output.len(),
            2,
            "Origin transaction should have 2 outputs"
        );
        assert_eq!(
            tx_origin.output[0].value,
            Amount::from_sat(value),
            "Origin output should have the value we sent"
        );
        assert_eq!(
            tx_origin.output[1].value,
            Amount::from_sat(speedup_value),
            "Origin output should have the speedup value"
        );
        assert_eq!(
            taproot_output_instructions.len(),
            2,
            "Taproot output script should have 2 instructions"
        );
        assert_eq!(
            taproot_output_instructions[0].opcode(),
            Some(OP_PUSHNUM_1),
            "First taproot output instruction should be OP_1"
        );
        assert_eq!(
            taproot_output_instructions[1].push_bytes().unwrap().len(),
            32,
            "Second taproot output instruction should be OP_PUSHBYTES_32 with the hashed tweaked pubkey"
        );

        // Check Spend Input
        println!("tx_spend.input: {:?}", tx_spend.input);
        assert_eq!(
            tx_spend.input.len(),
            1,
            "Spend transaction should have 1 input"
        );
        assert_eq!(
            tx_spend.input[0].previous_output.txid,
            tx_origin.compute_txid(),
            "Spend input should have the same txid as the origin transaction"
        );
        assert_eq!(
            tx_spend.input[0].previous_output.vout, 0,
            "Spend input should have the same output index as the origin transaction"
        );
        assert_eq!(
            tx_spend.input[0].sequence,
            Sequence::from_hex("0xfffffffd").unwrap(),
            "Spend input should have the sequence number 0xfffffffd"
        );
        // Check that the witness is added to the transaction
        assert_eq!(
            transaction.input[0].witness.len(),
            1,
            "Spend input should have 1 witness"
        );

        Ok(())
    }
}
