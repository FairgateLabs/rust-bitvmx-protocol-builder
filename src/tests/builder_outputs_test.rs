#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::Hash,
        opcodes::all::{OP_PUSHNUM_1, OP_RETURN},
        Amount, PublicKey, ScriptBuf, Sequence,
    };

    use std::rc::Rc;
    use storage_backend::storage::Storage;

    use crate::{
        builder::{ProtocolBuilder, SpendingArgs},
        errors::ProtocolBuilderError,
        graph::output::OutputType,
        scripts::ProtocolScript,
        tests::utils::{ecdsa_sighash_type, new_key_manager, taproot_sighash_type, TemporaryDir},
    };

    #[test]
    fn test_op_return_output_script() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_op_return_output_script");

        let ecdsa_sighash_type = ecdsa_sighash_type();
        let value = 1000;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_spending_type =
            OutputType::new_segwit_script_spend(&script, Amount::from_sat(value));
        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();

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
        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        let mut builder = ProtocolBuilder::new("op_return", storage.clone())?;
        let protocol = builder
            .connect_with_external_transaction(
                txid,
                output_index,
                output_spending_type,
                "op_return",
                &ecdsa_sighash_type,
            )?
            .add_op_return_output("op_return", data.clone())?
            .build(&key_manager)?;
        let tx = protocol.transaction("op_return")?;

        // Assert
        let script_op_return = tx.output[0].script_pubkey.clone();
        //println!("script_op_return: {:?}", script_op_return);
        assert_eq!(hex::encode(script_op_return.to_bytes()), "6a4552534b5f504547494e00000000000000007ac5496aee77c1ba1f0854206a26dda82a81d6d8741976f972e9aa5e226eae26289b794aac9bbe702f378aa64c6104f16b79298c");

        let instructions = script_op_return
            .instructions()
            .flatten()
            .collect::<Vec<_>>();
        //println!("instructions: {:?}", instructions);
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
        let test_dir = TemporaryDir::new("test_taproot_keypath_and_signature");
        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let ecdsa_sighash_type = ecdsa_sighash_type();
        let taproot_sighash_type = taproot_sighash_type();
        let value = 1000;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let public_key = key_manager.derive_keypair(0).unwrap();
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_spending_type =
            OutputType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let speedup_value = 2450000;
        let pubkey_alice = key_manager.derive_keypair(1).unwrap();

        // Act
        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        let mut builder = ProtocolBuilder::new("tap_keypath", storage.clone())?;
        let protocol = builder
            .connect_with_external_transaction(
                txid,
                output_index,
                output_spending_type,
                "keypath_origin",
                &ecdsa_sighash_type,
            )?
            // This connection creates the output and input scripts for the taprootkeypath spend
            .add_taproot_key_spend_connection(
                "connection",
                "keypath_origin",
                value,
                &public_key,
                "keypath_spend",
                &taproot_sighash_type,
            )?
            .add_speedup_output("keypath_origin", speedup_value, &pubkey_alice)?
            .add_p2wpkh_output("keypath_spend", value, &pubkey_alice)?
            .build_and_sign(&key_manager)?;

        let signature = protocol
            .input_taproot_script_spend_signature("keypath_spend", 0, 0)
            .unwrap()
            .unwrap();
        let mut spending_args = SpendingArgs::new_args();
        spending_args.push_taproot_signature(signature);
        // This methods adds the witness and other impiortant information to the transaction
        let transaction = protocol.transaction_to_send("keypath_spend", &[spending_args])?;

        let tx_origin = protocol.transaction("keypath_origin")?;
        let tx_spend = protocol.transaction("keypath_spend")?;

        // Assert
        assert_eq!(
            tx_origin.output.len(),
            2,
            "Origin transaction should have 2 outputs"
        );
        let script_taproot_output = tx_origin.output[0].script_pubkey.clone();
        //println!("script_taproot_output: {:?}", hex::encode(script_taproot_output.to_bytes()));
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
