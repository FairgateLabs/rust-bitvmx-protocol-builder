#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::Hash,
        key::rand::RngCore,
        opcodes::all::OP_RETURN,
        secp256k1::{self},
        Amount, EcdsaSighashType, PublicKey, ScriptBuf, TapSighashType, XOnlyPublicKey,
    };
    use std::{env, path::PathBuf, rc::Rc};
    use storage_backend::storage::Storage;

    use crate::{
        builder::{ProtocolBuilder, SpendingArgs},
        errors::ProtocolBuilderError,
        graph::{input::SighashType, output::OutputSpendingType},
        scripts::ProtocolScript,
        unspendable::unspendable_key,
    };
    fn temp_storage() -> PathBuf {
        let dir = env::temp_dir();
        let mut rng = secp256k1::rand::thread_rng();
        let index = rng.next_u32();
        dir.join(format!("storage_{}.db", index))
    }

    
    #[test]
    fn test_op_return_output_script() -> Result<(), ProtocolBuilderError> {
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_spending_type =
            OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

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
        let storage = Rc::new(Storage::new_with_path(&temp_storage())?);
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
            .build()?;
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

}
