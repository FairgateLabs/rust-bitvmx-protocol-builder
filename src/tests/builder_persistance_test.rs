#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::Hash,
        key::rand::RngCore,
        secp256k1::{self, Scalar},
        Amount, EcdsaSighashType, PublicKey, ScriptBuf, TapSighashType, XOnlyPublicKey,
    };
    use std::{env, path::PathBuf, rc::Rc};
    use storage_backend::storage::Storage;

    use crate::{
        builder::ProtocolBuilder,
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
    fn test_persistence() -> Result<(), ProtocolBuilderError> {
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let txid = Hash::all_zeros();
        let output_index = 0;
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_spending_type =
            OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let storage = Rc::new(Storage::new_with_path(&temp_storage())?);
        let mut builder = ProtocolBuilder::new("rounds", storage.clone())?;
        builder.connect_with_external_transaction(
            txid,
            output_index,
            output_spending_type,
            "A",
            &ecdsa_sighash_type,
        )?;

        drop(builder);

        let mut builder = ProtocolBuilder::new("rounds", storage)?;
        let protocol = builder.build()?;

        let tx = protocol.transaction("A")?;
        assert_eq!(tx.input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A"]);

        Ok(())
    }

    #[test]
    fn test_persistence_2() -> Result<(), ProtocolBuilderError> {
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);

        let storage = Rc::new(Storage::new_with_path(&temp_storage())?);
        let mut builder = ProtocolBuilder::new("rounds", storage.clone())?;
        builder.add_p2wsh_connection(
            "connection",
            "A",
            value,
            &script,
            "B",
            &ecdsa_sighash_type,
        )?;

        drop(builder);

        let mut builder = ProtocolBuilder::new("rounds", storage)?;
        let protocol = builder.build()?;

        assert_eq!(protocol.transaction("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_3() -> Result<(), ProtocolBuilderError> {
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let storage = Rc::new(Storage::new_with_path(&temp_storage())?);
        let mut builder = ProtocolBuilder::new("rounds", storage.clone())?;
        builder.add_p2wpkh_connection(
            "connection",
            "A",
            value,
            &public_key,
            "B",
            &ecdsa_sighash_type,
        )?;

        drop(builder);

        let mut builder = ProtocolBuilder::new("rounds", storage)?;
        let protocol = builder.build()?;

        assert_eq!(protocol.transaction("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_4() -> Result<(), ProtocolBuilderError> {
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let storage = Rc::new(Storage::new_with_path(&temp_storage())?);
        let mut builder = ProtocolBuilder::new("rounds", storage.clone())?;
        builder.add_taproot_key_spend_connection(
            "connection",
            "A",
            value,
            &public_key,
            "B",
            &sighash_type,
        )?;

        drop(builder);

        let mut builder = ProtocolBuilder::new("rounds", storage)?;
        let protocol = builder.build()?;

        assert_eq!(protocol.transaction("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_5() -> Result<(), ProtocolBuilderError> {
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let mut rng = secp256k1::rand::thread_rng();
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let internal_key = XOnlyPublicKey::from(unspendable_key(&mut rng)?);
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);

        let storage = Rc::new(Storage::new_with_path(&temp_storage())?);
        let mut builder = ProtocolBuilder::new("rounds", storage.clone())?;
        builder.add_taproot_script_spend_connection(
            "connection",
            "A",
            value,
            &internal_key,
            &[script.clone()],
            "B",
            &sighash_type,
        )?;

        drop(builder);

        let mut builder = ProtocolBuilder::new("rounds", storage)?;
        let protocol = builder.build()?;

        assert_eq!(protocol.transaction("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_6() -> Result<(), ProtocolBuilderError> {
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let script_expired = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key);
        let script_renew = ProtocolScript::new(ScriptBuf::from(vec![0x01]), &public_key);

        let storage = Rc::new(Storage::new_with_path(&temp_storage())?);
        let mut builder = ProtocolBuilder::new("rounds", storage.clone())?;
        builder.add_linked_message_connection(
            "A",
            "B",
            value,
            &[script.clone()],
            100,
            &script_expired,
            &script_renew,
            100,
            &public_key,
            &sighash_type,
        )?;

        drop(builder);

        let mut builder = ProtocolBuilder::new("rounds", storage)?;
        let protocol = builder.build()?;

        assert_eq!(protocol.transaction("A").unwrap().output.len(), 3);
        assert_eq!(protocol.transaction("B").unwrap().input.len(), 2);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_7() -> Result<(), ProtocolBuilderError> {
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let storage = Rc::new(Storage::new_with_path(&temp_storage())?);
        let mut builder = ProtocolBuilder::new("rounds", storage.clone())?;
        builder.add_taproot_tweaked_key_spend_connection(
            "connection",
            "A",
            value,
            &public_key,
            &Scalar::ZERO,
            "B",
            &sighash_type,
        )?;

        drop(builder);

        let mut builder = ProtocolBuilder::new("rounds", storage)?;
        let protocol = builder.build()?;

        assert_eq!(protocol.transaction("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }
}
