#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::Hash, secp256k1::Scalar, EcdsaSighashType, PublicKey, ScriptBuf, TapSighashType,
    };
    use std::rc::Rc;
    use storage_backend::storage::Storage;

    use crate::{
        builder::{Protocol, ProtocolBuilder},
        errors::ProtocolBuilderError,
        scripts::ProtocolScript,
        tests::utils::{new_key_manager, TemporaryDir},
        types::{input::SighashType, output::OutputType},
    };

    #[test]
    fn test_persistence() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_persistence");
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let txid = Hash::all_zeros();
        let output_index = 0;
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let output_type = OutputType::segwit_script(value, &script)?;

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        //let mut builder = ProtocolBuilder::new("rounds", storage.clone())?;

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_external_connection(
            &mut protocol,
            txid,
            output_index,
            output_type,
            "A",
            &ecdsa_sighash_type,
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build(false, &key_manager)?;

        let tx = protocol.transaction_by_name("A")?;
        assert_eq!(tx.input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A"]);

        Ok(())
    }

    #[test]
    fn test_persistence_2() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_persistence_2");
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        //let mut builder = ProtocolBuilder::new("rounds", storage.clone())?;

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_p2wsh_connection(
            &mut protocol,
            "connection",
            "A",
            value,
            &script,
            "B",
            &ecdsa_sighash_type,
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build(false, &key_manager)?;

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_3() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_persistence_3");
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        //let mut builder = ProtocolBuilder::new("rounds", storage.clone())?;

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_p2wpkh_connection(
            &mut protocol,
            "connection",
            "A",
            value,
            &public_key,
            "B",
            &ecdsa_sighash_type,
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build(false, &key_manager)?;

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_4() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_persistence_4");
        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();

        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;

        let public_key = key_manager.derive_keypair(0)?;

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_taproot_key_spend_connection(
            &mut protocol,
            "connection",
            "A",
            value,
            &public_key,
            None,
            "B",
            &sighash_type,
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build_and_sign(&key_manager)?;

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_5() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_persistence_5");
        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let public_key = key_manager.derive_keypair(0)?;
        let internal_key = key_manager.derive_keypair(1)?;
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_taproot_script_spend_connection(
            &mut protocol,
            "connection",
            "A",
            value,
            &internal_key,
            &[script.clone()],
            true,
            vec![],
            "B",
            &sighash_type,
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build_and_sign(&key_manager)?;

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_6() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_persistence_6");
        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let public_key = key_manager.derive_keypair(0)?;
        let internal_key = key_manager.derive_keypair(1)?;
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let script_expired = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key);
        let script_renew = ProtocolScript::new(ScriptBuf::from(vec![0x01]), &public_key);

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_linked_message_connection(
            &mut protocol,
            "A",
            "B",
            value,
            &[script.clone()],
            100,
            &script_expired,
            &script_renew,
            100,
            &public_key,
            &internal_key,
            true,
            vec![],
            &sighash_type,
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build_and_sign(&key_manager)?;

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 3);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 2);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_7() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_persistence_7");
        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let public_key = key_manager.derive_keypair(0)?;

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_taproot_key_spend_connection(
            &mut protocol,
            "connection",
            "A",
            value,
            &public_key,
            Some(&Scalar::ZERO),
            "B",
            &sighash_type,
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build_and_sign(&key_manager)?;

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_8() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_persistence_8");
        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let value = 1000;
        let public_key = key_manager.derive_keypair(0)?;

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_taproot_key_spend_connection(
            &mut protocol,
            "connection",
            "A",
            value,
            &public_key,
            Some(&Scalar::ZERO),
            "B",
            &sighash_type,
        )?;

        protocol.build_and_sign(&key_manager)?;
        protocol.save(storage.clone())?;

        drop(protocol);

        let protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 1);

        let signature = protocol.input_taproot_key_spend_signature("B", 0)?;
        assert!(signature.is_some());

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }
}
