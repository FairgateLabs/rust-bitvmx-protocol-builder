#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, PublicKey, ScriptBuf};
    use std::rc::Rc;

    use crate::{
        builder::{Protocol, ProtocolBuilder},
        errors::ProtocolBuilderError,
        scripts::{ProtocolScript, SignMode},
        tests::utils::TestContext,
        types::{
            connection::{InputSpec, OutputSpec},
            input::SpendMode,
            output::OutputType,
        },
    };

    use key_manager::key_type::BitcoinKeyType;

    #[test]
    fn test_persistence() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_persistence").unwrap();
        let storage = Rc::new(tc.new_storage("protocol"));

        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let txid = Hash::all_zeros();
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key, SignMode::Single);
        let output_type = OutputType::segwit_script(value, &script)?;

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_external_connection(
            &mut protocol,
            "EXT",
            txid,
            OutputSpec::Auto(output_type),
            "A",
            InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build(tc.key_manager(), "")?;

        let tx = protocol.transaction_by_name("A")?;
        assert_eq!(tx.input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["EXT", "A"]);

        Ok(())
    }

    #[test]
    fn test_persistence_2() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_persistence_2").unwrap();
        let storage = Rc::new(tc.new_storage("protocol"));

        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key, SignMode::Single);

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_p2wsh_connection(
            &mut protocol,
            "connection",
            "A",
            value,
            &script,
            "B",
            &tc.ecdsa_sighash_type(),
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build(tc.key_manager(), "")?;

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_3() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_persistence_3").unwrap();
        let storage = Rc::new(tc.new_storage("protocol"));

        let value = 1000;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_p2wpkh_connection(
            &mut protocol,
            "connection",
            "A",
            value,
            &public_key,
            "B",
            &tc.ecdsa_sighash_type(),
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build(tc.key_manager(), "")?;

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_4() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_persistence_4").unwrap();
        let public_key = tc.key_manager().derive_keypair(BitcoinKeyType::P2tr, 0)?;
        let internal_key = tc.key_manager().derive_keypair(BitcoinKeyType::P2tr, 1)?;
        let storage = Rc::new(tc.new_storage("protocol"));

        let value = 1000;
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key, SignMode::Single);

        let mut protocol = Protocol::new("rounds");
        let builder = ProtocolBuilder {};

        builder.add_taproot_connection(
            &mut protocol,
            "connection",
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

        protocol.save(storage.clone())?;

        drop(protocol);

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build_and_sign(tc.key_manager(), "")?;

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 1);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 1);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }

    #[test]
    fn test_persistence_5() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_persistence_5").unwrap();
        let public_key = tc.key_manager().derive_keypair(BitcoinKeyType::P2tr, 0)?;
        let internal_key = tc.key_manager().derive_keypair(BitcoinKeyType::P2tr, 1)?;
        let storage = Rc::new(tc.new_storage("protocol"));

        let value = 1000;
        let script =
            ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key, SignMode::Single);
        let script_expired =
            ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key, SignMode::Single);
        let script_renew =
            ProtocolScript::new(ScriptBuf::from(vec![0x01]), &public_key, SignMode::Single);

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
            &SpendMode::All {
                key_path_sign: SignMode::Single,
            },
            &tc.tr_sighash_type(),
        )?;

        protocol.save(storage.clone())?;

        drop(protocol);

        let mut protocol = match Protocol::load("rounds", storage.clone())? {
            Some(protocol) => protocol,
            None => panic!("Failed to load protocol"),
        };

        protocol.build_and_sign(tc.key_manager(), "")?;

        assert_eq!(protocol.transaction_by_name("A").unwrap().output.len(), 3);
        assert_eq!(protocol.transaction_by_name("B").unwrap().input.len(), 2);

        let transaction_names = protocol.transaction_names();
        assert_eq!(&transaction_names, &["A", "B"]);

        Ok(())
    }
}
