#[cfg(test)]
mod tests {
    use crate::{
        scripts::{ProtocolScript, SignMode},
        types::output::{OutputType, AUTO_AMOUNT, RECOVER_AMOUNT},
    };

    use bitcoin::{key::rand, secp256k1::Secp256k1, Amount, ScriptBuf, WScriptHash};

    #[test]
    fn test_new_segwit_key_spend() {
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let value = 1000;
        let witness_public_key_hash = bitcoin::PublicKey::from(public_key)
            .wpubkey_hash()
            .expect("key is compressed");
        let script_pubkey = ScriptBuf::new_p2wpkh(&witness_public_key_hash);

        let output_type = OutputType::segwit_key(value, &public_key.into()).unwrap();

        match output_type {
            OutputType::SegwitPublicKey {
                value: v,
                script_pubkey: s,
                public_key: key,
            } => {
                assert_eq!(v, Amount::from_sat(value));
                assert_eq!(s, script_pubkey);
                assert_eq!(key, public_key.into());
            }
            _ => panic!("Wrong enum variant"),
        }
    }

    #[test]
    fn test_new_segwit_script_spend() {
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let value = 1000;
        let script = ProtocolScript::new(
            bitcoin::ScriptBuf::new(),
            &public_key.into(),
            SignMode::Single,
        );
        let script_pubkey = ScriptBuf::new_p2wsh(&WScriptHash::from(script.get_script().clone()));

        let output_type = OutputType::segwit_script(value, &script).unwrap();

        match output_type {
            OutputType::SegwitScript {
                value: v,
                script_pubkey: s,
                script: sc,
            } => {
                assert_eq!(v, Amount::from_sat(value));
                assert_eq!(s, script_pubkey);
                assert_eq!(sc.get_script(), script.get_script());
            }
            _ => panic!("Wrong enum variant"),
        }
    }

    #[test]
    fn test_auto_amount_flags() {
        // Test AUTO_AMOUNT sentinel value
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());

        let auto_output = OutputType::segwit_key(AUTO_AMOUNT, &public_key.into()).unwrap();
        let recover_output = OutputType::segwit_key(RECOVER_AMOUNT, &public_key.into()).unwrap();
        let normal_output = OutputType::segwit_key(1000, &public_key.into()).unwrap();

        // Test auto_value() flags
        assert_eq!(auto_output.auto_value(), true);
        assert_eq!(auto_output.recover_value(), false);

        // Test recover_value() flags
        assert_eq!(recover_output.auto_value(), false);
        assert_eq!(recover_output.recover_value(), true);

        // Test normal value has no flags
        assert_eq!(normal_output.auto_value(), false);
        assert_eq!(normal_output.recover_value(), false);

        // Test dust_limit() returns >= 540 sats
        assert!(auto_output.dust_limit().to_sat() >= 540);
        assert!(recover_output.dust_limit().to_sat() >= 540);
        assert_eq!(auto_output.dust_limit(), Amount::from_sat(540));
    }

    #[test]
    fn test_recover_amount_flags() {
        // Test RECOVER_AMOUNT with different output types
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let script = ProtocolScript::new(ScriptBuf::new(), &public_key.into(), SignMode::Single);

        // Test with SegwitScript
        let recover_script_output = OutputType::segwit_script(RECOVER_AMOUNT, &script).unwrap();
        assert_eq!(recover_script_output.auto_value(), false);
        assert_eq!(recover_script_output.recover_value(), true);
        assert!(recover_script_output.dust_limit().to_sat() >= 540);
    }
}
