#[cfg(test)]
mod tests {
    use crate::{
        scripts::{ProtocolScript, SignMode},
        types::OutputType,
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
}
