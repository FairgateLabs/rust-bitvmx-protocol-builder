#[cfg(test)]
mod tests {
    use crate::{scripts::ProtocolScript, types::OutputType};

    use bitcoin::{
        key::{rand, Parity, TweakedPublicKey},
        secp256k1::{Scalar, Secp256k1},
        Amount, PublicKey, ScriptBuf, WScriptHash, XOnlyPublicKey,
    };

    #[test]
    fn test_new_taproot_tweaked_key_spend() {
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());

        let (_, parity) = public_key.x_only_public_key();

        let adjusted_key = if parity == Parity::Odd {
            PublicKey::new(public_key.negate(&secp))
        } else {
            PublicKey::new(public_key)
        };

        let tweak = Scalar::random();
        let value = 1000;

        let public_key: PublicKey = public_key.into();
        let script_pubkey =
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(
                XOnlyPublicKey::from(adjusted_key)
                    .add_tweak(&secp, &tweak)
                    .unwrap()
                    .0,
            ));

        let output_type = OutputType::tr_key(value, &public_key, Some(&tweak), vec![]).unwrap();

        match output_type {
            OutputType::TaprootKey {
                value: v,
                internal_key,
                tweak: t,
                script_pubkey: s,
                prevouts,
            } => {
                assert_eq!(v, Amount::from_sat(value));
                assert_eq!(s, script_pubkey);
                assert_eq!(internal_key, public_key);
                assert_eq!(t.unwrap(), tweak.to_be_bytes());
                assert!(prevouts.is_empty());
            }
            _ => panic!("Wrong enum variant"),
        }
    }

    #[test]
    fn test_new_taproot_untweaked_key_spend() {
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let value = 1000;
        let script_pubkey = ScriptBuf::new_p2tr(&secp, XOnlyPublicKey::from(public_key), None);

        let output_type = OutputType::tr_key(value, &public_key.into(), None, vec![]).unwrap();

        match output_type {
            OutputType::TaprootKey {
                value: v,
                internal_key,
                tweak: t,
                script_pubkey: s,
                prevouts,
            } => {
                assert_eq!(v, Amount::from_sat(value));
                assert_eq!(internal_key, public_key.into());
                assert_eq!(t, None);
                assert_eq!(s, script_pubkey);
                assert!(prevouts.is_empty());
            }
            _ => panic!("Wrong enum variant"),
        }
    }

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
        let script = ProtocolScript::new(bitcoin::ScriptBuf::new(), &public_key.into());
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
