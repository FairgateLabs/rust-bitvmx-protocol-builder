#[cfg(test)]
mod test {
    use crate::types::input::{InputSignatures, SighashType, Signature};

    use bitcoin::key::rand;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::{taproot, EcdsaSighashType, TapSighashType};

    #[test]
    fn test_empty_signatures() {
        let empty_sigs = InputSignatures::new(vec![]);
        assert!(empty_sigs.get_taproot_signature(0).is_err());
        assert!(empty_sigs.get_ecdsa_signature(0).is_err());
    }

    #[test]
    fn test_taproot_signature() {
        let _msg = Message::from_digest_slice(&[0; 32]).unwrap();
        let tap_sig = taproot::Signature::from_slice(&[1; 64]).unwrap();
        let sigs = InputSignatures::new(vec![Some(Signature::Taproot(tap_sig))]);

        assert!(sigs.get_taproot_signature(0).is_ok());
        assert!(sigs.get_ecdsa_signature(0).is_err());
        assert!(sigs.get_taproot_signature(1).is_err());
    }

    #[test]
    fn test_ecdsa_signature() {
        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&[0; 32]).unwrap();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let ecdsa_sig = secp.sign_ecdsa(&msg, &secret_key);
        let sigs = InputSignatures::new(vec![Some(Signature::Ecdsa(
            bitcoin::ecdsa::Signature::sighash_all(ecdsa_sig),
        ))]);

        assert!(sigs.get_ecdsa_signature(0).is_ok());
        assert!(sigs.get_taproot_signature(0).is_err());
    }

    #[test]
    fn test_iterator() {
        let tap_sig = taproot::Signature::from_slice(&[1; 64]).unwrap();
        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(&[0; 32]).unwrap();
        let (secret_key, _) = secp.generate_keypair(&mut rand::thread_rng());
        let ecdsa_sig = secp.sign_ecdsa(&msg, &secret_key);
        let sigs = InputSignatures::new(vec![
            Some(Signature::Taproot(tap_sig)),
            Some(Signature::Ecdsa(bitcoin::ecdsa::Signature::sighash_all(
                ecdsa_sig,
            ))),
        ]);

        assert_eq!(sigs.iter().count(), 2);
    }

    #[test]
    fn test_sighash_types() {
        let tap_sighash = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash = SighashType::Ecdsa(EcdsaSighashType::All);

        match tap_sighash {
            SighashType::Taproot(_) => {}
            _ => panic!("Expected Taproot sighash type"),
        }

        match ecdsa_sighash {
            SighashType::Ecdsa(_) => {}
            _ => panic!("Expected ECDSA sighash type"),
        }
    }
}
