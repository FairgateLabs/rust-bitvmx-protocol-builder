#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, EcdsaSighashType, ScriptBuf, TapSighashType};

    use crate::{
        builder::{Protocol, ProtocolBuilder},
        errors::ProtocolBuilderError,
        helpers::weight_computing::{get_transaction_hex, get_transaction_vsize},
        scripts::ProtocolScript,
        tests::utils::{new_key_manager, TemporaryDir},
        types::{
            input::{InputArgs, LeafSpec, SighashType},
            output::OutputType,
        },
    };

    #[test]
    fn test_weights_for_single_connection() -> Result<(), ProtocolBuilderError> {
        let test_dir = TemporaryDir::new("test_weights_for_single_connection");
        let key_manager =
            new_key_manager(test_dir.path("keystore"), test_dir.path("musig2data")).unwrap();
        let sighash_type = SighashType::Taproot(TapSighashType::All);
        let ecdsa_sighash_type = SighashType::Ecdsa(EcdsaSighashType::All);
        let value = 1000;
        let public_key = key_manager.derive_keypair(0)?;
        let internal_key = key_manager.derive_keypair(1)?;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let blocks = 100;

        let expired_from = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key);
        let renew_from = ProtocolScript::new(ScriptBuf::from(vec![0x01]), &public_key);
        let expired_to = ProtocolScript::new(ScriptBuf::from(vec![0x02]), &public_key);
        let renew_to = ProtocolScript::new(ScriptBuf::from(vec![0x03]), &public_key);
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key);
        let script_a = ProtocolScript::new(ScriptBuf::from(vec![0x05]), &public_key);
        let script_b = ProtocolScript::new(ScriptBuf::from(vec![0x06]), &public_key);

        let output_type = OutputType::segwit_script(value, &script)?;

        let scripts_from = vec![script_a.clone(), script_b.clone()];
        let scripts_to = scripts_from.clone();

        let mut protocol = Protocol::new("single_connection");
        let builder = ProtocolBuilder {};

        builder
            .add_external_connection(
                &mut protocol,
                txid,
                output_index,
                output_type,
                "start",
                &ecdsa_sighash_type,
            )?
            .add_taproot_script_spend_connection(
                &mut protocol,
                "protocol",
                "start",
                value,
                &internal_key,
                &scripts_from,
                true,
                vec![],
                "challenge",
                &sighash_type,
            )?
            .add_timelock_connection(
                &mut protocol,
                "start",
                value,
                &internal_key,
                &expired_from,
                &renew_from,
                true,
                vec![],
                "challenge",
                blocks,
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                &mut protocol,
                "protocol",
                "challenge",
                value,
                &internal_key,
                &scripts_to,
                true,
                vec![],
                "response",
                &sighash_type,
            )?
            .add_timelock_connection(
                &mut protocol,
                "challenge",
                value,
                &internal_key,
                &expired_to,
                &renew_to,
                true,
                vec![],
                "response",
                blocks,
                &sighash_type,
            )?;

        protocol.build_and_sign(&key_manager)?;

        let challenge_args = &[
            InputArgs::new_taproot_script_args(LeafSpec::Index(0)),
            InputArgs::new_taproot_script_args(LeafSpec::Index(1)),
        ];
        let response_args = &[
            InputArgs::new_taproot_script_args(LeafSpec::Index(0)),
            InputArgs::new_taproot_script_args(LeafSpec::Index(1)),
        ];

        let start = protocol.transaction_to_send("start", &[InputArgs::new_segwit_args()])?;
        let challenge = protocol.transaction_to_send("challenge", challenge_args)?;
        let response = protocol.transaction_to_send("response", response_args)?;

        // Taproot transaction (SegWit)
        let start_weight = get_transaction_vsize(&start);
        println!(
            "Taproot Start transaction has a weight of: {}\n Transaction bytes are:\n{}\n",
            start_weight,
            get_transaction_hex(&start),
        );

        // Taproot transaction (SegWit)
        let challenge_weight = get_transaction_vsize(&challenge);
        println!(
            "Taproot Challenge transaction has a weight of: {}\n Transaction bytes are:\n{}\n",
            challenge_weight,
            get_transaction_hex(&challenge),
        );

        // Taproot transaction (SegWit)
        let response_weight = get_transaction_vsize(&response);
        println!(
            "Taproot Response transaction has a weight of: {}\n Transaction bytes are:\n{}\n",
            response_weight,
            get_transaction_hex(&response)
        );

        assert_eq!(start.input.len(), 1);
        assert_eq!(challenge.input.len(), 2);
        assert_eq!(response.input.len(), 2);

        assert_eq!(start.output.len(), 2);
        assert_eq!(challenge.output.len(), 2);
        assert_eq!(response.output.len(), 0);

        let sighashes_start = protocol.inputs("start")?;
        let sighashes_challenge = protocol.inputs("challenge")?;
        let sighashes_response = protocol.inputs("response")?;

        assert_eq!(sighashes_start.len(), 1);
        assert_eq!(sighashes_challenge.len(), 2);
        assert_eq!(sighashes_response.len(), 2);

        Ok(())
    }
}
