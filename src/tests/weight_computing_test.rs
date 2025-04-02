#[cfg(test)]
mod tests {
    use bitcoin::{
        hashes::Hash, Amount, EcdsaSighashType, ScriptBuf, TapSighashType, XOnlyPublicKey,
    };
    use std::rc::Rc;
    use storage_backend::storage::Storage;

    use crate::{
        builder::{ProtocolBuilder, SpendingArgs},
        errors::ProtocolBuilderError,
        graph::{input::SighashType, output::OutputSpendingType},
        helpers::weight_computing::{get_transaction_hex, get_transaction_vsize},
        scripts::ProtocolScript,
        tests::utils::{new_key_manager, TemporaryDir},
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
        let internal_key = XOnlyPublicKey::from(key_manager.derive_keypair(1)?);
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

        let output_spending_type =
            OutputSpendingType::new_segwit_script_spend(&script, Amount::from_sat(value));

        let scripts_from = vec![script_a.clone(), script_b.clone()];
        let scripts_to = scripts_from.clone();

        let storage = Rc::new(Storage::new_with_path(&test_dir.path("protocol"))?);
        let mut builder = ProtocolBuilder::new("single_connection", storage)?;
        let protocol = builder
            .connect_with_external_transaction(
                txid,
                output_index,
                output_spending_type,
                "start",
                &ecdsa_sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "start",
                value,
                &internal_key,
                &scripts_from,
                "challenge",
                &sighash_type,
            )?
            .add_timelock_connection(
                "start",
                value,
                &internal_key,
                &expired_from,
                &renew_from,
                "challenge",
                blocks,
                &sighash_type,
            )?
            .add_taproot_script_spend_connection(
                "protocol",
                "challenge",
                value,
                &internal_key,
                &scripts_to,
                "response",
                &sighash_type,
            )?
            .add_timelock_connection(
                "challenge",
                value,
                &internal_key,
                &expired_to,
                &renew_to,
                "response",
                blocks,
                &sighash_type,
            )?
            .build_and_sign(&key_manager)?;

        let challenge_spending_args = &[
            SpendingArgs::new_taproot_args(script_a.get_script()),
            SpendingArgs::new_taproot_args(renew_from.get_script()),
        ];
        let response_spending_args = &[
            SpendingArgs::new_taproot_args(script_a.get_script()),
            SpendingArgs::new_taproot_args(renew_to.get_script()),
        ];

        let start = protocol.transaction_to_send("start", &[SpendingArgs::new_args()])?;
        let challenge = protocol.transaction_to_send("challenge", challenge_spending_args)?;
        let response = protocol.transaction_to_send("response", response_spending_args)?;

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

        let sighashes_start = protocol.spending_info("start")?;
        let sighashes_challenge = protocol.spending_info("challenge")?;
        let sighashes_response = protocol.spending_info("response")?;

        assert_eq!(sighashes_start.len(), 1);
        assert_eq!(sighashes_challenge.len(), 2);
        assert_eq!(sighashes_response.len(), 2);

        Ok(())
    }
}
