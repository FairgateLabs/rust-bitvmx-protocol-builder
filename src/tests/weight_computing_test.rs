#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, ScriptBuf};

    use crate::{
        builder::{Protocol, ProtocolBuilder},
        errors::ProtocolBuilderError,
        helpers::weight_computing::{get_transaction_hex, get_transaction_vsize},
        scripts::{ProtocolScript, SignMode},
        tests::utils::TestContext,
        types::{
            input::{InputArgs, LeafSpec},
            output::{OutputType, SpendMode},
        },
    };

    #[test]
    fn test_weights_for_single_connection() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_weights_for_single_connection").unwrap();
        let public_key = tc.key_manager().derive_keypair(0).unwrap();
        let internal_key = tc.key_manager().derive_keypair(1).unwrap();

        let value = 1000;
        let txid = Hash::all_zeros();
        let output_index = 0;
        let blocks = 100;

        let expired_from = ProtocolScript::new(ScriptBuf::from(vec![0x00]), &public_key, SignMode::Single);
        let renew_from = ProtocolScript::new(ScriptBuf::from(vec![0x01]), &public_key, SignMode::Single);
        let expired_to = ProtocolScript::new(ScriptBuf::from(vec![0x02]), &public_key, SignMode::Single);
        let renew_to = ProtocolScript::new(ScriptBuf::from(vec![0x03]), &public_key, SignMode::Single);
        let script = ProtocolScript::new(ScriptBuf::from(vec![0x04]), &public_key, SignMode::Single);
        let script_a = ProtocolScript::new(ScriptBuf::from(vec![0x05]), &public_key, SignMode::Single);
        let script_b = ProtocolScript::new(ScriptBuf::from(vec![0x06]), &public_key, SignMode::Single);

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
                &tc.ecdsa_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "start",
                value,
                &internal_key,
                &scripts_from,
                &SpendMode::All { key_path_sign: SignMode::Single },
                &[],
                "challenge",
                &tc.tr_sighash_type(),
            )?
            .add_timelock_connection(
                &mut protocol,
                "start",
                value,
                &internal_key,
                &expired_from,
                &renew_from,
                &SpendMode::All { key_path_sign: SignMode::Single },
                &[],
                "challenge",
                blocks,
                &tc.tr_sighash_type(),
            )?
            .add_taproot_connection(
                &mut protocol,
                "protocol",
                "challenge",
                value,
                &internal_key,
                &scripts_to,
                &SpendMode::All { key_path_sign: SignMode::Single },
                &[],
                "response",
                &tc.tr_sighash_type(),
            )?
            .add_timelock_connection(
                &mut protocol,
                "challenge",
                value,
                &internal_key,
                &expired_to,
                &renew_to,
                &SpendMode::All { key_path_sign: SignMode::Single },
                &[],
                "response",
                blocks,
                &tc.tr_sighash_type(),
            )?;

        protocol.build_and_sign(tc.key_manager(), "")?;

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

    #[test]
    fn dust_threshold_estimation_test() {
        let fee_rate = 3.0; // Conservative relay fee (Bitcoin Core default)

        let taproot_spend_size = taproot_script_spend_size_vbytes();
        let dust = dust_threshold(fee_rate, taproot_spend_size);
        let padding = 5; // Slightly above dust

        let output_value = suggested_output_value(dust, padding);

        println!("Taproot script spend size estimate: {} vbytes", taproot_spend_size);
        println!("Dust threshold (at {} sat/vB): {} sats", fee_rate, dust);
        println!("Suggested output value: {} sats", output_value);

        // Example: CPFP child transaction spends this + pays miner
        let parent_tx_vbytes = 200; // rough estimate
        let child_tx_vbytes = 120;  // single-input CPFP spend
        let total_required_fee = cpfp_fee_for_chain(fee_rate, parent_tx_vbytes, child_tx_vbytes);

        println!(
            "Required total CPFP fee to get both mined: {} sats",
            total_required_fee
        );

        let cpfp_contribution_needed = total_required_fee.saturating_sub(output_value);
        println!(
            "Child tx must contribute at least: {} sats in additional fees",
            cpfp_contribution_needed
        );
    }

    /// Estimated spend size for a Taproot script path (conservative)
    fn taproot_script_spend_size_vbytes() -> usize {
        165 // Based on Bitcoin Core's estimate
    }

    /// Compute dust threshold: size × fee_rate × 3
    fn dust_threshold(fee_rate_sat_per_vbyte: f64, spend_size_vbytes: usize) -> u64 {
        (spend_size_vbytes as f64 * fee_rate_sat_per_vbyte * 3.0).ceil() as u64
    }

    /// Suggest a near-dust output (dust + padding)
    fn suggested_output_value(dust: u64, padding: u64) -> u64 {
        dust + padding // e.g., dust + 5 sats
    }

    /// Estimate total fee required for CPFP to get both txs mined
    fn cpfp_fee_for_chain(fee_rate_sat_per_vbyte: f64, parent_vbytes: usize, child_vbytes: usize) -> u64 {
        ((parent_vbytes + child_vbytes) as f64 * fee_rate_sat_per_vbyte).ceil() as u64
    }
}
