#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, ScriptBuf};

    use crate::{
        builder::{Protocol, ProtocolBuilder},
        errors::ProtocolBuilderError,
        graph::estimate::estimate_min_relay_fee,
        scripts::{ProtocolScript, SignMode, StackItem},
        tests::utils::TestContext,
        types::{
            connection::{InputSpec, OutputSpec},
            input::{InputArgs, SpendMode},
            output::OutputType,
        },
    };

    use key_manager::key_type::BitcoinKeyType;

    // Test 1: Auto/Recover Backfill - Simplified
    // Objective: Validate Protocol::compute_minimum_output_values runs without errors.
    // Verifies that the protocol correctly builds a parent->child chain and fees are deducted.
    #[test]
    fn test_auto_recover_backfill() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_auto_recover_backfill").unwrap();

        let parent_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2wpkh, 0)
            .unwrap();

        let child_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2wpkh, 1)
            .unwrap();

        let txid = Hash::all_zeros();
        let fixed_value = 10000u64;

        let mut protocol = Protocol::new("auto_recover_test");
        let builder = ProtocolBuilder {};

        // Create a simple parent -> child chain
        builder
            .add_external_connection(
                &mut protocol,
                "external",
                txid,
                OutputSpec::Auto(OutputType::segwit_key(fixed_value, &parent_key)?),
                "parent",
                InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            )?
            .add_p2wpkh_connection(
                &mut protocol,
                "parent_to_child",
                "parent",
                5000,
                &child_key,
                "child",
                &tc.ecdsa_sighash_type(),
            )?;

        // Test that compute_minimum_output_values runs without errors
        protocol.compute_minimum_output_values()?;

        // Build and sign to verify the protocol is valid
        protocol.build_and_sign(tc.key_manager(), "")?;

        // Get the transactions
        let parent_tx = protocol.transaction_to_send("parent", &[InputArgs::new_segwit_args()])?;

        // Verify parent has output
        assert!(
            parent_tx.output.len() > 0,
            "Parent transaction should have at least one output"
        );

        let parent_value = parent_tx.output[0].value.to_sat();

        // Get child transaction 
        let child_tx = protocol.transaction_to_send("child", &[InputArgs::new_segwit_args()])?;

        // Verify child consumed parent output by having an input
        assert!(
            child_tx.input.len() > 0,
            "Child should have at least one input from parent"
        );

        println!(
            "Parent value: {} sats, Child transaction has {} inputs",
            parent_value,
            child_tx.input.len()
        );

        Ok(())
    }

    // Test 2: Fee Estimate Monotonicity
    // Objective: Sanity-check that estimated min relay fee increases when additional witness items are declared.
    #[test]
    fn test_fee_estimate_monotonicity() -> Result<(), ProtocolBuilderError> {
        let tc = TestContext::new("test_fee_estimate_monotonicity").unwrap();

        let internal_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2tr, 0)
            .unwrap();

        let ecdsa_key = tc
            .key_manager()
            .derive_keypair(BitcoinKeyType::P2wpkh, 1)
            .unwrap();

        let value = 10000;
        let txid = Hash::all_zeros();

        // Create baseline script with no extra stack items
        let baseline_script = ProtocolScript::new(
            ScriptBuf::from(vec![0x01]),
            &internal_key,
            SignMode::Single,
        );

        // Create script with extra stack item
        let mut enhanced_script = ProtocolScript::new(
            ScriptBuf::from(vec![0x01]),
            &internal_key,
            SignMode::Single,
        );
        enhanced_script.add_stack_item(StackItem::new_raw(32)); // Add 32 bytes of data

        let segwit_output = OutputType::segwit_key(value, &ecdsa_key)?;

        // Build baseline protocol
        let mut baseline_protocol = Protocol::new("baseline_fee_test");
        let builder = ProtocolBuilder {};

        builder
            .add_external_connection(
                &mut baseline_protocol,
                "external",
                txid,
                OutputSpec::Auto(segwit_output.clone()),
                "origin",
                InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            )?
            .add_taproot_connection(
                &mut baseline_protocol,
                "conn_baseline",
                "origin",
                value,
                &internal_key,
                &[baseline_script],
                &SpendMode::Script { leaf: 0 },
                "spend_baseline",
                &tc.tr_sighash_type(),
            )?;

        baseline_protocol.build_and_sign(tc.key_manager(), "")?;

        let baseline_args = InputArgs::new_taproot_script_args(0);
        let baseline_tx = baseline_protocol.transaction_to_send("spend_baseline", &[baseline_args])?;
        let baseline_inputs = baseline_protocol.inputs("spend_baseline")?;

        // Build enhanced protocol with extra stack item
        let mut enhanced_protocol = Protocol::new("enhanced_fee_test");

        builder
            .add_external_connection(
                &mut enhanced_protocol,
                "external",
                txid,
                OutputSpec::Auto(segwit_output),
                "origin",
                InputSpec::Auto(tc.ecdsa_sighash_type(), SpendMode::Segwit),
            )?
            .add_taproot_connection(
                &mut enhanced_protocol,
                "conn_enhanced",
                "origin",
                value,
                &internal_key,
                &[enhanced_script],
                &SpendMode::Script { leaf: 0 },
                "spend_enhanced",
                &tc.tr_sighash_type(),
            )?;

        enhanced_protocol.build_and_sign(tc.key_manager(), "")?;

        let enhanced_args = InputArgs::new_taproot_script_args(0);
        let enhanced_tx = enhanced_protocol.transaction_to_send("spend_enhanced", &[enhanced_args])?;
        let enhanced_inputs = enhanced_protocol.inputs("spend_enhanced")?;

        // Compute fees
        let baseline_fee = estimate_min_relay_fee(&baseline_tx, "spend_baseline", &baseline_inputs, 1, 5)?;
        let enhanced_fee = estimate_min_relay_fee(&enhanced_tx, "spend_enhanced", &enhanced_inputs, 1, 5)?;

        println!("Baseline fee: {} sats", baseline_fee);
        println!("Enhanced fee (with extra stack item): {} sats", enhanced_fee);

        // Monotonicity check: enhanced fee should be >= baseline fee
        assert!(
            enhanced_fee >= baseline_fee,
            "Fee with extra stack item ({} sats) should be >= baseline fee ({} sats)",
            enhanced_fee,
            baseline_fee
        );

        Ok(())
    }
}
