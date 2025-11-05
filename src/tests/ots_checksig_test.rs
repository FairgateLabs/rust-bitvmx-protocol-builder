#[cfg(test)]
mod tests {

    use crate::errors::ScriptError;
    use crate::scripts::{ots_checksig, ots_checksig_old, ots_checksig_old_using_stack};
    use crate::tests::utils::TestContext;
    use bitcoin::ScriptBuf;
    use key_manager::winternitz::WinternitzType;

    #[test]
    fn test_ots_checksig() {
        use crate::tests::utils::TestContext;
        use key_manager::winternitz::WinternitzType;

        // Create test context with KeyManager
        let tc = TestContext::new("test_ots_checksig_old_comprehensive").unwrap();
        let key_manager = tc.key_manager();

        // Test with different WinternitzType variants and message sizes
        let test_cases = vec![(WinternitzType::HASH160, 1)];

        for (key_type, message_size) in test_cases {
            // Create real WinternitzPublicKey through KeyManager
            let winternitz_key = key_manager
                .derive_winternitz(message_size, key_type, 0)
                .unwrap();

            // Test both keep_message scenarios
            for keep_message in [false, true] {
                // Test ots_checksig_old (should work for all types)

                println!("old");
                let old_script_result = ots_checksig_old(&winternitz_key, keep_message).unwrap();
                println!("old stack");
                let old_script_using_stack_result =
                    ots_checksig_old_using_stack(&winternitz_key, keep_message).unwrap();

                println!("new");

                let new_script_result = ots_checksig(&winternitz_key, keep_message).unwrap();

                println!("old_script_result: {:?}", old_script_result);
                println!(
                    "old_script_using_stack_result: {:?}",
                    old_script_using_stack_result
                );
                assert_eq!(old_script_result, old_script_using_stack_result);
            }
        }
    }
}
