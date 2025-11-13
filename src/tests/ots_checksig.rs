#[cfg(test)]
mod tests {
    use bitcoin_script_stack::stack::StackTracker;
    use key_manager::winternitz::{
        checksum_length, message_digits_length, to_checksummed_message, Winternitz, WinternitzType,
    };

    use crate::scripts::ots_checksig_internal;

    // The purpose of this test is to evaluate the ots_checksig functionality by using its internal
    // method, ots_checksig_internal. This involves passing signatures obtained from the key manager
    // and verifying the correct execution of the stack.
    #[test]
    fn test_ots_checksig() {
        let message_bytes = &[1];
        let message_digits_length = message_digits_length(message_bytes.len());
        let checksummed_message = to_checksummed_message(message_bytes);
        let checksum_size = checksum_length(message_digits_length);
        let message_size = checksummed_message.len() - checksum_size;

        let master_secret = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let winternitz = Winternitz::new();
        let pk = winternitz
            .generate_private_key(
                &master_secret,
                WinternitzType::HASH160,
                message_size,
                checksum_size,
                1,
            )
            .unwrap();

        let pubk = winternitz
            .generate_public_key(
                &master_secret,
                WinternitzType::HASH160,
                message_size,
                checksum_size,
                1,
            )
            .unwrap();

        let sig = winternitz.sign_message(message_size, &checksummed_message, &pk);

        let mut stack = StackTracker::new();

        for i in 0..sig.len() {
            stack.hexstr(&hex::encode(sig.to_hashes()[i].clone()));
            stack.number(sig.checksummed_message_digits()[i] as u32);
        }

        let _ = ots_checksig_internal(&mut stack, &pubk, false).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }
}
