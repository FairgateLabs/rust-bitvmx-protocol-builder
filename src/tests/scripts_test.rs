#[cfg(test)]
mod tests {
    use bitcoin::{
        opcodes::all::{OP_CSV, OP_DROP, OP_CHECKSIG, OP_RETURN},
        PublicKey
    };

    use crate::
        scripts::{op_return, timelock}
    ;

    #[test]
    fn test_timelock_output_script() {
        // Arrenge
        let blocks = 587;
        let pubkey_bytes =
            hex::decode("02c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fd")
                .expect("Decoding failed");
        let public_key = PublicKey::from_slice(&pubkey_bytes).expect("Invalid public key format");

        // Act
        let script_timelock = timelock(blocks, &public_key);

        // Assert
        let instructions = script_timelock.get_script().instructions().flatten().collect::<Vec<_>>();
        //println!("instructions: {:?}", instructions);
        assert_eq!(instructions.len(), 5, "Script should have 5 instructions");
        assert_eq!(instructions[0].script_num(), Some(blocks as i64), "First instruction should be a number");
        assert_eq!(instructions[1].opcode(), Some(OP_CSV), "Second instruction should be OP_CSV");
        assert_eq!(instructions[2].opcode(), Some(OP_DROP), "Third instruction should be OP_DROP");
        // First byte is the even byte, we skip it to get the x-only public key
        assert_eq!(instructions[3].push_bytes().unwrap().as_bytes(), &public_key.inner.serialize()[1..], "Fourth instruction should be the public key");
        assert_eq!(instructions[4].opcode(), Some(OP_CHECKSIG), "Fifth instruction should be OP_CHECKSIG");
        // Check the scriptPubKey hex is ok
        let script_timelock_bytes_hex = hex::encode(script_timelock.get_script().to_bytes());
        assert_eq!(script_timelock_bytes_hex, "024b02b27520c6047f9441ed7d6d3045406e95c07cd85a6a6d4c90d35b8c6a568f07cfd511fdac");
    }

    #[test]
    fn test_op_return_output_script() {
        // Arrange
        let number: u64 = 0;
        let mut address = [0u8; 20];
        let decoded_address = hex::decode("7ac5496aee77c1ba1f0854206a26dda82a81d6d8").unwrap();
        address.copy_from_slice(&decoded_address);
        let decoded_xpubkey = hex::decode("741976f972e9aa5e226eae26289b794aac9bbe702f378aa64c6104f16b79298c").unwrap();
        let xpubkey = decoded_xpubkey.as_slice();

        // Push different kind of data
        let mut data = [0u8; 69];
        data.copy_from_slice([
            b"RSK_PEGIN".as_slice(),
            &number.to_be_bytes(),
            &address,
            &xpubkey
        ].concat().as_slice());

        // Act
        let script_op_return = op_return(&data);

        // Assert
        let instructions = script_op_return.get_script().instructions().flatten().collect::<Vec<_>>();
        //println!("instructions: {:?}", instructions);
        assert_eq!(instructions.len(), 2, "Script should have 2 instructions");
        assert_eq!(instructions[0].opcode(), Some(OP_RETURN), "First instruction should be OP_RETURN");
        assert_eq!(instructions[1].push_bytes().unwrap().as_bytes(), &data, "Second instruction should be data we sent");
        // Check the scriptPubKey hex is ok
        let script_timelock_bytes_hex = hex::encode(script_op_return.get_script().to_bytes());
        assert_eq!(script_timelock_bytes_hex, "6a4552534b5f504547494e00000000000000007ac5496aee77c1ba1f0854206a26dda82a81d6d8741976f972e9aa5e226eae26289b794aac9bbe702f378aa64c6104f16b79298c");
    }
}