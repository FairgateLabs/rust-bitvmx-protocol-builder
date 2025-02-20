use bitcoin::ScriptBuf;
use key_manager::winternitz::WinternitzSignature;

#[derive(Clone, Debug)]
pub struct SpendingArgs {
    args: Vec<Vec<u8>>,
    taproot_leaf: Option<ScriptBuf>,
}

impl SpendingArgs {
    pub fn new_taproot_args(taproot_leaf: &ScriptBuf) -> Self {
        SpendingArgs {
            args: vec![],
            taproot_leaf: Some(taproot_leaf.clone()),
        }
    }

    pub fn new_args() -> Self {
        SpendingArgs {
            args: vec![],
            taproot_leaf: None,
        }
    }

    pub fn push_slice(&mut self, args: &[u8]) -> &mut Self {
        self.args.push(args.to_vec());
        self
    }

    pub fn push_taproot_signature(
        &mut self,
        taproot_signature: bitcoin::taproot::Signature,
    ) -> &mut Self {
        self.push_slice(&taproot_signature.serialize());
        self
    }

    pub fn push_ecdsa_signature(
        &mut self,
        ecdsa_signature: bitcoin::ecdsa::Signature,
    ) -> &mut Self {
        self.push_slice(&ecdsa_signature.serialize());
        self
    }

    pub fn push_winternitz_signature(
        &mut self,
        winternitz_signature: WinternitzSignature,
    ) -> &mut Self {
        let hashes = winternitz_signature.to_hashes();
        let digits = winternitz_signature.checksummed_message_digits();

        for (hash, digit) in hashes.iter().zip(digits.iter()) {
            let digit = if *digit == 0 {
                [].to_vec()
            } else {
                [*digit].to_vec()
            };

            self.push_slice(hash);
            self.push_slice(&digit);
        }

        self
    }

    pub fn get_taproot_leaf(&self) -> Option<ScriptBuf> {
        self.taproot_leaf.clone()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Vec<u8>> {
        self.args.iter()
    }
}
