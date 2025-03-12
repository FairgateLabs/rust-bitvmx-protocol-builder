use std::rc::Rc;

use bitcoin::{key::UntweakedPublicKey, secp256k1::Scalar, PublicKey, Txid};
use key_manager::{key_manager::KeyManager, keystorage::keystore::KeyStore};
use storage_backend::storage::Storage;

use crate::{
    errors::ProtocolBuilderError,
    graph::{input::SighashType, output::OutputSpendingType},
    scripts::ProtocolScript,
};

use super::protocol::Protocol;

pub struct ProtocolBuilder {
    protocol: Protocol,
    storage: Rc<Storage>,
}
impl ProtocolBuilder {
    pub fn new(protocol_name: &str, storage: Rc<Storage>) -> Result<Self, ProtocolBuilderError> {
        match Protocol::load(protocol_name, storage.clone())? {
            Some(protocol) => Ok(Self { protocol, storage }),
            None => Ok(Self {
                protocol: Protocol::new(protocol_name),
                storage,
            }),
        }
    }

    pub fn build(&mut self) -> Result<Protocol, ProtocolBuilderError> {
        self.protocol.build()
    }

    pub fn build_and_sign<K: KeyStore>(
        &mut self,
        key_manager: &KeyManager<K>,
    ) -> Result<Protocol, ProtocolBuilderError> {
        self.protocol.build_and_sign(key_manager)
    }

    pub fn add_taproot_key_spend_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        internal_key: &PublicKey,
        tweak: &Scalar,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_taproot_tweaked_key_spend_output(
            transaction_name,
            value,
            internal_key,
            tweak,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_taproot_script_spend_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        internal_key: &UntweakedPublicKey,
        spending_scripts: &[ProtocolScript],
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_taproot_script_spend_output(
            transaction_name,
            value,
            internal_key,
            spending_scripts,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_p2wpkh_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        public_key: &PublicKey,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol
            .add_p2wpkh_output(transaction_name, value, public_key)?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_p2wsh_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        script_pubkey: &ProtocolScript,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol
            .add_p2wsh_output(transaction_name, value, script_pubkey)?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_timelock_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        internal_key: &UntweakedPublicKey,
        expired_script: &ProtocolScript,
        renew_script: &ProtocolScript,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_timelock_output(
            transaction_name,
            value,
            internal_key,
            expired_script,
            renew_script,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_speedup_output(
        &mut self,
        transaction_name: &str,
        value: u64,
        speedup_public_key: &PublicKey,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol
            .add_speedup_output(transaction_name, value, speedup_public_key)?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_op_return_output(
        &mut self,
        transaction_name: &str,
        data: Vec<u8>,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_op_return_output(transaction_name, data)?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_taproot_key_spend_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_taproot_key_spend_input(
            transaction_name,
            previous_output,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_taproot_script_spend_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_taproot_script_spend_input(
            transaction_name,
            previous_output,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_p2wpkh_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol
            .add_p2wpkh_input(transaction_name, previous_output, sighash_type)?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_p2wsh_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol
            .add_p2wsh_input(transaction_name, previous_output, sighash_type)?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_timelock_input(
        &mut self,
        transaction_name: &str,
        previous_output: u32,
        blocks: u16,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_timelock_input(
            transaction_name,
            previous_output,
            blocks,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_taproot_tweaked_key_spend_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        value: u64,
        internal_key: &PublicKey,
        tweak: &Scalar,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_taproot_tweaked_key_spend_connection(
            connection_name,
            from,
            value,
            internal_key,
            tweak,
            to,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_taproot_key_spend_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        value: u64,
        internal_key: &PublicKey,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_taproot_key_spend_connection(
            connection_name,
            from,
            value,
            internal_key,
            to,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_taproot_script_spend_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        value: u64,
        internal_key: &UntweakedPublicKey,
        spending_scripts: &[ProtocolScript],
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_taproot_script_spend_connection(
            connection_name,
            from,
            value,
            internal_key,
            spending_scripts,
            to,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_p2wpkh_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        value: u64,
        public_key: &PublicKey,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_p2wpkh_connection(
            connection_name,
            from,
            value,
            public_key,
            to,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn add_p2wsh_connection(
        &mut self,
        connection_name: &str,
        from: &str,
        value: u64,
        script: &ProtocolScript,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_p2wsh_connection(
            connection_name,
            from,
            value,
            script,
            to,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_timelock_connection(
        &mut self,
        from: &str,
        value: u64,
        internal_key: &UntweakedPublicKey,
        expired_script: &ProtocolScript,
        renew_script: &ProtocolScript,
        to: &str,
        blocks: u16,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.add_timelock_connection(
            from,
            value,
            internal_key,
            expired_script,
            renew_script,
            to,
            blocks,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn connect_with_external_transaction(
        &mut self,
        txid: Txid,
        output_index: u32,
        output_spending_type: OutputSpendingType,
        to: &str,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol.connect_with_external_transaction(
            txid,
            output_index,
            output_spending_type,
            to,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(self)
    }

    pub fn connect(
        &mut self,
        connection_name: &str,
        from: &str,
        output_index: u32,
        to: &str,
        input_index: u32,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.protocol
            .connect(connection_name, from, output_index, to, input_index)?;
        self.save_protocol()?;

        Ok(self)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn connect_rounds(
        &mut self,
        connection_name: &str,
        rounds: u32,
        from: &str,
        to: &str,
        value: u64,
        spending_scripts_from: &[ProtocolScript],
        spending_scripts_to: &[ProtocolScript],
        sighash_type: &SighashType,
    ) -> Result<(String, String), ProtocolBuilderError> {
        let result = self.protocol.connect_rounds(
            connection_name,
            rounds,
            from,
            to,
            value,
            spending_scripts_from,
            spending_scripts_to,
            sighash_type,
        )?;
        self.save_protocol()?;

        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_linked_message_connection(
        &mut self,
        from: &str,
        to: &str,
        protocol_value: u64,
        protocol_scripts: &[ProtocolScript],
        timelock_value: u64,
        timelock_expired: &ProtocolScript,
        timelock_renew: &ProtocolScript,
        speedup_value: u64,
        speedup_key: &PublicKey,
        sighash_type: &SighashType,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_taproot_script_spend_connection(
            "linked_messages",
            from,
            protocol_value,
            &Protocol::create_unspendable_key()?,
            protocol_scripts,
            to,
            sighash_type,
        )?;
        self.add_timelock_connection(
            from,
            timelock_value,
            &Protocol::create_unspendable_key()?,
            timelock_expired,
            timelock_renew,
            to,
            0,
            sighash_type,
        )?;
        self.add_speedup_output(from, speedup_value, speedup_key)?;

        Ok(self)
    }

    pub fn add_outputs_for_external_transaction(
        &mut self,
        transaction_name: &str,
        output_value: u64,
        output_public_key: &PublicKey,
        speedup_value: u64,
        speedup_public_key: &PublicKey,
    ) -> Result<&mut Self, ProtocolBuilderError> {
        self.add_p2wpkh_output(transaction_name, output_value, output_public_key)?;
        self.add_speedup_output(transaction_name, speedup_value, speedup_public_key)?;

        Ok(self)
    }

    pub fn visualize(&self) -> Result<String, ProtocolBuilderError> {
        self.protocol.visualize()
    }

    fn save_protocol(&self) -> Result<(), ProtocolBuilderError> {
        self.protocol.save(self.storage.clone())?;
        Ok(())
    }
}
