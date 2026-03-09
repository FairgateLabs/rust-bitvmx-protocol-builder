#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use bitcoin::Network;

    use crate::{config::Config, errors::ConfigError};

    // Serialize all env-var-dependent tests to avoid race conditions in parallel test runs
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // Test 1: Load Development Config (requested scenario)
    // Objective: Validate Config::new() loads config/development.json when BITVMX_ENV=development.
    // Expected: Parses successfully; builder.ecdsa_sighash_type == "SIGHASH_ALL", rpc.network == regtest.
    #[test]
    fn test_load_development_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("BITVMX_ENV", "development");

        let config = Config::new().expect("development config should load successfully");

        assert_eq!(
            config.builder.ecdsa_sighash_type,
            "SIGHASH_ALL",
            "builder.ecdsa_sighash_type should be SIGHASH_ALL"
        );
        assert_eq!(
            config.rpc.network,
            Network::Regtest,
            "rpc.network should be regtest"
        );

        std::env::remove_var("BITVMX_ENV");
    }

    // Test 2: Default Env Fallback
    // Objective: Validate that when BITVMX_ENV is not set, Config::new() falls back to development.
    // Expected: Parses successfully with development config values.
    #[test]
    fn test_default_env_fallback() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("BITVMX_ENV");

        let config = Config::new().expect("should fall back to development config when BITVMX_ENV is unset");

        assert_eq!(
            config.rpc.network,
            Network::Regtest,
            "fallback config should load development values (regtest network)"
        );
        assert_eq!(
            config.builder.ecdsa_sighash_type,
            "SIGHASH_ALL",
            "fallback config should load development values (SIGHASH_ALL)"
        );
    }

    // Test 3: Unknown Environment Returns Error
    // Objective: Validate that a non-existent environment name returns a ConfigFileError.
    // Expected: Config::new() returns Err(ConfigError::ConfigFileError).
    #[test]
    fn test_unknown_env_returns_error() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("BITVMX_ENV", "nonexistent_env_xyz");

        let result = Config::new();

        match result {
            Err(ConfigError::ConfigFileError(_)) => {}
            Err(e) => panic!("Expected ConfigFileError for unknown environment, got: {:?}", e),
            Ok(_) => panic!("Expected error for unknown environment but config loaded successfully"),
        }

        std::env::remove_var("BITVMX_ENV");
    }

    // Test 4: All Development Fields
    // Objective: Exhaustively validate every readable field from config/development.json.
    // Expected: Each field matches the value defined in the file.
    #[test]
    fn test_all_development_fields() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("BITVMX_ENV", "development");

        let config = Config::new().expect("development config should load successfully");

        // RPC fields (url/username/password are Secret<String> and not directly comparable)
        assert_eq!(config.rpc.network, Network::Regtest);
        assert_eq!(config.rpc.wallet, "test_wallet");

        // Builder fields
        assert_eq!(config.builder.protocol_amount, 200);
        assert_eq!(config.builder.speedup_amount, 9999859);
        assert_eq!(config.builder.locked_amount, 5000000000);
        assert_eq!(config.builder.locked_blocks, 200);
        assert_eq!(config.builder.ecdsa_sighash_type, "SIGHASH_ALL");
        assert_eq!(config.builder.taproot_sighash_type, "SIGHASH_ALL");

        // Key manager fields (Secret fields mnemonic_sentence/passphrase are not directly comparable)
        assert_eq!(config.key_manager.network, "regtest");

        // Key storage fields (path is a plain String; password is Secret and not directly comparable)
        assert_eq!(config.key_storage.path, "/tmp/storage.db");

        std::env::remove_var("BITVMX_ENV");
    }
}
