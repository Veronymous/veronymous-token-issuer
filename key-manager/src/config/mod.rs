use crate::error::KeyManagerError;
use crate::error::KeyManagerError::ConfigError;
use config::{Config, File};
use serde::Deserialize;
use std::net::IpAddr;

const CONFIG_ENV_VAR: &str = "VERONYMOUS_KEY_MANAGER_CONFIG";
const DEFAULT_CONFIG_LOCATION: &str = "veronymous_key_manager_config.yml";

#[derive(Clone, Debug, Deserialize)]
pub struct KeyManagerConfig {
    pub host: IpAddr,

    pub port: u16,

    pub tls_key: String,

    pub tls_cert: String,

    // Client ca for tls authentication
    pub client_ca: String,

    pub key_file: String,

    pub key_lifetime: u64,
}

impl KeyManagerConfig {
    pub fn load() -> Result<Self, KeyManagerError> {
        // Get the config location
        let config_location =
            std::env::var(CONFIG_ENV_VAR).unwrap_or_else(|_| DEFAULT_CONFIG_LOCATION.into());

        // Load the config
        let mut config = Config::new();
        config
            .merge(File::with_name(&config_location))
            .map_err(|e| ConfigError(format!("{:?}", e)))?;

        Ok(config
            .try_into()
            .map_err(|e| ConfigError(format!("{:?}", e)))?)
    }
}
