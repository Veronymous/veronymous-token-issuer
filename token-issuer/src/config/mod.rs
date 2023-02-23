use crate::error::TokenIssuerError;
use crate::error::TokenIssuerError::ConfigError;
use config::{Config, File};
use serde::Deserialize;
use std::net::IpAddr;

const CONFIG_ENV_VAR: &str = "VERONYMOUS_TOKEN_ISSUER_CONFIG";
const DEFAULT_CONFIG_LOCATION: &str = "veronymous_token_issuer_config.yml";

#[derive(Clone, Debug, Deserialize)]
pub struct TokenIssuerConfig {
    pub host: IpAddr,

    pub port: u16,

    pub key_lifetime: u64,

    pub key_manager_endpoint: String,

    pub key_manager_ca: String,

    pub key_manager_auth_cert: String,

    pub key_manager_auth_key: String,

    pub tls_cert: String,

    pub tls_key: String,

    pub auth_ca: String
}

impl TokenIssuerConfig {
    pub fn load() -> Result<Self, TokenIssuerError> {
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
