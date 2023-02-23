use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum TokenIssuerError {
    #[error("Config error. {0}")]
    ConfigError(String),

    #[error("Connection error. {0}")]
    ConnectionError(String),

    #[error("Key manager error. {0}")]
    KeyManagerError(String),

    #[error("Deserialization error. {0}")]
    DeserializationError(String),

    #[error("Illegal state error. {0}")]
    IllegalStateError(String),

    #[error("Token error. {0}")]
    TokenError(String),
}
