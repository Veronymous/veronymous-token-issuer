use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum KeyManagerError {
    #[error("DB Error. {0}")]
    DBError(String),

    #[error("Serialization error. {0}")]
    SerializationError(String),

    #[error("Deserialization error. {0}")]
    DeserializationError(String),

    #[error("Not found. {0}")]
    NotFoundError(String),

    #[error("Config error. {0}")]
    ConfigError(String),
}
