use crate::error::TokenIssuerError;
use crate::error::TokenIssuerError::{IllegalStateError, TokenError};
use crate::manager::{KeyManager, KeyProfile};
use rand::thread_rng;
use std::sync::Arc;
use tokio::sync::RwLock;
use veronymous_token::root_exchange::{issue_root_token, RootTokenRequest};
use veronymous_token::serde::Serializable;

pub struct TokenIssuer {
    key_manager: Arc<RwLock<KeyManager>>,
}

impl TokenIssuer {
    pub fn new(key_manager: Arc<RwLock<KeyManager>>) -> Self {
        Self { key_manager }
    }
}

impl TokenIssuer {
    pub async fn issue_current_token(
        &self,
        token_request: &RootTokenRequest,
    ) -> Result<Vec<u8>, TokenIssuerError> {
        let key_manager = self.key_manager.read().await;

        let key = key_manager.get_current_key();

        Self::issue_token(token_request, key)
    }

    pub async fn issue_next_token(
        &self,
        token_request: &RootTokenRequest,
    ) -> Result<Vec<u8>, TokenIssuerError> {
        let key_manager = self.key_manager.read().await;

        let key = key_manager.get_next_key();

        Self::issue_token(token_request, key)
    }

    fn issue_token(
        token_request: &RootTokenRequest,
        key: &Option<KeyProfile>,
    ) -> Result<Vec<u8>, TokenIssuerError> {
        let key = match key {
            Some(key) => key,
            None => return Err(IllegalStateError(format!("Missing issuing key."))),
        };

        let mut rng = thread_rng();

        let token_response = issue_root_token(
            token_request,
            &key.signing_key,
            &key.public_key,
            &key.params,
            &mut rng,
        )
        .map_err(|e| TokenError(format!("Could not issue root token. {:?}", e)))?;

        let token_response = token_response.serialize();

        Ok(token_response)
    }
}
