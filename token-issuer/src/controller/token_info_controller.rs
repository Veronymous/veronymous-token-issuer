use crate::grpc::veronymous_token_info_service::veronymous_token_info_service_server::VeronymousTokenInfoService;
use crate::grpc::veronymous_token_info_service::{TokenInfo, TokenInfoRequest};
use crate::manager::{KeyManager, KeyProfile};
use ps_signatures::serde::Serializable;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};

pub struct TokenInfoController {
    key_manager: Arc<RwLock<KeyManager>>,
}

impl TokenInfoController {
    pub fn new(key_manager: Arc<RwLock<KeyManager>>) -> Self {
        Self { key_manager }
    }
}

#[tonic::async_trait]
impl VeronymousTokenInfoService for TokenInfoController {
    async fn get_token_info(
        &self,
        _: Request<TokenInfoRequest>,
    ) -> Result<Response<TokenInfo>, Status> {
        debug!("Got 'get_token_info' request.");

        let key_manager = self.key_manager.read().await;

        let key_profile = match key_manager.get_current_key() {
            Some(key_profile) => key_profile,
            None => {
                error!("current key profile not found");
                return Err(Status::not_found("Could not get token info."));
            }
        };

        Ok(Response::new(key_profile.try_into()?))
    }

    async fn get_next_token_info(
        &self,
        _: Request<TokenInfoRequest>,
    ) -> Result<Response<TokenInfo>, Status> {
        debug!("Got 'get_next_token_info' request.");

        let key_manager = self.key_manager.read().await;

        let key_profile = match key_manager.get_next_key() {
            Some(key_profile) => key_profile,
            None => {
                error!("current key profile not found");
                return Err(Status::not_found("Could not get token info."));
            }
        };

        Ok(Response::new(key_profile.try_into()?))
    }
}

impl TryInto<TokenInfo> for &KeyProfile {
    type Error = Status;

    fn try_into(self) -> Result<TokenInfo, Status> {
        let params = match self.params.serialize() {
            Ok(params) => params,
            Err(e) => {
                error!("Could not serialize ps params. {:?}", e);
                return Err(Status::internal("Could not serialize ps params"));
            }
        };

        let public_key = match self.public_key.serialize() {
            Ok(public_key) => public_key,
            Err(e) => {
                error!("Could not serialize public key. {:?}", e);
                return Err(Status::internal("Could not serialize public key"));
            }
        };

        Ok(TokenInfo {
            params,
            public_key,
            key_lifetime: self.key_lifetime,
        })
    }
}
