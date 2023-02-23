use crate::error::KeyManagerError;
use crate::grpc::key_manager_service::key_manager_service_server::KeyManagerService;
use crate::grpc::key_manager_service::{GetIssuingKeyRequest, GetIssuingKeyResponse};
use crate::manager::{KeyManager, KeyProfile};
use ps_signatures::serde::Serializable;
use std::sync::{Arc, Mutex};
use tonic::{Request, Response, Status};

pub struct KeyManagerController {
    key_manager: Arc<Mutex<KeyManager>>,
}

impl KeyManagerController {
    pub fn new(key_manager: Arc<Mutex<KeyManager>>) -> Self {
        Self { key_manager }
    }
}

#[tonic::async_trait]
impl KeyManagerService for KeyManagerController {
    async fn get_issuing_key(
        &self,
        request: Request<GetIssuingKeyRequest>,
    ) -> Result<Response<GetIssuingKeyResponse>, Status> {
        let request = request.into_inner();

        let key_manager = self.key_manager.lock().unwrap();

        let key_profile = match key_manager.get_key_profile(request.epoch) {
            Ok(key_profile) => key_profile,
            Err(err) => {
                return match err {
                    KeyManagerError::NotFoundError(e) => Err(Status::not_found(e.to_string())),
                    e => Err(Status::aborted(e.to_string())),
                }
            }
        };

        Ok(Response::new(key_profile.try_into()?))
    }
}

impl TryInto<GetIssuingKeyResponse> for KeyProfile {
    type Error = Status;

    fn try_into(self) -> Result<GetIssuingKeyResponse, Self::Error> {
        let signing_key = self
            .signing_key
            .serialize()
            .map_err(|_| Status::aborted("Could not serialize signing key"))?;

        let public_key = self
            .public_key
            .serialize()
            .map_err(|_| Status::aborted("Could not serialize public key"))?;

        let params = self
            .params
            .serialize()
            .map_err(|_| Status::aborted("Could not serialize params"))?;

        Ok(GetIssuingKeyResponse {
            signing_key,
            public_key,
            params,
        })
    }
}
