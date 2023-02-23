use crate::grpc::veronymous_token_service::veronymous_token_service_server::VeronymousTokenService;
use crate::grpc::veronymous_token_service::{TokenRequest, TokenResponse};
use crate::issuer::TokenIssuer;
use tonic::{Request, Response, Status};
use veronymous_token::root_exchange::RootTokenRequest;
use veronymous_token::serde::Serializable;

pub struct TokenIssuerController {
    token_issuer: TokenIssuer,
}

impl TokenIssuerController {
    pub fn new(token_issuer: TokenIssuer) -> Self {
        Self { token_issuer }
    }
}

#[tonic::async_trait]
impl VeronymousTokenService for TokenIssuerController {
    async fn issue_token(
        &self,
        request: Request<TokenRequest>,
    ) -> Result<Response<TokenResponse>, Status> {
        let request = request.into_inner();

        debug!("Got 'issue_token' request: {:?}", request);

        let token_request = request.token_request;

        // parse the token request
        let token_request = match RootTokenRequest::deserialize(&token_request) {
            Ok(request) => request,
            Err(e) => {
                debug!("Could not decode veronymous root token request. {:?}", e);

                return Err(Status::invalid_argument("Invalid token request."));
            }
        };

        let token_response = match self.token_issuer.issue_current_token(&token_request).await {
            Ok(response) => response,
            Err(e) => {
                debug!("Could not issue token response. {:?}", e);

                return Err(Status::aborted("Could not issue token"));
            }
        };

        let response = TokenResponse { token_response };

        Ok(Response::new(response))
    }

    async fn issue_next_token(
        &self,
        request: Request<TokenRequest>,
    ) -> Result<Response<TokenResponse>, Status> {
        let request = request.into_inner();

        debug!("Got 'issue_next_token' request: {:?}", request);

        let token_request = request.token_request;

        // parse the token request
        let token_request = match RootTokenRequest::deserialize(&token_request) {
            Ok(request) => request,
            Err(e) => {
                debug!("Could not decode veronymous root token request. {:?}", e);

                return Err(Status::invalid_argument("Invalid token request."));
            }
        };

        let token_response = match self.token_issuer.issue_next_token(&token_request).await {
            Ok(response) => response,
            Err(e) => {
                debug!("Could not issue token response. {:?}", e);

                return Err(Status::aborted("Could not issue token"));
            }
        };

        let response = TokenResponse { token_response };

        Ok(Response::new(response))
    }
}
