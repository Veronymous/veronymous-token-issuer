#[macro_use]
extern crate log;

use std::fs;
use crate::config::TokenIssuerConfig;
use crate::controller::token_info_controller::TokenInfoController;
use crate::controller::token_issuer_controller::TokenIssuerController;
use crate::grpc::veronymous_token_info_service::veronymous_token_info_service_server::VeronymousTokenInfoServiceServer;
use crate::grpc::veronymous_token_service::veronymous_token_service_server::VeronymousTokenServiceServer;
use crate::issuer::TokenIssuer;
use crate::manager::KeyManager;
use std::net::SocketAddr;
use tonic::transport::Server;

mod config;
mod controller;
mod error;
mod grpc;
mod issuer;
mod manager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("Loading token issuer...");

    // Config
    let config = TokenIssuerConfig::load().unwrap();

    // Services
    let key_manager = KeyManager::create(&config).await.unwrap();
    let token_issuer = TokenIssuer::new(key_manager.clone());

    // Controllers
    let token_info_controller =
        VeronymousTokenInfoServiceServer::new(TokenInfoController::new(key_manager.clone()));

    let token_issuer_controller =
        VeronymousTokenServiceServer::new(TokenIssuerController::new(token_issuer));

    // TLS config

    // Encryption
    let cert = fs::read(&config.tls_cert).unwrap();
    let key = fs::read(&config.tls_key).unwrap();

    let id = tonic::transport::Identity::from_pem(cert, key);
    let tls_config = tonic::transport::ServerTlsConfig::new().identity(id);

    // Auth
    let ca = fs::read(&config.auth_ca).unwrap();
    let ca = tonic::transport::Certificate::from_pem(ca);
    let tls_config = tls_config.client_ca_root(ca);

    Server::builder()
        .tls_config(tls_config)
        .unwrap()
        .add_service(token_info_controller)
        .add_service(token_issuer_controller)
        .serve(SocketAddr::new(config.host, config.port))
        .await?;

    Ok(())
}
