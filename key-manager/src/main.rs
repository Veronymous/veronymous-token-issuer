#[macro_use]
extern crate log;

mod config;
mod controller;
mod error;
mod grpc;
mod manager;

use std::fs;
use crate::config::KeyManagerConfig;
use crate::controller::KeyManagerController;
use crate::grpc::key_manager_service::key_manager_service_server::KeyManagerServiceServer;
use crate::manager::KeyManager;
use std::net::SocketAddr;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    info!("Loading Key Manager...");

    // Configuration
    let config = KeyManagerConfig::load().unwrap();

    // Services
    let key_manager = KeyManager::create(&config).unwrap();

    // Controller
    let key_manager_controller =
        KeyManagerServiceServer::new(KeyManagerController::new(key_manager));

    // TLS Config

    // Encryption
    let cert = fs::read(&config.tls_cert).unwrap();
    let key = fs::read(&config.tls_key).unwrap();

    let id = tonic::transport::Identity::from_pem(cert, key);
    let tls_config = tonic::transport::ServerTlsConfig::new().identity(id);

    // Auth
    let ca = fs::read(&config.client_ca).unwrap();
    let ca = tonic::transport::Certificate::from_pem(ca);
    let tls_config = tls_config.client_ca_root(ca);

    info!("Staring server on {}:{}", config.host, config.port);

    Server::builder()
        .tls_config(tls_config)
        .unwrap()
        .add_service(key_manager_controller)
        .serve(SocketAddr::new(config.host, config.port))
        .await?;

    Ok(())
}
