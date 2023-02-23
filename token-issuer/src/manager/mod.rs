use crate::config::TokenIssuerConfig;
use crate::error::TokenIssuerError;
use crate::error::TokenIssuerError::{ConnectionError, DeserializationError, KeyManagerError};
use crate::manager::grpc::key_manager_service::key_manager_service_client::KeyManagerServiceClient;
use crate::manager::grpc::key_manager_service::GetIssuingKeyRequest;
use ps_signatures::keys::{PsParams, PsPublicKey, PsSigningKey};
use ps_signatures::serde::Serializable;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, thread};
use tokio::sync::RwLock;
use tokio::time::Instant;
use tonic::transport::{Channel, Endpoint};
use tonic::Code;

mod grpc;

const RETRIEVE_KEY_ATTEMPTS: u8 = 10;
const RETRIEVE_KEY_INTERVAL: u64 = 2;

// This class talks to the key manager
pub struct KeyManager {
    key_manager_client: KeyManagerServiceClient<Channel>,

    key_lifetime: u64,

    current_key: Option<KeyProfile>,

    next_key: Option<KeyProfile>,
}

impl KeyManager {
    pub async fn create(config: &TokenIssuerConfig) -> Result<Arc<RwLock<Self>>, TokenIssuerError> {
        // Key manager encryption
        let tls_ca = fs::read(&config.key_manager_ca).unwrap();
        let tls_ca = tonic::transport::Certificate::from_pem(tls_ca);

        // TLS authentication credentials
        let auth_cert = fs::read(&config.key_manager_auth_cert).unwrap();
        let auth_cert_key = fs::read(&config.key_manager_auth_key).unwrap();

        let auth_id = tonic::transport::Identity::from_pem(&auth_cert, &auth_cert_key);

        // TLS Config
        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tls_ca)
            .identity(auth_id);

        let endpoint = Endpoint::from_str(&config.key_manager_endpoint)
            .unwrap()
            .tls_config(tls_config.clone())
            .unwrap();

        let key_manager_client = KeyManagerServiceClient::connect(endpoint)
            .await
            .map_err(|e| ConnectionError(format!("Could not connect to key manager. {:?}", e)))?;

        let mut key_manager = Self {
            key_manager_client,
            key_lifetime: config.key_lifetime * 60, // To seconds
            current_key: None,
            next_key: None,
        };

        // Update keys
        key_manager.update_keys().await?;

        let key_manager = Arc::new(RwLock::new(key_manager));

        //  Schedule key updates
        Self::schedule_key_updates(key_manager.clone(), config);

        Ok(key_manager)
    }

    pub fn get_current_key(&self) -> &Option<KeyProfile> {
        &self.current_key
    }

    pub fn get_next_key(&self) -> &Option<KeyProfile> {
        &self.next_key
    }

    fn schedule_key_updates(key_manager: Arc<RwLock<KeyManager>>, config: &TokenIssuerConfig) {
        // Convert minutes to seconds
        let key_lifetime = config.key_lifetime * 60;

        let next_key_update = Self::calculate_next_key_update(key_lifetime);
        let key_lifetime = Duration::from_secs(key_lifetime);

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval_at(next_key_update, key_lifetime);

            debug!("Scheduled key updates...");
            loop {
                interval_timer.tick().await;

                debug!("Updating keys...");

                let mut key_manager = key_manager.write().await;

                // TODO: Catch error or panic?
                key_manager.update_keys().await.unwrap();
            }
        });
    }

    async fn update_keys(&mut self) -> Result<(), TokenIssuerError> {
        let (current_epoch, next_epoch) = self.get_key_epochs();

        debug!("Current epoch: {}", current_epoch);
        debug!("Next epoch: {}", next_epoch);

        // Current key
        if let Some(key) = &self.current_key {
            if current_epoch != key.epoch {
                // Update is required
                let current_key = self.get_key(current_epoch).await?;
                self.current_key = Some(current_key);
            }
        } else {
            // Update is required
            let current_key = self.get_key(current_epoch).await?;
            self.current_key = Some(current_key);
        }

        // Next key
        if let Some(key) = &self.next_key {
            if next_epoch != key.epoch {
                // Update is required
                let next_key = self.get_key(next_epoch).await?;
                self.next_key = Some(next_key);
            }
        } else {
            // Update is required
            let next_key = self.get_key(next_epoch).await?;
            self.next_key = Some(next_key);
        }

        Ok(())
    }

    async fn get_key(&mut self, epoch: u64) -> Result<KeyProfile, TokenIssuerError> {
        let mut response = None;

        for _ in 0..RETRIEVE_KEY_ATTEMPTS {
            debug!("Retrieving key for epoch {}", epoch);
            let request = tonic::Request::new(GetIssuingKeyRequest { epoch });

            let result = match self.key_manager_client.get_issuing_key(request).await {
                Ok(response) => Some(response),
                Err(e) => {
                    if Code::NotFound == e.code() {
                        debug!("Key retrieval failed, trying again...");
                        // Try again
                        None
                    } else {
                        return Err(KeyManagerError(format!("Could not get key. {:?}", e)));
                    }
                }
            };

            if let Some(r) = result {
                response = Some(r);
                break;
            }

            thread::sleep(Duration::from_secs(RETRIEVE_KEY_INTERVAL));
        }

        if let None = response {
            return Err(KeyManagerError(format!("Could not get issuing key.")));
        }

        // Decode the response
        let response = response.unwrap().into_inner();

        let params = PsParams::deserialize(&response.params)
            .map_err(|e| DeserializationError(format!("Could not deserialize {:?}", e)))?;
        let signing_key = PsSigningKey::deserialize(&response.signing_key)
            .map_err(|e| DeserializationError(format!("Could not deserialize {:?}", e)))?;
        let public_key = PsPublicKey::deserialize(&response.public_key)
            .map_err(|e| DeserializationError(format!("Could not deserialize {:?}", e)))?;

        Ok(KeyProfile {
            epoch,
            params,
            signing_key,
            public_key,
            key_lifetime: self.key_lifetime,
        })
    }

    // (current, next)
    fn get_key_epochs(&self) -> (u64, u64) {
        let now = SystemTime::now();
        let now = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let current_epoch = now - (now % self.key_lifetime);

        let next_epoch = current_epoch + self.key_lifetime;

        (current_epoch, next_epoch)
    }

    fn calculate_next_key_update(key_lifetime: u64) -> Instant {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let now_instant = Instant::now();

        let current_epoch = now - (now % key_lifetime);
        let next_epoch = current_epoch + key_lifetime;

        // Get next epoch as instant
        let time_until_next_epoch = next_epoch - now;
        let next_epoch = now_instant + Duration::from_secs(time_until_next_epoch);

        next_epoch
    }
}

pub struct KeyProfile {
    pub epoch: u64,

    pub params: PsParams,

    pub signing_key: PsSigningKey,

    pub public_key: PsPublicKey,

    pub key_lifetime: u64,
}
