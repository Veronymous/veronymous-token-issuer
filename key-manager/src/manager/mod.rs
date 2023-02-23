use crate::config::KeyManagerConfig;
use crate::error::KeyManagerError;
use crate::error::KeyManagerError::{
    DBError, DeserializationError, NotFoundError, SerializationError,
};
use ps_signatures::keys::{PsParams, PsPublicKey, PsSigningKey};
use ps_signatures::serde::Serializable;
use rand::thread_rng;
use rocksdb::{Options, DB};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

const SUFFIX_PARAMS: &str = "-key_params";
const SUFFIX_SIGNING_KEY: &str = "-signing_key";
const SUFFIX_PUBLIC_KEY: &str = "-public_key";

pub struct KeyManager {
    db: DB,

    key_lifetime: u64,

    current_epoch: Option<u64>,

    next_epoch: Option<u64>,
}

impl KeyManager {
    pub fn create(config: &KeyManagerConfig) -> Result<Arc<Mutex<Self>>, KeyManagerError> {
        let db = Self::connect_to_db(config)?;

        let mut key_manager = KeyManager {
            db,
            key_lifetime: config.key_lifetime * 60, // To seconds
            current_epoch: None,
            next_epoch: None,
        };

        // Initialize
        key_manager.update_keys()?;

        // Put wrap with mutex
        let key_manager = Arc::new(Mutex::new(key_manager));

        // Schedule key refresh
        Self::schedule_key_updates(key_manager.clone(), config);

        Ok(key_manager)
    }

    pub fn get_key_profile(&self, epoch: u64) -> Result<KeyProfile, KeyManagerError> {
        if !self.key_exists(epoch) {
            return Err(NotFoundError("Key not found".to_string()));
        }

        let key_profile = KeyProfile {
            params: self.get_key_params(&Self::create_key_params_id(epoch))?,
            signing_key: self.get_signing_key(&Self::create_signing_key_id(epoch))?,
            public_key: self.get_public_key(&Self::create_public_key_id(epoch))?,
            key_lifetime: self.key_lifetime,
        };

        Ok(key_profile)
    }

    fn schedule_key_updates(key_manager: Arc<Mutex<KeyManager>>, config: &KeyManagerConfig) {
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

                // TODO: Catch or panic?
                let mut key_manager = key_manager.lock().unwrap();
                key_manager.update_keys().unwrap();
            }
        });
    }

    fn update_keys(&mut self) -> Result<(), KeyManagerError> {
        let (current_epoch, next_epoch) = self.get_key_epochs();

        debug!("Current epoch: {}", current_epoch);
        debug!("Next epoch: {}", next_epoch);

        // Provision current key
        self.update_key(current_epoch)?;
        // Provision the next key
        self.update_key(next_epoch)?;

        self.current_epoch = Some(current_epoch);
        self.next_epoch = Some(next_epoch);

        Ok(())
    }

    fn update_key(&mut self, epoch: u64) -> Result<(), KeyManagerError> {
        if !self.key_exists(epoch) {
            // Provision key
            self.provision_key(epoch)?;
        }

        Ok(())
    }

    fn provision_key(&mut self, epoch: u64) -> Result<(), KeyManagerError> {
        let mut rng = thread_rng();

        // Generate the params and keys
        let params = PsParams::generate(&mut rng);
        let signing_key = PsSigningKey::generate(1, &params, &mut rng);
        let public_key = signing_key.derive_public_key(&params);

        self.store_key_params(&params, &Self::create_key_params_id(epoch))?;
        self.store_signing_key(&signing_key, &Self::create_signing_key_id(epoch))?;
        self.store_public_key(&public_key, &Self::create_public_key_id(epoch))?;

        Ok(())
    }

    fn store_key_params(
        &mut self,
        params: &PsParams,
        params_id: &String,
    ) -> Result<(), KeyManagerError> {
        let params_serialized = params
            .serialize()
            .map_err(|e| SerializationError(format!("Could not serialize params. {:?}", e)))?;

        self.db
            .put(params_id, &params_serialized)
            .map_err(|e| DBError(format!("Could not store params. {:?}", e)))?;

        Ok(())
    }

    fn store_signing_key(
        &mut self,
        signing_key: &PsSigningKey,
        key_id: &String,
    ) -> Result<(), KeyManagerError> {
        //let key_id = self.get_current_signing_key_id()?;
        let key_serialized = signing_key
            .serialize()
            .map_err(|e| SerializationError(format!("Could not serialize signing key. {:?}", e)))?;

        self.db
            .put(key_id, &key_serialized)
            .map_err(|e| DBError(format!("Could not store signing key. {:?}", e)))?;

        Ok(())
    }

    fn store_public_key(
        &mut self,
        public_key: &PsPublicKey,
        key_id: &String,
    ) -> Result<(), KeyManagerError> {
        let key_serialized = public_key
            .serialize()
            .map_err(|e| SerializationError(format!("Could not serialize public key. {:?}", e)))?;

        self.db
            .put(key_id, &key_serialized)
            .map_err(|e| DBError(format!("Could not store public keys. {:?}", e)))?;

        Ok(())
    }

    fn get_key_params(&self, key_id: &String) -> Result<PsParams, KeyManagerError> {
        let result = self
            .db
            .get(key_id)
            .map_err(|e| DBError(format!("Could not get key params. {:?}", e)))?;

        let params = match result {
            Some(params) => params,
            None => return Err(NotFoundError(format!("Key params not found."))),
        };

        let params = PsParams::deserialize(&params).map_err(|e| {
            DeserializationError(format!("Could not deserialize key params. {:?}", e))
        })?;

        Ok(params)
    }

    fn get_public_key(&self, key_id: &String) -> Result<PsPublicKey, KeyManagerError> {
        let result = self
            .db
            .get(key_id)
            .map_err(|e| DBError(format!("Could not get public key. {:?}", e)))?;

        let public_key = match result {
            Some(key) => key,
            None => return Err(NotFoundError(format!("Public key not found."))),
        };

        let public_key = PsPublicKey::deserialize(&public_key).map_err(|e| {
            DeserializationError(format!("Could not deserialize public key. {:?}", e))
        })?;

        Ok(public_key)
    }

    fn get_signing_key(&self, key_id: &String) -> Result<PsSigningKey, KeyManagerError> {
        let result = self
            .db
            .get(key_id)
            .map_err(|e| DBError(format!("Could not get signing key. {:?}", e)))?;

        let signing_key = match result {
            Some(key) => key,
            None => return Err(NotFoundError(format!("Signing key not found."))),
        };

        let signing_key = PsSigningKey::deserialize(&signing_key).map_err(|e| {
            DeserializationError(format!("Could not deserialize signing key. {:?}", e))
        })?;

        Ok(signing_key)
    }

    fn key_exists(&self, epoch: u64) -> bool {
        self.db.key_may_exist(Self::create_public_key_id(epoch))
            && self.db.key_may_exist(Self::create_signing_key_id(epoch))
            && self.db.key_may_exist(Self::create_key_params_id(epoch))
    }

    // (current, next)
    fn get_key_epochs(&self) -> (u64, u64) {
        let now = SystemTime::now();
        let now = now.duration_since(UNIX_EPOCH).unwrap().as_secs();

        let current_epoch = now - (now % self.key_lifetime);

        let next_epoch = current_epoch + self.key_lifetime;

        (current_epoch, next_epoch)
    }

    fn create_key_params_id(epoch: u64) -> String {
        format!("{}-{}", epoch, SUFFIX_PARAMS)
    }

    fn create_signing_key_id(epoch: u64) -> String {
        format!("{}-{}", epoch, SUFFIX_SIGNING_KEY)
    }

    fn create_public_key_id(epoch: u64) -> String {
        format!("{}-{}", epoch, SUFFIX_PUBLIC_KEY)
    }

    // Connect to the database
    fn connect_to_db(config: &KeyManagerConfig) -> Result<DB, KeyManagerError> {
        let mut options = Options::default();
        options.create_if_missing(true);

        let db = DB::open(&options, &config.key_file)
            .map_err(|e| DBError(format!("Could not connect to the keys database. {:?}", e)))?;

        Ok(db)
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
    pub params: PsParams,

    pub signing_key: PsSigningKey,

    pub public_key: PsPublicKey,

    pub key_lifetime: u64,
}
