//! Functions for persisting and retrieving data from the filesystem.

use crate::encryption::MOUNT_PATH;
use crate::error::{IdentityError, Result};
use crate::state::WorkloadConfig;
use ed25519_dalek::SigningKey;
use lazy_static::lazy_static;
use rand::thread_rng;
use shared::types::IdentityInfo;
use std::env::var;
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

lazy_static! {
    /// The directory where all persistent files can be read from and written to
    pub static ref STORAGE_PATH: PathBuf =
        PathBuf::from(var("STORAGE_PATH").unwrap_or("/mnt".to_string()));
    /// The path to the workload configuration file
    pub static ref WORKLOAD_CONFIG_PATH: PathBuf = MOUNT_PATH.join("workload_config.json");
}

/// Returns the stored workload configuration if it exists
pub fn get_workload_config() -> Result<Option<WorkloadConfig>> {
    // Try to read file, panic on errors other than file not found
    match fs::read_to_string(&*WORKLOAD_CONFIG_PATH) {
        Ok(data) => Ok(Some(
            serde_json::from_str::<WorkloadConfig>(&data).expect("Unable to read workload config"),
        )),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => panic!("Failed to read workload config: {}", err),
    }
}

/// Stores the workload configuration to disk
pub fn store_workload_config(config: &WorkloadConfig) -> Result<()> {
    let data = serde_json::to_string_pretty(config).map_err(IdentityError::internal)?;
    fs::write(&*WORKLOAD_CONFIG_PATH, data).expect("Unable to write workload config");
    Ok(())
}

/// Returns the stored instance key if it exists, or generates a new one
pub fn get_or_create_instance_key() -> SigningKey {
    // Create storage directory if it doesn't exist
    if let Err(err) = fs::create_dir_all(&*STORAGE_PATH) {
        if err.kind() != ErrorKind::AlreadyExists {
            panic!("Failed to create storage directory: {}", err);
        }
    }

    let key_path = STORAGE_PATH.join("instance.key");
    if key_path.exists() {
        // Read existing key
        let key_bytes = fs::read(&key_path).expect("Failed to read instance key");
        let key_array: &[u8; 32] = &key_bytes.try_into().expect("Failed to parse instance key");
        SigningKey::from_bytes(key_array)
    } else {
        // Generate new key
        let key = SigningKey::generate(&mut thread_rng());
        fs::write(&key_path, key.to_bytes()).expect("Failed to write instance key");
        key
    }
}

/// Returns the stored owner token if it exists, or generates a new one
pub fn get_or_create_owner_token() -> String {
    let token_path = STORAGE_PATH.join("owner_token.txt");
    if token_path.exists() {
        // Read existing owner token
        fs::read_to_string(&token_path).expect("Failed to read owner token")
    } else {
        // Generate new owner token
        let token = hex::encode(rand::random::<[u8; 32]>());
        fs::write(&token_path, &token).expect("Failed to generate owner token");
        token
    }
}

/// Returns the stored owner data if it exists
pub fn get_owner() -> Result<Option<IdentityInfo>> {
    let owner_path = STORAGE_PATH.join("owner.json");
    // Try to read file, panic on errors other than file not found
    match fs::read_to_string(&owner_path) {
        Ok(data) => serde_json::from_str(&data)
            .map_err(IdentityError::internal)
            .map(Some),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => panic!("Failed to read owner file: {}", err),
    }
}

/// Stores the owner data to disk
pub fn store_owner(owner: &IdentityInfo) -> Result<()> {
    let owner_path = STORAGE_PATH.join("owner.json");
    let data = serde_json::to_string_pretty(owner).map_err(IdentityError::internal)?;
    fs::write(&owner_path, data).expect("Failed to write owner to file");
    Ok(())
}

/// Returns the stored operator data if it exists
pub fn get_operator() -> Result<Option<IdentityInfo>> {
    let op_path = STORAGE_PATH.join("operator.json");
    // Try to read file, panic on errors other than file not found
    match fs::read_to_string(&op_path) {
        Ok(data) => serde_json::from_str(&data)
            .map_err(IdentityError::internal)
            .map(Some),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => panic!("Failed to read operator file: {}", err),
    }
}

/// Stores the operator data to disk
pub fn store_operator(operator: &IdentityInfo) -> Result<()> {
    let op_path = STORAGE_PATH.join("operator.json");
    let data = serde_json::to_string_pretty(operator).map_err(IdentityError::internal)?;
    fs::write(&op_path, data).map_err(IdentityError::internal)?;
    Ok(())
}
