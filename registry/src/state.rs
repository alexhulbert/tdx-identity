//! State management for the registry service.
//!
//! This module contains the `AppState` struct, which holds the database connection and provides
//! methods for interacting with the database.

use crate::error::{RegistryError, Result};
use serde::{Deserialize, Serialize};
use shared::types::{base64_serde, hex_serde, IdentityInfo};
use std::env::var;

#[derive(Debug)]
pub struct AppState {
    pub db: sled::Db,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryEntry {
    #[serde(with = "hex_serde")]
    pub ppid: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub attestation_quote: Vec<u8>,
    pub operator: Option<IdentityInfo>,
    pub owner: Option<IdentityInfo>,
}

impl AppState {
    pub fn new() -> Result<Self> {
        let db_path = var("REGISTRY_DB_PATH").unwrap_or_else(|_| "registry.db".to_string());
        let db = sled::open(db_path)?;
        Ok(AppState { db })
    }

    /// Update the registry entry for the given instance public key
    pub async fn insert(&self, key: &[u8], entry: RegistryEntry) -> Result<()> {
        let serialized = bincode::serialize(&entry)
            .map_err(|_| RegistryError::internal("Failed to serialize entry"))?;
        self.db.insert(key, serialized)?;
        Ok(())
    }

    /// Retrieve the registry entry for the given instance public key
    pub async fn get(&self, key: &[u8]) -> Option<RegistryEntry> {
        self.db
            .get(key)
            .ok()?
            .and_then(|v| bincode::deserialize(&v).ok())
    }
}
