//! Axum state management module
//!
//! Automatically persists state to disk and registry and
//! handles recovery from persisted state on startup

use crate::{
    encryption::initialize_encryption,
    error::{IdentityError, Result},
    ssh::start_ssh_server,
    storage::{
        get_operator, get_or_create_instance_key, get_or_create_owner_token, get_owner,
        get_workload_config, store_operator, store_owner, store_workload_config,
    },
    tdx::{create_tdx_quote, is_tdx_available},
    workload::run_container,
};
use ed25519_dalek::{SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};
use lazy_static::lazy_static;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use shared::{
    encrypted_ppid::get_encrypted_ppid,
    report_data::create_attestation_hash,
    types::{IdentityInfo, RegisterRequest},
};
use std::{env::var, sync::RwLock};

lazy_static! {
    static ref REGISTRY_URL: String =
        var("REGISTRY_URL").unwrap_or("http://localhost:3000".to_string());
}

/// Axum application state
#[derive(Debug)]
pub struct AppState {
    pub workload_config: RwLock<Option<WorkloadConfig>>,
    pub owner: RwLock<Option<IdentityInfo>>,
    pub operator: RwLock<Option<IdentityInfo>>,
    pub owner_token: String,
    pub instance_key: SigningKey,
    pub instance_pubkey_bytes: [u8; PUBLIC_KEY_LENGTH],
    pub ppid: Vec<u8>,
    pub http_client: Client,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkloadConfig {
    pub image: String,
    pub persist_dirs: Vec<String>,
    pub port: u16,
    pub finalized: bool,
}

/// Error response from the registry
#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
}

impl AppState {
    /// Creates a new application state
    /// If an owner exists, this automatically mounts encrypted storage
    /// If a workload is configured, this automatically starts the workload container
    /// If the workload is not finalized, this automatically starts the SSH server
    ///
    /// # Panics
    ///
    /// Panics if any required data cannot be read from disk or generated
    pub async fn new() -> Result<Self> {
        // Get data from disk or generate new data where appropriate
        let instance_key = get_or_create_instance_key();
        let instance_pubkey_bytes = instance_key.verifying_key().to_bytes();
        let owner_token = get_or_create_owner_token();
        let operator = get_operator()?;
        let owner = get_owner()?;
        let workload_config = get_workload_config()?;

        // Get encrypted PPID from TDX, defaulting to instance key if TDX is not available
        let ppid = if is_tdx_available() {
            get_encrypted_ppid().expect("Failed to get encrypted ppid from TDX")
        } else {
            VerifyingKey::from(&instance_key).to_bytes().to_vec()
        };

        if let Some(owner) = &owner {
            // Mount encrypted storage if owner exists
            initialize_encryption(&owner.pubkey, &ppid).await;

            if let Some(workload_config) = &workload_config {
                // Start workload container if workload is configured
                run_container(workload_config)
                    .await
                    .expect("Failed to run container");
                if !workload_config.finalized {
                    // Start SSH server if workload is not finalized
                    start_ssh_server(&owner.pubkey).await;
                }
            }
        }

        Ok(Self {
            owner_token,
            instance_key,
            instance_pubkey_bytes,
            ppid,
            operator: RwLock::new(operator),
            owner: RwLock::new(owner),
            workload_config: RwLock::new(workload_config),
            http_client: Client::new(),
        })
    }

    /// Sets the workload configuration in state and persists it to disk
    /// This does not start the workload container or SSH server
    /// This will fail if the workload is already finalized
    pub async fn configure_workload(&self, config: &WorkloadConfig) -> Result<()> {
        // Set config in state
        let mut config_lock = self
            .workload_config
            .write()
            .expect("Failed to acquire write lock on workload config");

        // Fail if workload config is already finalized
        if config_lock.clone().map_or(false, |c| c.finalized) {
            return Err(IdentityError::invalid_request(
                "Workload config already finalized",
            ));
        }

        *config_lock = Some(config.clone());

        // Persist config to disk
        store_workload_config(config)?;

        Ok(())
    }

    /// Marks the workload as finalized in state and disk
    /// This does not restart the workload container or stop the SSH server
    /// This will fail if the workload is already finalized
    pub fn finalize_workload(&self) -> Result<()> {
        // Set config in state
        let mut config_lock = self
            .workload_config
            .write()
            .expect("Failed to acquire write lock on workload config");
        let Some(config) = &mut *config_lock else {
            return Err(IdentityError::invalid_request("Workload not configured"));
        };

        // Fail if workload config is already finalized
        if config.finalized {
            return Err(IdentityError::invalid_request(
                "Workload config already finalized",
            ));
        }

        config.finalized = true;

        // Persist config to disk
        store_workload_config(config)?;

        Ok(())
    }

    /// Sets the owner in state and persists it to disk
    /// This does not mount encrypted storage or register changes with the registry
    pub fn set_owner(&self, owner: IdentityInfo) -> Result<()> {
        // Persist owner to disk
        store_owner(&owner).map_err(IdentityError::internal)?;

        // Set owner in state
        let mut owner_lock = self
            .owner
            .write()
            .expect("Failed to acquire write lock on owner");
        *owner_lock = Some(owner);

        Ok(())
    }

    /// Sets the operator in state and persists it to disk
    /// This does not register changes with the registry
    pub fn set_operator(&self, operator: IdentityInfo) -> Result<()> {
        // Persist operator to disk
        store_operator(&operator).map_err(IdentityError::internal)?;

        // Set operator in state
        let mut operator_lock = self
            .operator
            .write()
            .expect("Failed to acquire write lock on operator");
        *operator_lock = Some(operator);

        Ok(())
    }

    /// Sends the current state to the registry
    pub async fn register_with_registry(&self) -> Result<()> {
        let ppid = self.ppid.clone();
        let operator: Option<IdentityInfo> = self.operator.read().unwrap().clone();
        let owner: Option<IdentityInfo> = self.owner.read().unwrap().clone();

        // Serialize and hash the state to create the attestation quote report_data
        let report_data = create_attestation_hash(
            &self.instance_pubkey_bytes,
            &ppid,
            operator.as_ref(),
            owner.as_ref(),
        );
        // Create attestation quote
        let quote = create_tdx_quote(report_data).await?;

        // Send registration request to registry
        let request = RegisterRequest {
            instance_pubkey: self.instance_pubkey_bytes,
            attestation_quote: quote,
            ppid,
            operator,
            owner,
        };

        let response = self
            .http_client
            .post(format!("{}/register", *REGISTRY_URL))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                IdentityError::registry(format!("Failed to connect to registry: {}", e))
            })?;

        if !response.status().is_success() {
            // Extract and display error from registry response
            let msg = match response.json::<ErrorResponse>().await {
                Ok(error_response) => error_response.error,
                Err(e) => format!("Unknown registry error: {}", e),
            };
            return Err(IdentityError::registry(msg));
        }

        Ok(())
    }
}
