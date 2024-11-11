//! Handlers for the registry service

use crate::{
    error::{RegistryError, Result},
    state::{AppState, RegistryEntry},
    tdx::verify_attestation,
    validation::{validate_existing_instance, validate_request},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use shared::{
    report_data::reconstruct_attestation_hash,
    types::{IdentityInfo, RegisterRequest},
};
use std::sync::Arc;

/// Main handler for registering an instance
/// This will validate the request, verify the attestation, and store the entry
/// in the registry
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterRequest>,
) -> Result<StatusCode> {
    validate_request(&request)?;

    // Create hash and verify attestation
    let hash = reconstruct_attestation_hash(&request);
    verify_attestation(&request.attestation_quote, &hash, &request.ppid).await?;

    // Check existing entry
    if let Some(existing) = state.get(&request.instance_pubkey).await {
        validate_existing_instance(&existing, &request)?;
    }

    // Store entry
    let entry = RegistryEntry {
        ppid: request.ppid,
        attestation_quote: request.attestation_quote,
        operator: request.operator.map(IdentityInfo::from),
        owner: request.owner.map(IdentityInfo::from),
    };

    state
        .insert(&request.instance_pubkey, entry)
        .await
        .map_err(RegistryError::internal)?;

    Ok(StatusCode::OK)
}

/// Handler for getting an instance's registry entry
pub async fn get_instance(
    State(state): State<Arc<AppState>>,
    Path(pubkey): Path<String>,
) -> Result<Json<RegistryEntry>> {
    // Decode passed public key as hexidecimal string
    let pubkey_bytes = hex::decode(pubkey)
        .map_err(|_| RegistryError::invalid_request("Invalid hex encoding for public key"))?;

    // Validate public key size
    if pubkey_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(RegistryError::invalid_request(format!(
            "Public key must be {} bytes",
            PUBLIC_KEY_LENGTH
        )));
    }

    // Retrieve entry from db
    let entry = state
        .get(&pubkey_bytes)
        .await
        .ok_or_else(|| RegistryError::invalid_request("Instance not found"))?;

    Ok(Json(entry))
}
