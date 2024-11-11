//! Handlers for the identity service

use crate::{
    encryption::initialize_encryption,
    error::{IdentityError, Result},
    ssh::{start_ssh_server, stop_ssh_server},
    state::{AppState, WorkloadConfig},
    validation::{validate_owner_token, validate_signature_header},
    workload::run_container,
};
use axum::{
    body::Bytes,
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{Signer, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use serde::Deserialize;
use shared::{
    sig_validation::verify_instance_signature,
    types::{hex_serde, IdentityInfo, UserType},
};
use std::sync::Arc;

/// Creates the router for the identity service
pub(crate) fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/instance/pubkey", get(get_instance_pubkey))
        .route("/operator/register", post(register_operator))
        .route("/owner/register", post(register_owner))
        .route("/workload/configure", post(configure_workload))
        .route("/workload/expose", post(expose_workload))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
pub struct RegisterIdentityRequest {
    #[serde(with = "hex_serde")]
    pub pubkey: [u8; PUBLIC_KEY_LENGTH],

    #[serde(with = "hex_serde")]
    pub signature: [u8; SIGNATURE_LENGTH],
}

#[derive(Debug, Deserialize)]
pub struct ConfigureWorkloadRequest {
    #[serde(with = "hex_serde")]
    pub instance_pubkey: [u8; PUBLIC_KEY_LENGTH],
    pub image: String,
    pub persist_dirs: Vec<String>,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct ExposeWorkloadRequest {
    #[serde(with = "hex_serde")]
    pub instance_pubkey: [u8; PUBLIC_KEY_LENGTH],
    pub image: String,
}

/// Configures the workload with the specified image and persist directories
/// This will start a podman container and SSH server, but not expose the port
async fn configure_workload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>> {
    // Parse request body as both raw bytes (for signature validation) and JSON
    let payload_raw = body.to_vec();
    let payload: ConfigureWorkloadRequest = serde_json::from_slice(&payload_raw)
        .map_err(|_| IdentityError::invalid_request("Invalid payload"))?;

    // Verify owner has been registered
    let owner = state.owner.read().unwrap().clone();
    let Some(owner) = owner.as_ref() else {
        return Err(IdentityError::unauthorized("Owner not registered"));
    };

    // Verify that the signature header matches the POST body
    validate_signature_header(&headers, payload_raw, owner.pubkey)?;

    // Validate instance pubkey matches the stored instance pubkey
    if payload.instance_pubkey != state.instance_pubkey_bytes {
        return Err(IdentityError::unauthorized("Instance pubkey mismatch"));
    }

    let workload_config = WorkloadConfig {
        image: payload.image,
        persist_dirs: payload.persist_dirs,
        port: payload.port,
        finalized: false,
    };

    // Save to state and disk
    state.configure_workload(&workload_config).await?;

    // Run the container with the specified config and start SSH server
    run_container(&workload_config).await?;
    start_ssh_server(&owner.pubkey).await;

    Ok(Json(serde_json::json!({ "status": "success" })))
}

/// Exposes the workload by stopping the SSH server
/// and rerunning the container with the port exposed
async fn expose_workload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>> {
    // Parse request body as both raw bytes (for signature validation) and JSON
    let payload_raw = body.to_vec();
    let payload: ExposeWorkloadRequest = serde_json::from_slice(&payload_raw)
        .map_err(|_| IdentityError::invalid_request("Invalid payload"))?;

    // Verify owner has been registered
    let owner = state.owner.read().unwrap().clone();
    let Some(owner) = owner.as_ref() else {
        return Err(IdentityError::unauthorized("Owner not registered"));
    };

    // Verify that the signature header matches the POST body
    validate_signature_header(&headers, payload_raw, owner.pubkey)?;

    // Validate instance pubkey matches the stored instance pubkey
    if payload.instance_pubkey != state.instance_pubkey_bytes {
        return Err(IdentityError::unauthorized("Instance pubkey mismatch"));
    }

    // Make sure the workload has been configured
    let workload_config = state.workload_config.read().unwrap().clone();
    let Some(workload_config) = workload_config else {
        return Err(IdentityError::invalid_request("Workload not configured"));
    };

    // Verify instance pubkey matches stored config
    if payload.image != workload_config.image {
        return Err(IdentityError::unauthorized(
            "Instance image mismatch with stored config",
        ));
    }

    // Save to state and disk
    state.finalize_workload()?;

    // Stop SSH server and rerun container with port exposed
    stop_ssh_server().await;
    run_container(&WorkloadConfig {
        finalized: true,
        ..workload_config
    })
    .await?;

    Ok(Json(serde_json::json!({ "status": "success" })))
}

/// Assigns an owner key to this TDX instance
async fn register_owner(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<RegisterIdentityRequest>,
) -> Result<Json<serde_json::Value>> {
    // Verify that the owner token header matches the stored owner token
    validate_owner_token(&headers, &state.owner_token)?;

    // Verify that the decoded signature is valid and matches the instance public key
    verify_instance_signature(
        &request.pubkey,
        &state.instance_pubkey_bytes,
        &request.signature,
        UserType::Owner,
    )
    .map_err(IdentityError::unauthorized)?;

    // Sign the owner pubkey with the instance pubkey
    let identity_signature = state
        .instance_key
        .try_sign(&request.pubkey)
        .map_err(IdentityError::internal)?
        .to_bytes();

    let owner = IdentityInfo {
        pubkey: request.pubkey,
        instance_signature: request.signature,
        identity_signature,
    };

    // Mount encrypted storage
    initialize_encryption(&owner.pubkey, &state.ppid).await;

    // Save owner to local state and registry
    state.set_owner(owner)?;
    state.register_with_registry().await?;

    Ok(Json(serde_json::json!({ "status": "success" })))
}

/// Assigns an operator key to this TDX instance
async fn register_operator(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegisterIdentityRequest>,
) -> Result<Json<serde_json::Value>> {
    // Don't allow the operator to change once its set
    if state.operator.read().unwrap().is_some() {
        return Err(IdentityError::invalid_request(
            "Operator already registered",
        ));
    }

    // Verify that the decoded signature is valid and matches the instance public key
    verify_instance_signature(
        &request.pubkey,
        &state.instance_pubkey_bytes,
        &request.signature,
        UserType::Operator,
    )
    .map_err(IdentityError::unauthorized)?;

    // Sign the operator pubkey with the instance pubkey
    let identity_signature = state
        .instance_key
        .try_sign(&request.pubkey)
        .map_err(IdentityError::internal)?
        .to_bytes();

    let operator = IdentityInfo {
        pubkey: request.pubkey,
        instance_signature: request.signature,
        identity_signature,
    };

    // Save operator to local state and registry
    state.set_operator(operator)?;
    state.register_with_registry().await?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "owner_token": state.owner_token,
    })))
}

/// Returns the instance public key
/// Used by the operator and owner to create signatures for registering themselves
async fn get_instance_pubkey(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "pubkey": hex::encode(&state.instance_pubkey_bytes)
    }))
}
