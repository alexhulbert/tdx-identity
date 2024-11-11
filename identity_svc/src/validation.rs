//! Validation functions for verifying signatures and tokens

use crate::error::{IdentityError, Result};
use axum::http::HeaderMap;
use ed25519_dalek::{Signature, VerifyingKey};

/// Header key for owner creation token
const TOKEN_HEADER: &str = "x-token";
/// Header key for signature
const SIGNATURE_HEADER: &str = "x-signature";

/// Validate that the x-signature header matches the request body
///
/// # Arguments
///
/// * `headers` - The headers of the request
/// * `payload` - The payload of the request
/// * `identity_pubkey_bytes` - The public key of the owner
pub fn validate_signature_header(
    headers: &HeaderMap,
    payload: Vec<u8>,
    owner_pubkey_bytes: [u8; 32],
) -> Result<()> {
    // Extract signature from headers
    let sig = headers
        .get(SIGNATURE_HEADER)
        .ok_or_else(|| IdentityError::unauthorized("Missing signature header"))?
        .to_str()
        .map_err(|_| IdentityError::unauthorized("Invalid signature header"))?;
    let sig =
        hex::decode(sig).map_err(|_| IdentityError::unauthorized("Invalid signature format"))?;
    let sig = Signature::from_slice(&sig)
        .map_err(|_| IdentityError::unauthorized("Invalid signature"))?;
    let identity_pubkey =
        VerifyingKey::from_bytes(&owner_pubkey_bytes).expect("Invalid identity public key format");

    // Verify signature
    identity_pubkey
        .verify_strict(&payload, &sig)
        .map_err(|_| IdentityError::unauthorized("Invalid signature"))?;

    Ok(())
}

/// Validate that the x-token header matches the stored owner token
///
/// # Arguments
///
/// * `headers` - The headers of the request
/// * `owner_token` - The stored owner token
pub fn validate_owner_token(headers: &HeaderMap, owner_token: &String) -> Result<()> {
    // Extract token from headers
    let token = headers
        .get(TOKEN_HEADER)
        .ok_or_else(|| IdentityError::unauthorized("Missing token header"))?
        .to_str()
        .map_err(|_| IdentityError::unauthorized("Invalid token header"))
        .map(String::from)?;

    // Validate token matches the one from the AppState
    if &token != owner_token {
        return Err(IdentityError::unauthorized("Invalid owner token"));
    }

    Ok(())
}
