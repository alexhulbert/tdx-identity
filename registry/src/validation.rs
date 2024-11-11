//! Validation functions for registry requests

use crate::{
    error::{RegistryError, Result},
    state::RegistryEntry,
};
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use shared::{
    sig_validation::verify_instance_signature,
    types::{IdentityInfo, RegisterRequest, UserType},
};

/// Verify that the identity info is valid
/// This will check that an owner or operator has signed the instance public key
/// with the private key corresponding to the public key in the identity info
/// and that the operator or owner's public key is signed by the instance public key
///
/// # Arguments
///
/// * `instance_pubkey` - The public key of the instance
/// * `identity_info` - The identity info to verify (contains public key and signature)
/// * `context` - The type of user being verified (operator or owner)
fn verify_identity_signatures(
    instance_pubkey: &[u8; PUBLIC_KEY_LENGTH],
    identity_info: &IdentityInfo,
    context: UserType,
) -> Result<()> {
    // Verify signatures
    verify_instance_signature(
        &identity_info.pubkey,
        instance_pubkey,
        &identity_info.instance_signature,
        UserType::Instance,
    )
    .map_err(RegistryError::unauthorized)?;

    verify_instance_signature(
        instance_pubkey,
        &identity_info.pubkey,
        &identity_info.identity_signature,
        context,
    )
    .map_err(RegistryError::unauthorized)?;

    Ok(())
}

/// Validate a register request
/// This will check that the operator and owner have signed the instance public key
/// with the correct keys. It will also check that the owner is only set if the operator is set
pub fn validate_request(request: &RegisterRequest) -> Result<()> {
    // Validate operator if present
    if let Some(op) = &request.operator {
        verify_identity_signatures(&request.instance_pubkey, op, UserType::Operator)?;
    }

    // Validate owner if present
    if let Some(owner) = &request.owner {
        if request.operator.is_none() {
            return Err(RegistryError::invalid_request(
                "Owner requires operator to be set",
            ));
        }
        verify_identity_signatures(&request.instance_pubkey, owner, UserType::Owner)?;
    }

    Ok(())
}

/// Validate that new registry data does not conflict with existing data
/// This will check that the new data does not modify the PPID, operator, or owner
/// of an existing instance
///
/// # Arguments
///
/// * `existing` - The existing registry entry from the database
/// * `request` - The new register request
pub fn validate_existing_instance(
    existing: &RegistryEntry,
    request: &RegisterRequest,
) -> Result<()> {
    if existing.ppid != request.ppid {
        return Err(RegistryError::forbidden(
            "Cannot modify PPID of existing instance",
        ));
    }

    if !matches_existing_identity(existing.operator.as_ref(), request.operator.as_ref()) {
        return Err(RegistryError::forbidden(
            "Cannot modify operator of existing instance",
        ));
    }

    if !matches_existing_identity(existing.owner.as_ref(), request.owner.as_ref()) {
        return Err(RegistryError::forbidden(
            "Cannot modify owner of existing instance",
        ));
    }

    Ok(())
}

/// Make sure that the new identity info matches any prior identity info
/// This will return true if the new identity info is None or if the new
/// identity info is the same as the existing identity info
fn matches_existing_identity(existing: Option<&IdentityInfo>, new: Option<&IdentityInfo>) -> bool {
    match (existing, new) {
        (None, _) => true,
        (Some(e), Some(n)) => e == n,
        _ => false,
    }
}
