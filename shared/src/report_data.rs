//! Functions for constructing and validating attestation data
//!
//! Quotes are constructed by hashing the instance public key, PPID, and optional
//! operator and owner information and sending the hash to the TDX subsystem to
//! be converted into a quote. The quote is then sent along with the original
//! data to the registry for validation.

use crate::types::{IdentityInfo, RegisterRequest};
use sha2::{Digest, Sha512};

/// Given a request to the registry, reconstruct the attestation hash
/// from the ppid, instance pubkey, etc. If the request is valid,
/// this hash should match the report_data in the quote.
///
/// # Arguments
///
/// * `request` - The request to the registry
///
/// # Returns
///
/// A vector of bytes representing the attestation hash
pub fn reconstruct_attestation_hash(request: &RegisterRequest) -> [u8; 64] {
    create_attestation_hash(
        &request.instance_pubkey,
        &request.ppid,
        request.operator.as_ref(),
        request.owner.as_ref(),
    )
}

/// Creates a hash of the instance public key, PPID, and optional operator and owner
/// information. This hash is used to create the attestation quote.
///
/// # Returns
///
/// A vector of bytes representing the attestation hash
pub fn create_attestation_hash(
    instance_pubkey_bytes: &[u8],
    ppid: &[u8],
    operator: Option<&IdentityInfo>,
    owner: Option<&IdentityInfo>,
) -> [u8; 64] {
    let mut hasher = Sha512::new();

    // Add required fields
    hasher.update(instance_pubkey_bytes);
    hasher.update(ppid);

    // Add operator if present
    if let Some(op) = operator {
        hasher.update(op.pubkey);
        hasher.update(op.instance_signature);
        hasher.update(op.identity_signature);
    }

    // Add owner if present
    if let Some(owner) = owner {
        hasher.update(owner.pubkey);
        hasher.update(owner.instance_signature);
        hasher.update(owner.identity_signature);
    }

    hasher.finalize().into()
}
