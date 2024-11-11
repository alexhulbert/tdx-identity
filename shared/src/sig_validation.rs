//! Contains a function for verifying a signed public key

use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

use crate::types::UserType;

/// Verify that the provided signature's public key matches the instance public key
/// and that the signed message matches the public key of the server
///
/// # Arguments
///
/// * `identity_pubkey_bytes` - The public key of the owner or operator
/// * `instance_pubkey_bytes` - The public key of the instance
/// * `signature` - The signature to verify
/// * `context` - The type of key being verified
pub fn verify_instance_signature(
    identity_pubkey_bytes: &[u8; PUBLIC_KEY_LENGTH],
    instance_pubkey_bytes: &[u8; PUBLIC_KEY_LENGTH],
    signature: &[u8; SIGNATURE_LENGTH],
    context: UserType,
) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(identity_pubkey_bytes)
        .map_err(|_| format!("Invalid {} public key", context))?;

    // Convert signature to ed25519 Signature object
    let sig =
        Signature::from_slice(signature).map_err(|_| format!("Invalid {} sig format", context))?;

    // Verify that the signature matches the instance public key and the identity public key
    key.verify_strict(instance_pubkey_bytes, &sig)
        .map_err(|_| format!("Invalid {} signature", context))?;

    Ok(())
}
