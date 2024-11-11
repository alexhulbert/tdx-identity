//! Intel TDX attestation verification functions

use dcap_qvl::collateral::get_collateral;
use dcap_qvl::verify::{verify, VerifiedReport};
use lazy_static::lazy_static;
use shared::encrypted_ppid::get_encrypted_ppid_from_quote;
use std::env::var;
use std::time::{Duration, UNIX_EPOCH};
use tdx_quote::Quote;

use crate::error::{RegistryError, Result};

lazy_static! {
    /// Whether to skip TDX attestation verification
    /// The attestation hash is always verified
    static ref SKIP_TDX_AUTH: bool = var("SKIP_TDX_AUTH").is_ok();
    /// PCCS URL for getting collateral from Intel
    static ref PCCS_URL: String =
        var("PCCS_URL").unwrap_or("https://localhost:8081/sgx/certification/v4/".to_string());
}

/// Verifies a quote is legitimate, attests to the given hash, and has the correct PPID
/// If TDX is not available, this function will only verify the hash
///
/// # Arguments
///
/// * `quote` - The quote to verify
/// * `hash` - The report_data that should be in the quote
/// * `ppid` - The PPID that the quote should have
pub async fn verify_attestation(
    quote: &[u8],
    hash: &[u8],
    ppid: &[u8],
) -> Result<Option<VerifiedReport>> {
    // Parse the quote
    let quote_obj = Quote::from_bytes(quote)
        .map_err(|e| RegistryError::unauthorized(format!("Failed to parse quote: {}", e)))?;

    // Verify the hash matches the report_data of the parsed quote
    if quote_obj.report_input_data() != hash {
        return Err(RegistryError::unauthorized("Attestation hash mismatch"));
    }

    // Skip TDX verification if the environment variable is set
    if *SKIP_TDX_AUTH {
        eprintln!("Skipping TDX verification");
        return Ok(None);
    }

    // Extract the PPID from the quote and verify it matches the expected PPID
    let quote_ppid = get_encrypted_ppid_from_quote(&quote_obj)
        .map_err(|e| RegistryError::unauthorized(format!("Failed to extract quote ppid: {}", e)))?;

    if quote_ppid != ppid {
        return Err(RegistryError::unauthorized("PPID mismatch"));
    };

    // Get collateral from Intel and use it to verify the quote
    let collateral = get_collateral(&PCCS_URL, quote, Duration::from_secs(10))
        .await
        .map_err(|e| RegistryError::unauthorized(format!("Failed to get collateral: {:?}", e)))?;

    let now = UNIX_EPOCH.elapsed().unwrap().as_secs();
    verify(quote, &collateral, now)
        .map_err(|e| RegistryError::unauthorized(format!("Failed to verify quote: {:?}", e)))
        .map(Some)
}
