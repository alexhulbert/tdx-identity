//! This module provides a function to create a TDX quote.

use crate::error::{IdentityError, Result};
use lazy_static::lazy_static;
use std::{env::var, path::Path};

lazy_static! {
    static ref MOCK_TDX_URL: String = var("MOCK_TDX_URL")
        .unwrap_or_else(|_| { "http://ns31695324.ip-141-94-163.eu:10080".to_string() });
}

/// Creates a TDX quote for the given report data.
/// If TDX is not available, a mock TDX service is used.
///
/// # Arguments
///
/// * `report_data` - The data to attest to
///
/// # Returns
///
/// * A TDX quote
pub async fn create_tdx_quote(report_data: [u8; 64]) -> Result<Vec<u8>> {
    if is_tdx_available() {
        // Use the TDX configfs subsystem to create an actual TDX quote
        return configfs_tsm::create_tdx_quote(report_data).map_err(IdentityError::internal);
    }

    println!("Warning: TDX is not available. Using mock TDX service.");

    // Use a mock TDX service to create a fake TDX quote
    let report_data_hex: String = hex::encode(report_data);
    let url = format!("{}/attest/{}", &*MOCK_TDX_URL, &report_data_hex);
    let response = reqwest::get(&url).await.map_err(IdentityError::internal)?;
    let response_bytes = response.bytes().await.map_err(IdentityError::internal)?;
    Ok(response_bytes.to_vec())
}

/// Returns true if the TDX configfs subsystem is available.
pub fn is_tdx_available() -> bool {
    Path::new("/sys/kernel/config/tsm/report").exists()
}
