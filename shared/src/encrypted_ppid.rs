//! Provides functions to extract the encrypted PPID
//! It supports getting the PPID either from a quote or direcrtly from TDX

use configfs_tsm::create_tdx_quote;
use tdx_quote::{CertificationData, QeReportCertificationData, Quote};

/// Errors that can occur when extracting the encrypted PPID
#[derive(Debug, thiserror::Error)]
pub enum PpidError {
    #[error("The PPID is not encrypted")]
    NotEncryptedPpid,
    #[error("Invalid data length")]
    InvalidDataLength,
    #[error("Invalid report data")]
    InvalidReportData,
    #[error("Quote parse error: {0}")]
    QuoteParseError(tdx_quote::QuoteParseError),
    #[error("Quote generation error: {0}")]
    QuoteGenerationError(configfs_tsm::QuoteGenerationError),
}

/// Extracts the encrypted PPID from a quote
pub fn get_encrypted_ppid_from_quote(quote: &Quote) -> Result<Vec<u8>, PpidError> {
    // The quotes we get from TDX should always be attesting to some report_data
    if let CertificationData::QeReportCertificationData(cert_data) = &quote.certification_data {
        extract_encrypted_ppid(cert_data)
    } else {
        Err(PpidError::InvalidReportData)
    }
}

/// Gets the encrypted PPID from directly from TDX
pub fn get_encrypted_ppid() -> Result<Vec<u8>, PpidError> {
    // Just generate a quote with empty report_data and extract the PPID from it
    let quote_raw = create_tdx_quote([0u8; 64]).map_err(PpidError::QuoteGenerationError)?;
    let quote = Quote::from_bytes(&quote_raw).map_err(PpidError::QuoteParseError)?;
    get_encrypted_ppid_from_quote(&quote)
}

/// Manually extracts the encrypted PPID from TDX quote certification data
fn extract_encrypted_ppid(cert_data: &QeReportCertificationData) -> Result<Vec<u8>, PpidError> {
    if cert_data.certification_data.len() < 6 {
        return Err(PpidError::InvalidDataLength);
    }

    // This is 3 during testing, but it should be 5
    let cert_type = i16::from_le_bytes([
        cert_data.certification_data[0],
        cert_data.certification_data[1],
    ]);

    // Strip type and size prefixes
    let data = &cert_data.certification_data[6..];

    // This is kept in the code for debugging purposes
    // The last two bytes of the cert_data are the pceid
    let pceid = i16::from_le_bytes([
        cert_data.certification_data[cert_data.certification_data.len() - 2],
        cert_data.certification_data[cert_data.certification_data.len() - 1],
    ]);
    eprint!("PCEID: ");
    dbg!(pceid);

    // Extract the PPID based on the cert type
    let ppid = match cert_type {
        2 => Ok(data[..256].to_vec()), // RSA-2048-OAEP
        3 => Ok(data[..384].to_vec()), // RSA-3072-OAEP
        _ => Err(PpidError::NotEncryptedPpid),
    }?;
    eprint!("PPID: ");
    dbg!(hex::encode(&ppid));

    Ok(ppid)
}
