//! Provides a function that creates a FUSE mount which mirrors encrypted files to $STORAGE_PATH

use crate::storage::STORAGE_PATH;
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use tokio::process::Command as TokioCommand;

lazy_static! {
    // This is the directory where the files can be read and written to
    pub static ref MOUNT_PATH: PathBuf = PathBuf::from("/tmp/tdx-identity-persist");
    // This is where the files are actually stored on disk
    static ref ENCRYPTED_PATH: PathBuf = STORAGE_PATH.join("tdx-store-encrypted");
    // A temporary file to store the encryption key for use by gocryptfs
    static ref KEY_PATH: PathBuf = PathBuf::from("/tmp/gocryptfs.key");
}

/// Mounts a virtual storage directory in tmp that mirrors encrypted files to $STORAGE_PATH
///
/// # Arguments
///
/// * `owner_pubkey_bytes` - The owner's public key, unencoded
/// * `ppid` - The encrypted PPID of this TDX instance
///
/// # Panics
///
/// Panics if the gocryptfs initialization or mount fails
pub async fn initialize_encryption(owner_pubkey_bytes: &[u8], ppid: &[u8]) {
    // Create required directories if they don't exist
    // Ignore errors here, they can be unpredictable if the directory is already mounted
    let _ = fs::create_dir_all(&*MOUNT_PATH);
    if !ENCRYPTED_PATH.exists() {
        fs::create_dir_all(&*ENCRYPTED_PATH).expect("Failed to create ENCRYPTED_PATH");
    }

    // Generate and save encryption key
    let key = generate_encryption_key(owner_pubkey_bytes, ppid);
    fs::write(&*KEY_PATH, &key).expect("Failed to write encryption key");

    // Initialize if not already initialized
    if !ENCRYPTED_PATH.join("gocryptfs.conf").exists() {
        init_gocryptfs().await;
    }

    // Mount MOUNT_PATH
    unmount().await;
    mount().await;
}

/// Calls gocryptfs init on the encrypted storage directory
async fn init_gocryptfs() {
    let status = TokioCommand::new("gocryptfs")
        .arg("-init")
        .arg("-passfile")
        .arg(&*KEY_PATH)
        .arg("-allow_other")
        .arg("-q")
        .arg(&*ENCRYPTED_PATH)
        .status()
        .await
        .expect("Failed to execute gocryptfs init");

    if !status.success() {
        panic!("gocryptfs initialization failed");
    }
}

/// Mounts the encrypted storage directory to MOUNT_PATH
async fn mount() {
    let status = TokioCommand::new("gocryptfs")
        .arg("-passfile")
        .arg(&*KEY_PATH)
        .arg("-allow_other")
        .arg(&*ENCRYPTED_PATH)
        .arg(&*MOUNT_PATH)
        .status()
        .await
        .expect("Failed to execute gocryptfs");

    if !status.success() {
        panic!("gocryptfs mount failed");
    }

    // Clean up the key file after successful mount
    fs::remove_file(&*KEY_PATH).expect("Failed to remove key file");
}

/// Unmounts the virtual storage directory
async fn unmount() {
    if !MOUNT_PATH.exists() {
        return;
    }

    // Ignore errors here, as the directory may not be mounted
    let _ = TokioCommand::new("fusermount")
        .arg("-u")
        .arg(&*MOUNT_PATH)
        .status()
        .await;
}

/// Dummy function to generate an encryption key
/// In a real implementation, this would interact with a KMS
/// For now, we'll just hash the concatenation of owner pubkey and ppid
fn generate_encryption_key(owner_pubkey: &[u8], ppid: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(owner_pubkey);
    hasher.update(ppid);
    hex::encode(hasher.finalize())
}
