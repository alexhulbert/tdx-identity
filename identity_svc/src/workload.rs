//! Manages creation of Podman containers for running workloads

use crate::{
    encryption::MOUNT_PATH,
    error::{IdentityError, Result},
    state::WorkloadConfig,
};
use futures_util::StreamExt;
use lazy_static::lazy_static;
use podman_api::{
    models::{ContainerMount, PortMapping},
    opts::{ContainerCreateOpts, ContainerStopOpts, PullOpts, VolumePruneOpts},
    Podman,
};
use std::{
    fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
};

/// Name of the Podman container
pub const CONTAINER_NAME: &str = "workload";
pub const PODMAN_SOCKET_PATH: &str = "/run/podman/podman.sock";

lazy_static! {
    /// Directories in the container are persisted via bind mounts to this folder
    static ref CONTAINER_PERSIST_DIR: PathBuf = MOUNT_PATH.join("podman");
    static ref PODMAN: Podman = Podman::unix(PODMAN_SOCKET_PATH);
}

/// Runs a workload container with the specified configuration
/// Only exposes the specified port if config.finalized is true
pub async fn run_container(config: &WorkloadConfig) -> Result<()> {
    // Connect to podman
    let podman = Podman::unix(PODMAN_SOCKET_PATH);

    // Validate persist directories
    for dir in &config.persist_dirs {
        sanitize_container_dir(dir)?;
    }

    // Remove existing container if it exists
    remove_existing_container().await;

    // Create persist directories
    fs::create_dir_all(&*CONTAINER_PERSIST_DIR).unwrap_or_else(|err| {
        if err.kind() != ErrorKind::AlreadyExists {
            panic!("Failed to create persist directory: {}", err);
        }
    });
    for dir in &config.persist_dirs {
        fs::create_dir_all(container_dir_to_host_dir(dir)).unwrap_or_else(|err| {
            if err.kind() != ErrorKind::AlreadyExists {
                panic!("Failed to create persist directory: {}", err);
            }
        });
    }

    // Create volume mounts
    let mounts: Vec<_> = config
        .persist_dirs
        .iter()
        .map(|dir| ContainerMount {
            _type: Some("bind".to_string()),
            source: Some(container_dir_to_host_dir(dir)),
            destination: Some(dir.clone()),
            options: None,
            gid_mappings: None,
            uid_mappings: None,
        })
        .collect();

    // Map port if specified
    let port_mappings = if config.finalized {
        vec![PortMapping {
            container_port: Some(config.port),
            host_port: Some(8080),
            protocol: Some("tcp".to_string()),
            host_ip: None,
            range: None,
        }]
    } else {
        vec![]
    };

    // Pull the image
    let pull_opts = PullOpts::builder().reference(config.image.clone()).build();
    let images = podman.images();
    let mut pull_stream = images.pull(&pull_opts);
    while let Some(result) = pull_stream.next().await {
        result.map_err(|e| IdentityError::internal(format!("Failed to pull image: {}", e)))?;
    }

    // Create the container
    let container_config = &ContainerCreateOpts::builder()
        .image(config.image.clone())
        .name(CONTAINER_NAME)
        .mounts(mounts)
        .portmappings(port_mappings)
        .build();
    let container_id = podman
        .containers()
        .create(container_config)
        .await
        .map_err(|e| IdentityError::internal(format!("Failed to create container: {}", e)))?
        .id;

    // Start the container
    podman
        .containers()
        .get(container_id)
        .start(None)
        .await
        .map_err(|e| IdentityError::internal(format!("Failed to start container: {}", e)))?;

    Ok(())
}

/// Stops and removes the workload container if it exists
async fn remove_existing_container() {
    let old_container = PODMAN.containers().get(CONTAINER_NAME);
    if old_container
        .exists()
        .await
        .expect("Failed to check if container exists")
    {
        // Ignore failure, it doesn't matter if it wasn't running to begin with
        let _ = old_container.stop(&ContainerStopOpts::default()).await;

        // Remove container
        old_container
            .remove()
            .await
            .expect("Failed to remove container");

        // Prune volumes to clear out any remaining state
        PODMAN
            .volumes()
            .prune(&VolumePruneOpts::default())
            .await
            .expect("Unable to reset Podman container to default state");
    }
}

/// Maps a container directory to the corresponding host directory
///
/// # Arguments
///
/// * `container_dir` - The absolute directory path inside the container
///
/// # Returns
///
/// * The absolute directory path to map to on the host machine
fn container_dir_to_host_dir(container_dir: &str) -> String {
    CONTAINER_PERSIST_DIR
        .join(container_dir.strip_prefix("/").unwrap_or(container_dir))
        .to_string_lossy()
        .to_string()
}

/// Sanitizes a container directory path to prevent directory traversal attacks
fn sanitize_container_dir(dir: &str) -> Result<()> {
    let path = Path::new(dir);

    // Reject any path components that are not normal or root
    if path
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::RootDir))
    {
        return Err(IdentityError::invalid_request("Invalid directory path"));
    }
    Ok(())
}
