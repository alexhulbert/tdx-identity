//! SSH server implementation that provides secure shell access to a Podman container.
//!
//! This module implements an SSH server that authenticates users using Ed25519 public key
//! authentication and provides them with shell access to a specified Podman container.
//! The server runs on port 2222 and maintains a single persistent connection to a podman
//! shell per authenticated session.

use crate::workload::{CONTAINER_NAME, PODMAN_SOCKET_PATH};
use async_trait::async_trait;
use ed25519_dalek::{VerifyingKey, PUBLIC_KEY_LENGTH};
use russh::{
    server::{run_stream, Auth, Config, Msg, Session},
    Channel, ChannelId, CryptoVec, MethodSet,
};
use russh_keys::key::{KeyPair, PublicKey};
use std::{process::Stdio, sync::Arc};
use std::{sync::OnceLock, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::{Child, Command},
    sync::{broadcast, Mutex},
};

/// Global shutdown signal sender for gracefully stopping the SSH server
static SHUTDOWN: OnceLock<broadcast::Sender<()>> = OnceLock::new();
const SSH_PORT: u16 = 2222;

/// Starts the SSH server with the specified Ed25519 public key for authentication.
///
/// # Arguments
///
/// * `key` - The owner key, used to authenticate clients
///
/// # Panics
///
/// Panics if:
/// * The key is invalid or has an incorrect size
/// * The server fails to bind to the specified port
pub async fn start_ssh_server(key: &[u8; PUBLIC_KEY_LENGTH]) {
    // Make sure the server isn't already running
    if SHUTDOWN.get().is_some() {
        eprintln!("Tried to run SSH server while already running");
        return;
    }

    // Extract the public key from the provided bytes
    let pubkey = VerifyingKey::from_bytes(key).expect("Invalid key");

    // Create a broadcast channel for receiving shutdown signals
    let (tx, rx) = broadcast::channel(1);
    let _ = SHUTDOWN.get_or_init(|| tx);

    // Bind the server to the specified port
    let listener = TcpListener::bind(("0.0.0.0", SSH_PORT))
        .await
        .expect("Failed to bind port");
    println!("SSH server started on port {SSH_PORT}");

    // Spawn the server loop in the background
    tokio::spawn(handle_incoming_connections(listener, pubkey, rx));
}

/// Stops the SSH server by sending a shutdown signal.
///
/// This function is idempotent and safe to call multiple times.
pub async fn stop_ssh_server() {
    if let Some(tx) = SHUTDOWN.get() {
        tx.send(()).expect("Failed to stop SSH server");
    }
}

/// Handles incoming SSH connections and spawns new handlers for each one.
///
/// # Arguments
///
/// * `listener` - The TCP listener for incoming connections
/// * `pubkey` - The public key used to verify client connections
/// * `shutdown_rx` - The broadcast receiver for shutdown signals
async fn handle_incoming_connections(
    listener: TcpListener,
    pubkey: VerifyingKey,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    // Configure the SSH server
    // Timeout after 1 hour of inactivity
    // Generates random keys for the server rather than using instance key
    let config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![KeyPair::generate_ed25519()],
        methods: MethodSet::PUBLICKEY,
        ..Default::default()
    });

    loop {
        tokio::select! {
            // Accept incoming connections and spawn a new handler for each one
            Ok((socket, addr)) = listener.accept() => {
                let handler = Handler {
                    pubkey,
                    shell: Arc::new(Mutex::new(None)),
                    shutdown: shutdown_rx.resubscribe(),
                };

                let config = config.clone();
                tokio::spawn(async move {
                    if let Err(e) = run_stream(config, socket, handler).await {
                        eprintln!("SSH error from {addr}: {e}");
                    }
                });
            }
            // Stop the server if a shutdown signal is received
            _ = shutdown_rx.recv() => break
        }
    }
}

/// Pipes I/O between the Podman shell and SSH channel.
async fn handle_shell_io(
    mut stdout: impl AsyncReadExt + Unpin,
    mut stderr: impl AsyncReadExt + Unpin,
    channel_id: ChannelId,
    session: russh::server::Handle,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut stdout_buf = [0u8; 1024];
    let mut stderr_buf = [0u8; 1024];

    // Send shell output to the SSH channel until the channel is closed
    loop {
        tokio::select! {
            Ok(n) = stdout.read(&mut stdout_buf) => {
                if n == 0 || session.data(channel_id, CryptoVec::from(stdout_buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
            Ok(n) = stderr.read(&mut stderr_buf) => {
                if n == 0 || session.data(channel_id, CryptoVec::from(stderr_buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
            _ = shutdown.recv() => break
        }
    }
    let _ = session.close(channel_id).await;
}

/// SSH server session handler that manages authentication and shell sessions.
///
/// The handler:
/// * Verifies client public keys against the configured key
/// * Spawns a Podman shell for authenticated sessions
/// * Manages I/O between the SSH channel and Podman shell
/// * Handles cleanup when sessions end
struct Handler {
    /// The public key used to verify client connections
    pubkey: VerifyingKey,
    /// The currently active shell process, if any
    shell: Arc<Mutex<Option<Child>>>,
    /// Receiver for server shutdown signals
    shutdown: broadcast::Receiver<()>,
}

#[async_trait]
impl russh::server::Handler for Handler {
    type Error = russh::Error;

    /// Opens a new shell session when a client requests one
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        // Start a new shell process in the Podman container
        let sock = &format!("unix://{PODMAN_SOCKET_PATH}");
        let mut child = Command::new("podman")
            .args(["--url", sock, "exec", "-it", CONTAINER_NAME, "/bin/sh"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start shell");

        // Create stdio streams for the shell process
        // Unwrap is safe because we set the streams above
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let channel_id = channel.id();
        let session = session.handle();

        *self.shell.lock().await = Some(child);

        // Spawn a new task to forward I/O between the shell and SSH channel
        tokio::spawn(handle_shell_io(
            stdout,
            stderr,
            channel_id,
            session,
            self.shutdown.resubscribe(),
        ));

        Ok(true)
    }

    /// Authenticates clients using their public key
    async fn auth_publickey(&mut self, _: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        match key {
            // The passed key contains unnecessary header bytes, so we compare the suffix
            // self.pubkey is of fixed size, so we can safely use ends_with
            PublicKey::Ed25519(k) if k.as_bytes().ends_with(self.pubkey.as_bytes()) => {
                Ok(Auth::Accept)
            }
            _ => Ok(Auth::Reject {
                proceed_with_methods: None,
            }),
        }
    }

    /// Handles data received from the client
    async fn data(
        &mut self,
        _: ChannelId,
        data: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(shell) = &mut *self.shell.lock().await {
            if let Some(stdin) = shell.stdin.as_mut() {
                stdin.write_all(data).await.ok();
            }
        }
        Ok(())
    }

    /// Cleans up when the client closes the channel
    async fn channel_close(&mut self, _: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        self.cleanup().await;
        Ok(())
    }

    /// Cleans up when the client sends EOF
    async fn channel_eof(&mut self, _: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        self.cleanup().await;
        Ok(())
    }
}

impl Handler {
    /// Cleans up the shell process when a session ends
    async fn cleanup(&mut self) {
        if let Some(mut child) = self.shell.lock().await.take() {
            // Ignore errors when killing the shell process
            // This is a kill() and we restart the podman container anyway
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }
}
