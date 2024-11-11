# TDX Identity Service

A secure identity management system built for Intel TDX (Trust Domain Extensions) environments. This projects allows for secure delegation of container management through hierarchical identity verification and hardware-backed attestation.

## Overview

This project consists of two main services:

1. **Identity Service** (port 3001): Manages instance identities, operator/owner registration, and workload deployment
2. **Registry Service** (port 3000): Validates and stores attestation data and identity relationships

Together, these services enable:
- Hardware-backed identity verification using Intel TDX
- Secure key delegation from operators to owners
- Encrypted container storage with owner-specific keys
- Temporary secure SSH access for container setup

## State Flow

The system follows a linear progression of state:

1. **Initial State**: A fresh TDX instance has only its instance key pair
2. **Operator Registration**: An operator registers their public key and gets an owner token
3. **Owner Registration**: An owner uses the token to register their public key
4. **Workload Configuration**: The owner configures a container and gets SSH access
5. **Workload Exposure**: The owner finalizes the configuration, stopping SSH access and exposing the container port

## Usage

### Environment Variables

Identity Service:
- `STORAGE_PATH`: Path for persistent storage (default: `/mnt`)
- `MOCK_TDX_URL`: URL for mock TDX service when running without TDX hardware
- `REGISTRY_URL`: URL of registry service (default: `http://localhost:3000`)

Registry Service:
- `REGISTRY_DB_PATH`: Path to registry database file (default: `registry.db`)
- `SKIP_TDX_AUTH`: Skip TDX attestation verification (for testing)
- `PCCS_URL`: Intel Provisioning Certificate Caching Service URL

### HTTP Routes

Identity Service (`localhost:3001`):
```
GET  /instance/pubkey     # Get instance public key
POST /operator/register   # Register operator public key
POST /owner/register      # Register owner public key with token
POST /workload/configure  # Start podman container with specified config
POST /workload/expose     # Close SSH access and expose port
```

Registry Service (`localhost:3000`):
```
POST /register            # Register instance attestation (called by identity service)
GET  /instance/{pubkey}   # Get instance registration info
```

## Project Structure

```
.
├── identity_svc/              # Identity service implementation
│   └── src/
│       ├── encryption.rs      # FUSE encryption mounting
│       ├── error.rs           # Error handling
│       ├── handlers.rs        # HTTP route handlers
│       ├── main.rs            # Service entry point
│       ├── ssh.rs             # SSH server implementation
│       ├── state.rs           # State progression
│       ├── storage.rs         # Filesystem persistence
│       ├── tdx.rs             # TDX quote generation
│       ├── validation.rs      # Request validation
│       └── workload.rs        # Container management
│
├── registry/                  # Registry service implementation
│   └── src/
│       ├── error.rs           # Error handling
│       ├── handlers.rs        # HTTP route handlers
│       ├── main.rs            # Service entry point
│       ├── state.rs           # Database management
│       ├── tdx.rs             # Quote verification
│       └── validation.rs      # Request validation
│
├── shared/                    # Shared code between services
│   └── src/
│       ├── encrypted_ppid.rs  # PPID extraction utilities
│       ├── lib.rs             # Library entry point
│       ├── report_data.rs     # Attestation data handling
│       └── sig_validation.rs  # Signature verification
│
└── tests/                     # Integration tests
```

## System Requirements

The identity service assumes the following about the underlying OS:

- Intel TDX hardware support (or mock service for testing)
- gocryptfs installed (for encrypted storage)
- Podman installed with container registry configured
- FUSE user_allow_other enabled in `/etc/fuse.conf` (not needed if running as root)
- Port 2222 available for SSH access
- Port 8080 should be exposed only after using nginx (or similar) to add the instance pubkey
  into response headers and proxying through cvm-reverse-proxy

## Running Tests

The test suite includes integration tests that verify the full flow from registration to workload deployment:

```bash
# Install Python dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r tests/requirements.txt

# Run cargo build before testing (this is necessary)
cargo build

# Run tests
pytest tests/
```

## Production Readiness Gaps

Current limitations that should be addressed before production use:

- PPID extraction doesn't support type 5 PCK certificate chain
- Podman containers aren't configured with AppArmor/SECcomp profiles
- Uses several beta/unaudited libraries
- Lacks proper key management system integration
- Missing rate limiting and DoS protection
- Registry service is not designed for on-chain or HA use cases