from pathlib import Path
from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class WorkloadManager:
    NGINX_CONFIG = """
    server {
        listen 80;
        server_name localhost;

        location / {
            root /usr/share/nginx/html;
            index index.html;
        }

        location /custom {
            return 200 'Hello from custom location\\n';
        }
    }
    """

    DEFAULT_CONFIG = {
        "image": "docker.io/library/nginx:latest",
        "persist_dirs": ["/etc/nginx/conf.d"],
        "port": 80
    }

    @staticmethod
    def setup_ssh_config(ssh_dir: Path, owner_key: ed25519.Ed25519PrivateKey) -> Path:
        """Create SSH key files and return path to private key"""
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        
        key_path = ssh_dir / "test_key"
        
        # Save private key
        key_bytes = owner_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption()
        )
        key_path.write_bytes(key_bytes)
        key_path.chmod(0o600)
        
        # Save public key
        pub_key_path = key_path.with_suffix('.pub')
        pub_key_path.write_text(WorkloadManager.ed25519_to_ssh_public_key(
            owner_key.public_key().public_bytes_raw()
        ))
        pub_key_path.chmod(0o644)
        
        return key_path

    @staticmethod
    def ed25519_to_ssh_public_key(key_bytes):
        """Convert raw Ed25519 public key bytes to SSH format"""
        key_type = "ssh-ed25519"
        key_parts = [
            len(key_type).to_bytes(4, 'big'),
            key_type.encode(),
            len(key_bytes).to_bytes(4, 'big'),
            key_bytes
        ]
        key_blob = b''.join(key_parts)
        return f"{key_type} {b64encode(key_blob).decode()}"

    @staticmethod
    def configure_nginx():
        """Configure nginx by writing custom config"""
        path = "/tmp/tdx-identity-persist/podman/etc/nginx/conf.d/default.conf"
        with open(path, "w") as f:
            f.write(WorkloadManager.NGINX_CONFIG)

    @staticmethod
    def get_default_config(instance_pubkey):
        """Get default workload configuration"""
        return {
            "instance_pubkey": instance_pubkey,
            **WorkloadManager.DEFAULT_CONFIG
        }

    @staticmethod
    def get_expose_config(instance_pubkey):
        """Get workload expose configuration"""
        return {
            "instance_pubkey": instance_pubkey,
            "image": WorkloadManager.DEFAULT_CONFIG["image"]
        }