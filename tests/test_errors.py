import requests
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from .utils.server_manager import ServerManager
from .utils.api_client import ApiClient

def test_invalid_operator_signature(servers: ServerManager, api: ApiClient):
    """Test that invalid operator signatures are rejected"""
    servers.start()
    instance_pubkey = api.get_instance_pubkey()
    
    # Try to register with wrong signature
    wrong_key = ed25519.Ed25519PrivateKey.generate()
    operator_key = ed25519.Ed25519PrivateKey.generate()
    operator_pubkey = operator_key.public_key().public_bytes_raw().hex()
    wrong_signature = wrong_key.sign(bytes.fromhex(instance_pubkey)).hex()
    
    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        requests.post(
            f'{api.identity_url}/operator/register',
            json={"pubkey": operator_pubkey, "signature": wrong_signature}
        ).raise_for_status()
    assert exc_info.value.response.status_code == 401

def test_workload_requires_owner(servers: ServerManager, api: ApiClient):
    """Test that workload configuration requires owner registration"""
    servers.start()
    instance_pubkey = api.get_instance_pubkey()
    operator_key = ed25519.Ed25519PrivateKey.generate()
    owner_key = ed25519.Ed25519PrivateKey.generate()
    
    api.register_operator(instance_pubkey, operator_key)
    # Don't register owner

    workload_config = {
        "instance_pubkey": instance_pubkey,
        "image": "docker.io/library/nginx:latest",
        "persist_dirs": ["/etc/nginx/conf.d"],
        "port": 80
    }
    
    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api.configure_workload(owner_key, workload_config)
    assert exc_info.value.response.status_code == 401

def test_owner_requires_operator(servers: ServerManager, api: ApiClient):
    """Test that owner registration requires operator to be registered first"""
    servers.start()
    instance_pubkey = api.get_instance_pubkey()
    owner_key = ed25519.Ed25519PrivateKey.generate()
    
    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api.register_owner(instance_pubkey, owner_key, 'invalid-token')
    assert exc_info.value.response.status_code == 401