import os
import time
import pytest
import paramiko
from pathlib import Path
from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from .utils.server_manager import ServerManager
from .utils.api_client import ApiClient
from .utils.workload import WorkloadManager

@pytest.fixture
def servers():
    manager = ServerManager()
    yield manager
    manager.stop()

@pytest.fixture
def api():
    return ApiClient()

@pytest.fixture
def workload():
    return WorkloadManager()

@pytest.fixture
def operator_key():
    return ed25519.Ed25519PrivateKey.generate()

@pytest.fixture
def owner_key():
    return ed25519.Ed25519PrivateKey.generate()

@pytest.fixture
def registered_environment(servers, api, operator_key, owner_key):
    """Sets up a complete test environment with servers running and owner registered"""
    servers.start()
    
    # Get instance pubkey after servers are started
    instance_pubkey = api.get_instance_pubkey()
    
    # Register operator and owner
    owner_token = api.register_operator(instance_pubkey, operator_key)
    api.register_owner(instance_pubkey, owner_key, owner_token)
    
    return {
        'instance_pubkey': instance_pubkey,
        'operator_key': operator_key,
        'owner_key': owner_key,
        'owner_token': owner_token
    }

@pytest.fixture
def ssh_key_path(tmp_path: Path, owner_key):
    """Create SSH key files and return path to private key"""
    return WorkloadManager.setup_ssh_config(tmp_path, owner_key)
