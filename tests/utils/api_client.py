import json
from typing import Dict, Any
import requests
from cryptography.hazmat.primitives.asymmetric import ed25519

class ApiClient:
    """Handles API interactions with the services"""
    def __init__(self):
        self.identity_url = 'http://localhost:3001'
        self.registry_url = 'http://localhost:3000'

    def get_instance_pubkey(self) -> str:
        response = requests.get(f'{self.identity_url}/instance/pubkey')
        response.raise_for_status()
        return response.json()['pubkey']

    def register_operator(self, instance_pubkey: str, operator_key: ed25519.Ed25519PrivateKey) -> str:
        operator_pubkey = operator_key.public_key().public_bytes_raw().hex()
        signature = operator_key.sign(bytes.fromhex(instance_pubkey)).hex()
        
        response = requests.post(
            f'{self.identity_url}/operator/register',
            json={"pubkey": operator_pubkey, "signature": signature}
        )
        response.raise_for_status()
        return response.json()['owner_token']

    def register_owner(self, instance_pubkey: str, owner_key: ed25519.Ed25519PrivateKey, owner_token: str) -> None:
        owner_pubkey = owner_key.public_key().public_bytes_raw().hex()
        signature = owner_key.sign(bytes.fromhex(instance_pubkey)).hex()
        
        response = requests.post(
            f'{self.identity_url}/owner/register',
            headers={'x-token': owner_token},
            json={"pubkey": owner_pubkey, "signature": signature}
        )
        response.raise_for_status()

    def configure_workload(self, owner_key: ed25519.Ed25519PrivateKey, config: Dict[str, Any]) -> None:
        signature = owner_key.sign(json.dumps(config).encode()).hex()
        response = requests.post(
            f'{self.identity_url}/workload/configure',
            headers={'x-signature': signature},
            json=config
        )
        response.raise_for_status()

    def get_instance(self, instance_pubkey: str) -> Dict[str, Any]:
        response = requests.get(f'{self.registry_url}/instance/{instance_pubkey}')
        response.raise_for_status()
        return response.json()
    
    def expose_workload(self, owner_key: ed25519.Ed25519PrivateKey, config: Dict[str, Any]) -> None:
        signature = owner_key.sign(json.dumps(config).encode()).hex()
        response = requests.post(
            f'{self.identity_url}/workload/expose',
            headers={'x-signature': signature},
            json=config
        )
        response.raise_for_status()