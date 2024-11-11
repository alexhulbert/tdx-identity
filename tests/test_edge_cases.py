from cryptography.hazmat.primitives.asymmetric import ed25519
import pytest
import requests

def test_double_operator_registration(servers, api, operator_key):
    """Test that operator can't be registered twice"""
    servers.start()
    
    instance_pubkey = api.get_instance_pubkey()
    
    # First registration should succeed
    api.register_operator(instance_pubkey, operator_key)
    
    # Second registration should fail
    new_operator_key = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api.register_operator(instance_pubkey, new_operator_key)
    assert exc_info.value.response.status_code == 400

def test_workload_validation(registered_environment, api, workload):
    """Test validation of workload configuration"""
    instance_pubkey = registered_environment['instance_pubkey']
    owner_key = registered_environment['owner_key']
    
    # Test with invalid port
    invalid_config = workload.get_default_config(instance_pubkey)
    invalid_config["port"] = -1
    
    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api.configure_workload(owner_key, invalid_config)
    assert exc_info.value.response.status_code == 400
    
    # Test with missing required field
    del invalid_config["port"]
    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api.configure_workload(owner_key, invalid_config)
    assert exc_info.value.response.status_code == 400

def test_expose_before_configure(registered_environment, api, workload):
    """Test that workload exposure fails if not configured"""
    instance_pubkey = registered_environment['instance_pubkey']
    owner_key = registered_environment['owner_key']
    
    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        api.expose_workload(owner_key, workload.get_expose_config(instance_pubkey))
    assert exc_info.value.response.status_code == 400