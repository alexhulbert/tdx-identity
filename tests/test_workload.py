import pytest
import requests
import time

from tests.utils.ssh import connect_with_retry

def test_ssh_access_and_nginx_config(
    registered_environment, api, workload, ssh_key_path
):
    """Test SSH access to container and nginx configuration"""
    instance_pubkey = registered_environment['instance_pubkey']
    owner_key = registered_environment['owner_key']
    
    # Configure and start workload
    config = workload.get_default_config(instance_pubkey)
    api.configure_workload(owner_key, config)
    
    # Verify SSH access
    assert connect_with_retry(ssh_key_path), "Failed to establish SSH connection"
    
    # Configure and expose nginx
    workload.configure_nginx()
    api.expose_workload(owner_key, workload.get_expose_config(instance_pubkey))
    
    time.sleep(2)  # Wait for nginx to start
    
    # Test custom location
    response = requests.get('http://localhost:8080/custom')
    assert response.status_code == 200
    assert "Hello from custom location" in response.text

def test_workload_persistence(
    servers, registered_environment, api, workload, ssh_key_path
):
    """Test that workload configuration persists across restarts"""
    instance_pubkey = registered_environment['instance_pubkey']
    owner_key = registered_environment['owner_key']
    
    # Configure and start workload
    config = workload.get_default_config(instance_pubkey)
    api.configure_workload(owner_key, config)
    
    # Verify SSH access
    assert connect_with_retry(ssh_key_path), "Failed to establish SSH connection"
    
    # Configure and expose nginx
    workload.configure_nginx()
    api.expose_workload(owner_key, workload.get_expose_config(instance_pubkey))
    time.sleep(2)
    
    # Verify initial nginx response
    response = requests.get('http://localhost:8080/custom')
    assert response.status_code == 200
    assert "Hello from custom location" in response.text
    
    # Restart servers
    servers.stop()
    servers.start(reset_state=False)
    time.sleep(15)
    
    # Verify custom config persists
    response = requests.get('http://localhost:8080/custom')
    assert response.status_code == 200
    assert "Hello from custom location" in response.text

def test_directory_traversal_prevention(registered_environment, api, workload):
    """Test that directory traversal attempts are blocked"""
    instance_pubkey = registered_environment['instance_pubkey']
    owner_key = registered_environment['owner_key']
    
    bad_paths = [
        "/etc/nginx/conf.d/../../../etc/shadow",
        "../outside/container",
        "/var/log/nginx/../../etc/passwd",
    ]

    for bad_path in bad_paths:
        config = workload.get_default_config(instance_pubkey)
        config["persist_dirs"] = [bad_path]
        
        with pytest.raises(requests.exceptions.HTTPError) as exc_info:
            api.configure_workload(owner_key, config)
        assert exc_info.value.response.status_code == 400
        assert "Invalid directory path" in exc_info.value.response.json()["error"]