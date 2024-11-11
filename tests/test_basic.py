def test_basic_registration_flow(servers, api, operator_key, owner_key):
    """Test the basic registration flow: operator -> owner -> workload"""
    servers.start()
    
    instance_pubkey = api.get_instance_pubkey()
    
    # Register operator and owner
    owner_token = api.register_operator(instance_pubkey, operator_key)
    api.register_owner(instance_pubkey, owner_key, owner_token)

    # Verify registration
    data = api.get_instance(instance_pubkey)
    assert 'operator' in data
    assert 'owner' in data

def test_persistence(servers, api, operator_key, owner_key):
    """Test that state persists across server restarts"""
    servers.start()
    
    instance_pubkey = api.get_instance_pubkey()
    
    # Initial registration
    owner_token = api.register_operator(instance_pubkey, operator_key)
    api.register_owner(instance_pubkey, owner_key, owner_token)

    # Restart servers without clearing state
    servers.stop()
    servers.start(reset_state=False)
    
    # Verify state persisted
    new_pubkey = api.get_instance_pubkey()
    assert new_pubkey == instance_pubkey
    
    data = api.get_instance(instance_pubkey)
    assert 'operator' in data
    assert 'owner' in data