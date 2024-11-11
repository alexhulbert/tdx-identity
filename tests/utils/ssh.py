import time
import paramiko
from pathlib import Path

def connect_with_retry(key_path: Path, max_retries: int = 5, delay: int = 2) -> bool:
    """Attempt SSH connection with retries"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for attempt in range(max_retries):
        try:
            ssh.connect(
                'localhost',
                port=2222,
                username='root',
                key_filename=str(key_path),
                timeout=5
            )
            ssh.close()
            return True
        except Exception as e:
            print(f"Connection attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
    
    return False