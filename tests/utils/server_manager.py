import os
import shutil
import signal
import subprocess
import time

class ServerManager:
    """Manages the lifecycle of test servers"""
    REGISTRY_PATH = '/tmp/registry.db'
    IDENTITY_PATH = '/tmp/identity_svc'

    def __init__(self):
        self.processes = {}

    def start(self, reset_state: bool = True) -> None:
        if reset_state:
            for path in [self.REGISTRY_PATH, self.IDENTITY_PATH]:
                if os.path.exists(path):
                    if os.path.isfile(path):
                        os.remove(path)
                    else:
                        shutil.rmtree(path)

        # Start registry with TDX auth skipped
        self.processes['registry'] = subprocess.Popen(
            ['cargo', 'run', '--bin', 'tdx-registry'],
            env={
                **os.environ, 
                'SKIP_TDX_AUTH': '1',
                'REGISTRY_DB_PATH': self.REGISTRY_PATH
            }
        )

        # Start identity service (no TDX skip needed)
        self.processes['identity'] = subprocess.Popen(
            ['cargo', 'run', '--bin', 'identity-svc'],
            env={
                **os.environ,
                'STORAGE_PATH': self.IDENTITY_PATH
            }
        )

        time.sleep(2)  # Wait for services to start

    def stop(self) -> None:
        for process in self.processes.values():
            process.send_signal(signal.SIGINT)
            process.wait()
        self.processes.clear()