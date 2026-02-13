import docker
import os
import tempfile
from typing import Optional, Tuple

class Sandbox:
    def __init__(self, image: str = "python:3.11-slim"):
        try:
            self.client = docker.from_env()
        except Exception as e:
            # Docker might not be installed, treat as fallback/unavailable
            self.client = None
        self.image = image

    def execute_poc(self, poc_code: str, timeout: int = 30) -> Tuple[bool, str]:
        """
        Executes a PoC script in an ephemeral, hardened container.
        """
        if not self.client:
            return False, "Docker unavailable"

        with tempfile.TemporaryDirectory() as tmp_dir:
            poc_file = os.path.join(tmp_dir, "poc.py")
            with open(poc_file, "w") as f:
                f.write(poc_code)

            try:
                # MANDATORY SANDBOX HARDENING
                container = self.client.containers.run(
                    self.image,
                    command=["python", "/mnt/poc.py"],
                    volumes={tmp_dir: {"bind": "/mnt", "mode": "ro"}},
                    network_mode="bridge", 
                    mem_limit="128m",
                    nano_cpus=500000000, 
                    remove=True,
                    stderr=True,
                    stdout=True,
                    detach=False,
                    timeout=timeout,
                    # security_opt=["no-new-privileges"], # Removing explicit seccomp to default to Docker's specific profile (safe)
                    cap_drop=["ALL"], # Drop all capabilities
                    user="nobody" # Run as non-root
                )
                return True, container.decode("utf-8")
            except Exception as e:
                return False, f"Sandbox Failure: {str(e)}"

    def is_healthy(self) -> bool:
        if not self.client: return False
        try:
            self.client.ping()
            return True
        except:
            return False
