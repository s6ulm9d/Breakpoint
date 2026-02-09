import docker
import os
import tempfile
from typing import Optional, Tuple

class Sandbox:
    def __init__(self, image: str = "python:3.11-slim"):
        try:
            self.client = docker.from_env()
        except Exception as e:
            print(f"[-] Docker not available: {e}")
            self.client = None
        self.image = image

    def execute_poc(self, poc_code: str, timeout: int = 30) -> Tuple[bool, str]:
        """
        Executes a PoC script in an ephemeral, hardened container.
        Returns (success, output).
        """
        if not self.client:
            return False, "Docker client not initialized. Cannot run sandbox."

        # Create a temporary directory for the PoC
        with tempfile.TemporaryDirectory() as tmp_dir:
            poc_file = os.path.join(tmp_dir, "poc.py")
            with open(poc_file, "w") as f:
                f.write(poc_code)

            try:
                # Basic hardening: read-only root, no-new-privileges, network isolation (optional)
                # For vulnerability testing, we might need network access to the target.
                container = self.client.containers.run(
                    self.image,
                    command=["python", "/mnt/poc.py"],
                    volumes={tmp_dir: {"bind": "/mnt", "mode": "ro"}},
                    network_mode="bridge", # Default, but can be locked down
                    mem_limit="128m",
                    nano_cpus=500000000, # 0.5 CPU
                    remove=True,
                    stderr=True,
                    stdout=True,
                    detach=False,
                    timeout=timeout,
                    security_opt=["no-new-privileges"]
                )
                return True, container.decode("utf-8")
            except docker.errors.ContainerError as e:
                return False, f"Container Error: {e.stderr.decode('utf-8')}"
            except Exception as e:
                return False, f"Execution failed: {str(e)}"

    def is_healthy(self) -> bool:
        if not self.client: return False
        try:
            self.client.ping()
            return True
        except:
            return False
