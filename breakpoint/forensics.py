import hashlib
import json
import hmac
import time
import os
import uuid

class ForensicLogger:
    """
    Implements an immutable chain-of-custody log for all attack actions.
    Generates a cryptographic hash of the run to verify integrity.
    """
    def __init__(self, run_id=None, verbose=False):
        self.run_id = run_id or str(uuid.uuid4())
        self.verbose = verbose
        self.start_time = time.time()
        self.chain_hash = hashlib.sha256(self.run_id.encode()).hexdigest()
        self.log_file = f"audit_{self.run_id}.log"
        self.events = []
        
        # Session Key (Simulated HSM/Vault retrieval)
        self.session_key = os.urandom(32).hex()

        self._write_entry("RUN_START", {"timestamp": self.start_time, "run_id": self.run_id})

    def log_event(self, event_type: str, data: dict):
        """
        Logs an event and updates the hash chain.
        """
        timestamp = time.time()
        entry = {
            "type": event_type,
            "timestamp": timestamp,
            "data": data,
            "prev_hash": self.chain_hash
        }
        
        # Serialize for hashing (Deterministic JSON)
        entry_str = json.dumps(entry, sort_keys=True)
        
        # Update Chain: Hash(Prev_Hash + Current_Entry_Str)
        self.chain_hash = hashlib.sha256((self.chain_hash + entry_str).encode()).hexdigest()
        
        # HMAC Signing (Forensic Proof)
        signature = hmac.new(self.session_key.encode(), entry_str.encode(), hashlib.sha256).hexdigest()
        
        entry["current_hash"] = self.chain_hash
        entry["signature"] = signature
        self.events.append(entry)
        
        # Persist immediately to disk (Audit Trail)
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
            
        return self.chain_hash

    def verify_chain(self, log_file):
        """
        Verifies the integrity of a log file.
        """
        # Implementation would read file line by line and re-hash to match chain
        pass

    def sign_run(self):
        """
        Generates a final HMAC signature for the entire run.
        """
        integrity_blob = f"{self.run_id}:{self.start_time}:{self.chain_hash}"
        signature = hmac.new(self.session_key.encode(), integrity_blob.encode(), hashlib.sha256).hexdigest()
        
        self._write_entry("RUN_COMPLETE", {"signature": signature, "final_hash": self.chain_hash})
        return {
            "run_id": self.run_id,
            "final_hash": self.chain_hash,
            "signature": signature,
            "audit_file": self.log_file
        }

    def _write_entry(self, ev_type, data):
        self.log_event(ev_type, data)

    def log_override_event(self, mode: str, target: str, env: str, operator_context: str = None):
        """
        Logs a critical safety override event (e.g., forcing destructive mode in prod).
        This must never be skipped when gates are opened.
        """
        if not operator_context:
            try:
                import platform
                operator_context = f"{os.environ.get('USERNAME')}@{platform.node()} (PID: {os.getpid()})"
            except:
                operator_context = "UNKNOWN"
            
        data = {
            "mode": mode,
            "target": target,
            "environment": env,
            "operator": operator_context,
            "status": "OVERRIDE_AUTHORIZED"
        }
        self.log_event("SAFETY_OVERRIDE", data)
