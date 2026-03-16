import logging
import requests
import os
from typing import Optional, List

logger = logging.getLogger(__name__)

class CrowdSecManager:
    def __init__(self):
        self.api_url = os.getenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080").rstrip("/")
        self.api_key = os.getenv("CROWDSEC_LAPI_KEY")
        self.machine_login = os.getenv("CROWDSEC_MACHINE_LOGIN", "localhost")
        self.machine_password = os.getenv("CROWDSEC_MACHINE_PASSWORD")
        
        # Headers for bouncer operations (GET/DELETE)
        self.bouncer_headers = {
            "X-Api-Key": self.api_key,
            "User-Agent": "traefik-god-mode",
        }
        
        # Headers for machine operations (POST) - using password auth
        self.machine_headers = {
            "User-Agent": "traefik-god-mode",
        }

    def block_ip(self, ip: str, duration: str = "24h", reason: str = "Traefik God Mode Detection"):
        """Create a ban decision in CrowdSec."""
        import subprocess
        
        # Use cscli command to add decision
        cmd = [
            "cscli", "decisions", "add",
            "--ip", ip,
            "--type", "ban",
            "--duration", duration,
            "--reason", reason
        ]
        
        # Execute cscli command in CrowdSec container
        full_cmd = ["docker", "exec", "traefik-stats-crowdsec"] + cmd
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Debug output
        logger.debug(f"Block IP command: {' '.join(full_cmd)}")
        logger.debug(f"Return code: {result.returncode}")
        logger.debug(f"Stdout: {result.stdout}")
        logger.debug(f"Stderr: {result.stderr}")
        
        # Check if successful - output goes to stderr, not stdout
        success = result.returncode == 0 and "successfully" in (result.stdout + result.stderr).lower()
        logger.debug(f"Success: {success}")
        return success

    def unblock_ip(self, ip: str):
        """Remove all active decisions for a specific IP."""
        import subprocess
        
        try:
            # Use cscli command to delete decision
            cmd = [
                "cscli", "decisions", "delete",
                "--ip", ip
            ]
            
            # Execute cscli command in CrowdSec container
            full_cmd = ["docker", "exec", "traefik-stats-crowdsec"] + cmd
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Debug output
            logger.debug(f"Unblock IP command: {' '.join(full_cmd)}")
            logger.debug(f"Return code: {result.returncode}")
            logger.debug(f"Stdout: {result.stdout}")
            logger.debug(f"Stderr: {result.stderr}")
            
            # Check if successful
            success = result.returncode == 0 and "deleted" in (result.stdout + result.stderr).lower()
            logger.debug(f"Success: {success}")
            return success
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {e}")
            return False

    def get_ip_reputation(self, ip: str) -> Optional[dict]:
        """Check if an IP has active decisions."""
        if not self.api_key:
            return None

        url = f"{self.api_url}/v1/decisions"
        params = {"ip": ip}

        try:
            response = requests.get(url, headers=self.bouncer_headers, params=params, timeout=5)
            if response.status_code == 200:
                decisions = response.json()
                return decisions[0] if decisions else None
        except:
            pass
        return None

    def get_all_decisions(self) -> List[dict]:
        """List all current decisions (bans)."""
        if not self.api_key:
            return []

        url = f"{self.api_url}/v1/decisions"
        try:
            response = requests.get(url, headers=self.bouncer_headers, timeout=5)
            if response.status_code == 200:
                return response.json() or []
        except:
            pass
        return []
