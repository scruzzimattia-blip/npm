import logging
import requests
import os
from typing import Optional, List

logger = logging.getLogger(__name__)

class CrowdSecManager:
    def __init__(self):
        self.api_url = os.getenv("CROWDSEC_LAPI_URL", "http://crowdsec:8080").rstrip("/")
        self.api_key = os.getenv("CROWDSEC_LAPI_KEY")
        self.headers = {
            "X-Api-Key": self.api_key,
            "User-Agent": "Traefik-God-Mode",
        }

    def block_ip(self, ip: str, duration: str = "24h", reason: str = "Traefik God Mode Detection"):
        """Create a ban decision in CrowdSec."""
        if not self.api_key:
            return False

        url = f"{self.api_url}/v1/decisions"
        payload = [{
            "value": ip,
            "scope": "Ip",
            "type": "ban",
            "origin": "traefik-god-mode",
            "duration": duration,
            "reason": reason
        }]

        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=5)
            return response.status_code == 201
        except:
            return False

    def unblock_ip(self, ip: str):
        """Remove all active decisions for a specific IP."""
        if not self.api_key:
            return False

        url = f"{self.api_url}/v1/decisions"
        params = {"ip": ip}

        try:
            response = requests.delete(url, headers=self.headers, params=params, timeout=5)
            return response.status_code == 200
        except:
            return False

    def get_ip_reputation(self, ip: str) -> Optional[dict]:
        """Check if an IP has active decisions."""
        if not self.api_key:
            return None

        url = f"{self.api_url}/v1/decisions"
        params = {"ip": ip}

        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=5)
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
            response = requests.get(url, headers=self.headers, timeout=5)
            if response.status_code == 200:
                return response.json() or []
        except:
            pass
        return []
