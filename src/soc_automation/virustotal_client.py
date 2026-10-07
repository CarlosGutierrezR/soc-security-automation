import os

import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, api_key=None, timeout=10, dry_run=True):
        self.api_key = api_key or os.getenv("VT_API_KEY")
        self.timeout = timeout
        self.dry_run = dry_run

    def _headers(self):
        if not self.api_key:
            raise ValueError("VT_API_KEY is required for live requests")

        return {
            "accept": "application/json",
            "x-apikey": self.api_key,
        }

    def _get(self, path):
        if self.dry_run:
            return {
                "status": "dry_run",
                "request": {
                    "method": "GET",
                    "url": f"{VT_BASE_URL}{path}",
                },
            }

        response = requests.get(
            f"{VT_BASE_URL}{path}",
            headers=self._headers(),
            timeout=self.timeout,
        )

        response.raise_for_status()
        return response.json()

    def lookup_ipv4(self, value):
        return self._get(f"/ip_addresses/{value}")

    def lookup_domain(self, value):
        return self._get(f"/domains/{value}")

    def lookup_sha256(self, value):
        return self._get(f"/files/{value}")
