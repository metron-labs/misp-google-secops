import json
import logging
import time
from datetime import datetime, timedelta

import requests

from src.config import Config

logger = logging.getLogger(__name__)

class MispClient:
    def __init__(self):
        self.base_url = Config.MISP_URL.rstrip('/')
        self.headers = {
            'Authorization': Config.MISP_API_KEY,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.verify_ssl = Config.MISP_VERIFY_SSL

    def fetch_attributes(self, last_timestamp=None, page=1, limit=100):
        """
        Fetch attributes from MISP.
        :param last_timestamp: Unix timestamp (int) or datetime object to fetch attributes updated since then.
        :param page: Page number.
        :param limit: Number of results per page.
        :return: List of attributes.
        """
        endpoint = f"{self.base_url}/attributes/restSearch"
        
        payload = {
            'page': page,
            'limit': limit,
            'returnFormat': 'json',
            # We want specific types that map well to UDM
            # IP, domain, hostname, file hashes, etc.
            'type': [
                'ip-src', 'ip-dst', 'domain', 'hostname', 
                'md5', 'sha1', 'sha256', 'url', 'uri'
            ],
            # Ensure we get published events
            'published': 1,
            # We also want to filter out attributes that are too old or deleted, 
            # but deleted logic is complex (MISP doesn't easily show deleted attributes in restSearch unless specifically asked, usually for sync).
            # For simplicity in this forwarder, we sync active IoCs.
        }

        if last_timestamp:
            payload['timestamp'] = last_timestamp

        try:
            logger.info(f"Fetching MISP attributes page {page} with limit {limit}")
            response = requests.post(
                endpoint, 
                headers=self.headers, 
                json=payload, 
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            attributes = data.get('response', {}).get('Attribute', [])
            return attributes
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching from MISP: {e}")
            if e.response:
                logger.error(f"Response content: {e.response.text}")
            raise

    def test_connection(self):
        """Test connectivity to MISP."""
        try:
            # lightweight call to check version/auth
            response = requests.get(
                f"{self.base_url}/servers/getVersion", 
                headers=self.headers, 
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            logger.info("Successfully connected to MISP.")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to MISP: {e}")
            return False
