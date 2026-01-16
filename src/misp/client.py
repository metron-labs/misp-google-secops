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

<<<<<<< HEAD
    def fetch_attributes(self, last_timestamp=None, page=1, limit=100):
        """
        Fetch attributes from MISP.
        :param last_timestamp: Unix timestamp (int) or datetime object to fetch attributes updated since then.
        :param page: Page number.
        :param limit: Number of results per page.
        :return: List of attributes.
        """
        endpoint = f"{self.base_url}/attributes/restSearch"
        
=======
    def fetch_attributes(
        self, last_timestamp=None, until_timestamp=None,
        page=1, limit=100
    ):
        """Fetch attributes from MISP."""
        endpoint = f"{self.base_url}/attributes/restSearch"
>>>>>>> feature-updates
        payload = {
            'page': page,
            'limit': limit,
            'returnFormat': 'json',
<<<<<<< HEAD
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
=======
            'type': [
                'ip-src', 'ip-dst', 'domain', 'hostname',
                'md5', 'sha1', 'sha256', 'url', 'uri'
            ],
            'published': 1,
        }

        if last_timestamp:
            if until_timestamp:
                payload['timestamp'] = [
                    last_timestamp, until_timestamp
                ]
            else:
                payload['timestamp'] = last_timestamp
        logger.info(payload)
        try:
            msg = (f"The application is requesting page {page} of "
                   f"threat indicators from MISP, collecting up to "
                   f"{limit} items at once.")
            logger.info(msg)
            response = requests.post(
                endpoint,
                headers=self.headers,
                json=payload,
>>>>>>> feature-updates
                verify=self.verify_ssl,
                timeout=30
            )
            response.raise_for_status()
<<<<<<< HEAD
            
            data = response.json()
            attributes = data.get('response', {}).get('Attribute', [])
            return attributes
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching from MISP: {e}")
            if e.response:
                logger.error(f"Response content: {e.response.text}")
=======
            data = response.json()
            attributes = data.get('response', {}).get('Attribute', [])
            return attributes
        except requests.exceptions.RequestException as e:
            msg = ("The application ran into an issue while trying to "
                   "retrieve data from the MISP server. This could be "
                   f"due to a network problem or a temporary server "
                   f"error: {e}")
            logger.error(msg)
            if e.response:
                logger.debug(
                    f"Technical details for diagnosis: "
                    f"{e.response.text}"
                )
>>>>>>> feature-updates
            raise

    def test_connection(self):
        """Test connectivity to MISP."""
        try:
<<<<<<< HEAD
            # lightweight call to check version/auth
            response = requests.get(
                f"{self.base_url}/servers/getVersion", 
                headers=self.headers, 
=======
            response = requests.get(
                f"{self.base_url}/servers/getVersion",
                headers=self.headers,
>>>>>>> feature-updates
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
<<<<<<< HEAD
            logger.info("Successfully connected to MISP.")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to MISP: {e}")
=======
            msg = ("The application has successfully established a "
                   "secure connection to the MISP server and is ready "
                   "to proceed.")
            logger.info(msg)
            return True
        except Exception as e:
            msg = ("The application tried to reach the MISP server but "
                   "couldn't verify the connection. Please check your "
                   f"URL and API key settings: {e}")
            logger.error(msg)
>>>>>>> feature-updates
            return False
