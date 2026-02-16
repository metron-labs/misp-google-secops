import json
import logging
import time
from datetime import datetime, timedelta

import requests
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log
)

from src.config import Config
from src.utils.http_handler import MISP_ERROR_HANDLER

logger = logging.getLogger(__name__)

class MispClient:
    # Client for interacting with MISP api.
    
    def __init__(self):
        self.base_url = Config.MISP_URL.rstrip('/')
        self.headers = {
            'Authorization': Config.MISP_API_KEY,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        self.verify_ssl = Config.MISP_VERIFY_SSL

    @retry(
        retry=retry_if_exception_type(requests.exceptions.RequestException),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True
    )
    def fetch_attributes(
        self, last_timestamp=None, until_timestamp=None,
        page=1, limit=100
    ):
        # Fetch attributes from MISP with automatic retry.
        endpoint = f"{self.base_url}/attributes/restSearch"
        payload = {
            'page': page,
            'limit': limit,
            'returnFormat': 'json',
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
                # defaulting to the current time if until_timestamp is not set.
                current_ts = int(datetime.utcnow().timestamp())
                payload['timestamp'] = [last_timestamp, current_ts]
        
        try:
            msg = (
                f"Requesting page {page} of threat indicators from "
                f"MISP, collecting up to {limit} items."
            )
            logger.info(msg)
            
            response = requests.post(
                endpoint,
                headers=self.headers,
                json=payload,
                verify=self.verify_ssl,
                timeout=30
            )
            
            MISP_ERROR_HANDLER.handle_response(response)
            
            data = response.json()
            attributes = data.get('response', {}).get('Attribute', [])
            return attributes
            
        except requests.exceptions.RequestException as e:
            msg = (
                "The application ran into an issue while trying to "
                "retrieve data from the MISP server. This could be "
                f"due to a network problem or a temporary server "
                f"error: {e}"
            )
            logger.error(msg)
            if hasattr(e, 'response') and e.response is not None:
                logger.debug(
                    f"Technical details for diagnosis: "
                    f"{e.response.text}"
                )
            raise

    def test_connection(self):
        # Test connectivity to MISP.
        try:
            response = requests.get(
                f"{self.base_url}/servers/getVersion",
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=10
            )
            response.raise_for_status()
            msg = (
                "Successfully established a secure connection to the "
                "MISP server and is ready to proceed."
            )
            logger.info(msg)
            return True
        except Exception as e:
            msg = (
                "The application tried to reach the MISP server but "
                "couldn't verify the connection. Please check your "
                f"URL and API key settings: {e}"
            )
            logger.error(msg)
            return False
