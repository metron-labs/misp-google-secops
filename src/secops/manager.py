import json
import logging
import time
from datetime import datetime, timedelta

import requests
import google.auth.transport.requests
from google.oauth2 import service_account
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log
)

from src.config import Config
from src.utils.http_handler import SECOPS_ERROR_HANDLER

logger = logging.getLogger(__name__)

class SecOpsManager:
    # Manager for Google SecOps interactions, including conversion
    # of MISP attributes to Entities and ingestion via Entity API.
    def __init__(self):
        self.creds = None
        self._load_credentials()

    def _load_credentials(self):
        # Load Google Service Account credentials.
        try:
            self.creds = (
                service_account.Credentials
                .from_service_account_file(
                    Config.GOOGLE_SA_CREDENTIALS,
                    scopes=[
                        'https://www.googleapis.com/auth/'
                        'malachite-ingestion'
                    ]
                )
            )
        except Exception as e:
            msg = (
                "The application was unable to load your Google "
                "Service Account credentials. Please ensure the path "
                "provided in your configuration is correct and the "
                f"file is accessible: {e}"
            )
            logger.error(msg)
            raise

    def _get_auth_header(self):
        # Refresh token if needed and return Authorization header.
        if not self.creds.valid:
            request = google.auth.transport.requests.Request()
            self.creds.refresh(request)
        return {'Authorization': f'Bearer {self.creds.token}'}

    @retry(
        retry=retry_if_exception_type(requests.exceptions.RequestException),
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=2, max=60),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True
    )
    def send_entities(self, entities):
        # Send a batch of Entity Context (IoCs) to Google SecOps.
        if not entities:
            return
            
        headers = self._get_auth_header()
        headers['Content-Type'] = 'application/json'
        payload = {
            "customerId": Config.GOOGLE_CUSTOMER_ID,
            "log_type": "MISP_IOC",
            "entities": entities
        }
        logger.debug(
            f"Preparing ingestion payload for customer "
            f"{Config.GOOGLE_CUSTOMER_ID} containing "
            f"{len(entities)} threat records."
        )
        
        try:
            msg = (
                f"Sending {len(entities)} threat entities to Google "
                f"SecOps instance."
            )
            logger.info(msg)
            
            response = requests.post(
                Config.SECOPS_ENTITY_API_URL,
                headers=headers,
                data=json.dumps(payload),
                timeout=60
            )
            
            SECOPS_ERROR_HANDLER.handle_response(response)
                
            msg = (
                "The threat data has been successfully delivered "
                "and ingested into Google SecOps. These indicators "
                "are now active for detection."
            )
            logger.info(msg)
            
        except requests.exceptions.RequestException as e:
            msg = (
                "The application encountered a technical problem "
                "while communicating with the Google SecOps Entity "
                f"API: {e}"
            )
            logger.error(msg)
            raise

    @staticmethod
    def convert_to_entity(attribute):
        # Convert a MISP attribute to a JSON-serializable Entity.
        if not attribute:
            return None
        attr_type = attribute.get('type')
        value = attribute.get('value')
        event_data = attribute.get('Event', {})
        event_info = event_data.get('info', 'MISP IoC')
        orgc_name = event_data.get('Orgc', {}).get('name', 'Unknown')
        threat_level_id = event_data.get('threat_level_id', '2')
        
        severity_map = {
            '1': 'CRITICAL',
            '2': 'HIGH', 
            '3': 'MEDIUM',
            '4': 'LOW'
        }
        severity = severity_map.get(str(threat_level_id), 'HIGH')
        
        entity_type_map = {
            'domain': 'DOMAIN_NAME',
            'hostname': 'DOMAIN_NAME',
            'ip-src': 'IP_ADDRESS',
            'ip-dst': 'IP_ADDRESS',
            'url': 'URL',
            'md5': 'FILE',
            'sha1': 'FILE',
            'sha256': 'FILE'
        }
        
        entity_type = entity_type_map.get(attr_type)
        if not entity_type:
            return None
        
        entity = {}
        if attr_type in ['domain', 'hostname']:
            entity = {"hostname": value}
        elif attr_type in ['ip-src', 'ip-dst']:
            entity = {"ip": value}
        elif attr_type == 'url':
            entity = {"url": value}
        elif attr_type in ['md5', 'sha1', 'sha256']:
            entity = {
                "file": {
                    attr_type: value
                }
            }
        
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(days=90)
        
        entity_context = {
            "metadata": {
                "collected_timestamp": (
                    SecOpsManager._get_current_timestamp_rfc3339()
                ),
                "vendor_name": orgc_name,
                "product_name": "MISP",
                "entity_type": entity_type,
                "source_type": "ENTITY_CONTEXT",
                "interval": {
                    "start_time": start_time.strftime(
                        '%Y-%m-%dT%H:%M:%SZ'
                    ),
                    "end_time": end_time.strftime('%Y-%m-%dT%H:%M:%SZ')
                },
                "threat": [{
                    "category": "NETWORK_SUSPICIOUS",
                    "severity": severity,
                    "summary": event_info,
                    "threat_id": attribute.get('uuid', ''),
                    "description": attribute.get('comment', ''),
                }]
            },
            "entity": entity
        }
        
        return entity_context

    @staticmethod
    def _format_timestamp(timestamp):
        # Convert MISP timestamp (epoch or string) to RFC3339.
        if not timestamp:
            return SecOpsManager._get_current_timestamp_rfc3339()
        
        try:
            dt = datetime.fromtimestamp(int(timestamp))
            return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            return SecOpsManager._get_current_timestamp_rfc3339()

    @staticmethod
    def _get_current_timestamp_rfc3339():
        # Get current timestamp in RFC3339 format.
        return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
