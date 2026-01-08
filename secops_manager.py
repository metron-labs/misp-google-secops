import json
import logging
from datetime import datetime, timedelta

import requests
import google.auth.transport.requests
from google.oauth2 import service_account

from config import Config

logger = logging.getLogger(__name__)

class SecOpsManager:
    """
    Manager class to handle Google SecOps interactions, including
    conversion of MISP attributes to Entities and ingestion via the Entity API.
    """
    
    # Entity API endpoint for IoC ingestion
    ENTITY_API_URL = "https://malachiteingestion-pa.googleapis.com/v2/entities:batchCreate"

    def __init__(self):
        self.creds = None
        self._load_credentials()

    def _load_credentials(self):
        try:
            # Use Chronicle-specific scope for ingestion
            self.creds = service_account.Credentials.from_service_account_file(
                Config.GOOGLE_SA_CREDENTIALS,
                scopes=['https://www.googleapis.com/auth/malachite-ingestion']
            )
        except Exception as e:
            logger.error(f"Failed to load Google credentials: {e}")
            raise

    def _get_auth_header(self):
        """Refresh token if needed and return Authorization header dict."""
        if not self.creds.valid:
            request = google.auth.transport.requests.Request()
            self.creds.refresh(request)
        return {'Authorization': f'Bearer {self.creds.token}'}

    def send_entities(self, entities):
        """
        Send a batch of Entity Context (IoCs) to Google SecOps.
        :param entities: List of entity context dicts.
        """
        if not entities:
            return

        headers = self._get_auth_header()
        headers['Content-Type'] = 'application/json'
        
        # Structure the payload as expected by Entity API
        payload = {
            "customerId": Config.GOOGLE_CUSTOMER_ID,
            "log_type": "MISP_IOC",
            "entities": entities
        }
        
        logger.info(f"Payload structure: customerId={Config.GOOGLE_CUSTOMER_ID}, entities count={len(entities)}")
        # Debug print payload if needed, ensuring sensitive info isn't excessive
        # print("Full Entity Payload JSON:")
        # print(json.dumps(payload, indent=2))
        
        try:
            logger.info(f"Sending {len(entities)} entities to Google SecOps...")
            response = requests.post(
                self.ENTITY_API_URL,
                headers=headers,
                data=json.dumps(payload),
                timeout=60
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to ingest entities. Status: {response.status_code}, Response: {response.text}")
                response.raise_for_status()
                
            logger.info("Successfully ingested entities as IoCs.")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Entity API error: {e}")
            raise

    @staticmethod
    def convert_to_entity(attribute):
        """
        Convert a single MISP attribute to a JSON-serializable Entity dict.
        """
        if not attribute:
            return None
            
        attr_type = attribute.get('type')
        value = attribute.get('value')
        event_data = attribute.get('Event', {})
        
        # Extract event context
        event_info = event_data.get('info', 'MISP IoC')
        # event_uuid = event_data.get('uuid', '') # Unused
        orgc_name = event_data.get('Orgc', {}).get('name', 'Unknown')
        threat_level_id = event_data.get('threat_level_id', '2')
        # threat_level_name = event_data.get('ThreatLevel', {}).get('name', 'Medium') # Unused
        
        # Map MISP threat level to severity
        severity_map = {
            '1': 'CRITICAL',
            '2': 'HIGH', 
            '3': 'MEDIUM',
            '4': 'LOW'
        }
        severity = severity_map.get(str(threat_level_id), 'HIGH')
        
        # Map MISP type to entity type
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
        
        # Build entity object based on type
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
        
        # Calculate expiration (default 90 days from now)
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(days=90)
        
        # Build entity context structure
        entity_context = {
            "metadata": {
                "collected_timestamp": SecOpsManager._get_current_timestamp_rfc3339(),
                "vendor_name": orgc_name,
                "product_name": "MISP",
                "entity_type": entity_type,
                "source_type": "ENTITY_CONTEXT",
                "interval": {
                    "start_time": start_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
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
        """Convert MISP timestamp (epoch or string) to RFC3339 string."""
        if not timestamp:
            return SecOpsManager._get_current_timestamp_rfc3339()
        
        try:
            dt = datetime.fromtimestamp(int(timestamp))
            return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            return SecOpsManager._get_current_timestamp_rfc3339()

    @staticmethod
    def _get_current_timestamp_rfc3339():
        return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
