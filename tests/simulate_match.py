#!/usr/bin/env python3
"""
UDM Event Generator for IoC Match Testing
Generates a UDM event based on user-provided IoC value to test SecOps matching
"""
import sys
import uuid
import json
import os
import logging
import requests
import google.auth.transport.requests
from google.oauth2 import service_account
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("udm-generator")

try:
    from src.config import Config
except ImportError as e:
    logger.error(f"Error importing project modules: {e}")
    sys.exit(1)

def get_current_timestamp():
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

def main():
    """Main execution function for UDM event generation."""
    logger.info("UDM Event Generator for IoC Match Testing")
    logger.info("=" * 50)
    
    if (Config.GOOGLE_SA_CREDENTIALS == '/app/credentials.json' and 
        not os.path.exists('/app/credentials.json')):
         local_creds = os.path.abspath('credentials.json')
         if os.path.exists(local_creds):
              logger.info(f"Using local credentials: {local_creds}")
              Config.GOOGLE_SA_CREDENTIALS = local_creds

    try:
        Config.validate()
    except ValueError as e:
        logger.error(f"Configuration Invalid: {e}")
        return

    logger.info("\nEnter IoC details to generate a matching UDM event:")
    logger.info("\nSupported types:")
    logger.info("  1. IP address (e.g., 192.168.1.100)")
    logger.info("  2. Domain/Hostname (e.g., malicious.com)")
    logger.info("  3. URL (e.g., http://malicious.com/path)")
    logger.info("  4. File hash (MD5/SHA1/SHA256)")
    
    ioc_type = input("\nSelect type (1-4): ").strip()
    ioc_value = input("Enter IoC value: ").strip()
    
    if not ioc_value:
        logger.error("Error: IoC value cannot be empty")
        return
    
    udm_target = {}
    event_desc = ""
    
    if ioc_type == "1":
        udm_target['ip'] = [ioc_value]
        event_desc = f"Simulated connection to IP: {ioc_value}"
        logger.info(f"\nGenerating event for IP: {ioc_value}")
    elif ioc_type == "2":
        udm_target['hostname'] = ioc_value
        event_desc = f"Simulated connection to domain: {ioc_value}"
        logger.info(f"\nGenerating event for domain: {ioc_value}")
    elif ioc_type == "3":
        udm_target['url'] = ioc_value
        event_desc = f"Simulated connection to URL: {ioc_value}"
        logger.info(f"\nGenerating event for URL: {ioc_value}")
    elif ioc_type == "4":
        hash_type = input("Hash type (md5/sha1/sha256): ").strip().lower()
        if hash_type not in ['md5', 'sha1', 'sha256']:
            logger.error("Invalid hash type")
            return
        udm_target['file'] = {hash_type: ioc_value}
        event_desc = f"Simulated file event with {hash_type}: {ioc_value}"
        logger.info(f"\nGenerating event for file hash: {ioc_value}")
    else:
        logger.error("Invalid type selection")
        return

    event = {
        "metadata": {
            "productName": "TrafficSimulator",
            "vendorName": "Internal",
            "productEventType": "Simulation",
            "eventType": "NETWORK_CONNECTION",
            "description": event_desc,
            "eventTimestamp": get_current_timestamp(),
            "productLogId": str(uuid.uuid4())
        },
        "principal": {
            "hostname": "test-workstation",
            "ip": ["10.0.0.100"],
            "user": {
                "userid": "test_user"
            }
        },
        "target": udm_target,
        "network": {
            "ipProtocol": "TCP",
            "direction": "OUTBOUND"
        },
        "securityResult": [{
            "description": "Test Event for IoC Matching",
            "severity": "LOW"
        }]
    }

    logger.info("\n--- UDM Event Payload ---")
    logger.info(json.dumps(event, indent=2))
    logger.info("-------------------------\n")

    try:
        creds = service_account.Credentials.from_service_account_file(
            Config.GOOGLE_SA_CREDENTIALS,
            scopes=['https://www.googleapis.com/auth/malachite-ingestion']
        )
        auth_req = google.auth.transport.requests.Request()
        creds.refresh(auth_req)
        token = creds.token
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        return

    url = os.getenv(
        'SECOPS_UDM_API_URL',
        'https://malachiteingestion-pa.googleapis.com/v2/udmevents:batchCreate'
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "customerId": Config.GOOGLE_CUSTOMER_ID,
        "events": [event]
    }

    logger.info("Sending UDM event to Google SecOps...")
    try:
        res = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if res.status_code == 200:
            logger.info("\n✓ UDM Event Sent Successfully!")
            logger.info("\nNext Steps:")
            logger.info("1. Go to Google SecOps Console")
            logger.info("2. Navigate to 'Investigation > SIEM Search'")
            logger.info(f"3. Search for: graph.target.hostname = \"{ioc_value}\"")
            logger.info("4. Check 'Alerts > IoC Matches' for correlation")
        else:
            logger.error(f"\n✗ Failed to send event. Status: {res.status_code}")
            logger.error(f"Response: {res.text}")
            
    except Exception as e:
        logger.error(f"\n✗ Failed to send event: {e}")

if __name__ == "__main__":
    main()
