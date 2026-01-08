import logging
import sys
import uuid
import json
import os
import requests
import google.auth.transport.requests
from google.oauth2 import service_account
from datetime import datetime
from dotenv import load_dotenv

# Add parent directory to path to import Config if needed, 
# although for this standalone script we might just read env directly.
# But let's try to be clean.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from config import Config
except ImportError:
    # Fallback if run incorrectly
    pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("traffic-simulator")

# Load env if likely running locally and Config didn't catch it
load_dotenv()

def get_current_timestamp():
    # Use UTC 'Z' format
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

def main():
    print("🚀 Starting Traffic Simulation to Trigger IoC Match...")
    
    # 1. Credentials
    creds_path = os.getenv('GOOGLE_SA_CREDENTIALS', 'credentials.json')
    if not os.path.exists(creds_path):
        # Try parent dir
        creds_path = os.path.join('..', 'credentials.json')
    
    if not os.path.exists(creds_path):
        print(f"❌ Could not find credentials.json at {creds_path}")
        return

    customer_id = os.getenv('GOOGLE_CUSTOMER_ID')
    if not customer_id:
        print("❌ GOOGLE_CUSTOMER_ID not set in environment.")
        return

    # 2. Authenticate
    try:
        # Scope for Ingestion
        creds = service_account.Credentials.from_service_account_file(
            creds_path,
            scopes=['https://www.googleapis.com/auth/malachite-ingestion']
        )
        auth_req = google.auth.transport.requests.Request()
        creds.refresh(auth_req)
        token = creds.token
        print("✅ Authenticated with Google Cloud")
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
        return

    # 3. Build UDM Event (Stream B)
    # Simulate match for 'ameteksen.com'
    target_domain = "ameteksen.com"
    
    print(f"📡 Simulating traffic to malicious domain: {target_domain}")
    
    event = {
        "metadata": {
            "productName": "TrafficSimulator",
            "vendorName": "Internal",
            "productEventType": "Simulation",
            "eventType": "NETWORK_CONNECTION",
            "description": f"Simulated connection to malicious domain {target_domain}",
            "eventTimestamp": get_current_timestamp(),
            "productLogId": str(uuid.uuid4())
        },
        "principal": {
            "hostname": "simulation-workstation",
            "ip": ["192.168.1.100"],
            "user": {
                "userid": "test_user"
            }
        },
        "target": {
            "hostname": target_domain,
            "ip": ["203.0.113.55"],
            "port": 443
        },
        "network": {
            "ipProtocol": "TCP",
            "direction": "OUTBOUND"
        },
        "securityResult": [{
            "description": "Simulation Event",
            "severity": "LOW"
        }]
    }

    payload = {
        "customerId": customer_id,
        "events": [event]
    }

    # 4. Send to Ingestion API
    url = "https://malachiteingestion-pa.googleapis.com/v2/udmevents:batchCreate"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        print(f"DTO size: 1 Events")
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        
        if response.status_code == 200:
            print("✅ SIMULATION SENT SUCCESSFULLY!")
            print("\n⏳ Next Steps:")
            print("1. Go to Google SecOps Console")
            print("2. Navigate to 'Detections' -> 'IoC Matches'")
            print("3. Look for a match involving 'ameteksen.com'")
        else:
            print(f"❌ Failed to send. Status: {response.status_code}")
            print(f"Response: {response.text}")
            
    except Exception as e:
        print(f"❌ Failed to send simulation event: {e}")

if __name__ == "__main__":
    main()
