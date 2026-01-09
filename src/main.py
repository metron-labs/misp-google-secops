import logging
import time
import json
import os
import signal
import sys
from datetime import datetime
from src.config import Config
from src.misp.client import MispClient
from src.secops.manager import SecOpsManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("misp-forwarder")

STATE_FILE = "data/state.json"

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
    return {}

def save_state(state):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f)
        logger.info(f"State saved to {STATE_FILE}. New last_timestamp: {state.get('last_timestamp')}")
    except Exception as e:
        logger.error(f"Failed to save state: {e}")

def signal_handler(sig, frame):
    logger.info("Shutdown signal received. Exiting...")
    sys.exit(0)

def main():
    logger.info("Starting MISP to Google SecOps Forwarder...")
    
    # Validate Config
    try:
        Config.validate()
    except ValueError as e:
        logger.critical(f"Configuration invalid: {e}")
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    misp = MispClient()
    secops = SecOpsManager()

    if not misp.test_connection():
        logger.error("Could not connect to MISP on startup. Will retry in loop.")

    state = load_state()
    # Default to 7 days ago if no state, to fetch some initial context
    # or just start from now? Usually 1-7 days is good for initial sync.
    # We will use 1 day ago for safety.
    last_timestamp = state.get('last_timestamp', 0)

    logger.info(f"Starting fetch loop. Last timestamp: {last_timestamp}")

    # TEST MODE from Config
    if Config.TEST_MODE:
        logger.info(f"RUNNING IN TEST MODE. Will exit after sending {Config.MAX_TEST_EVENTS} entities.")

    total_events_sent = 0

    while True:
        try:
            logger.info("Checking for new attributes...")
            
            # Fetch
            # Simple pagination loop for the current sync window
            page = 1
            total_processed = 0
            
            while True:
                attributes = misp.fetch_attributes(
                    last_timestamp=last_timestamp, 
                    page=page, 
                    limit=Config.FETCH_PAGE_SIZE
                )
                
                if not attributes:
                    break
                
                #logger.info(f"Fetched {attributes} attributes on page {page}.")
                
                # Convert to Entity Context (IoCs)
                entities = []
                for attr in attributes:
                    # TEST MODE: Stop collecting if we have enough
                    if Config.TEST_MODE and total_events_sent >= Config.MAX_TEST_EVENTS:
                        break
                        
                    entity = SecOpsManager.convert_to_entity(attr)
                    if entity:
                        entities.append(entity)
                
                # Forward entities (IoCs) in batches
                if entities:
                    # In TEST MODE, only send what we need to reach MAX_TEST_EVENTS
                    if Config.TEST_MODE:
                        entities_to_send = entities[:Config.MAX_TEST_EVENTS - total_events_sent]
                    else:
                        entities_to_send = entities
                    
                    # Forward in chunks of FORWARDER_BATCH_SIZE
                    for i in range(0, len(entities_to_send), Config.FORWARDER_BATCH_SIZE):
                        batch = entities_to_send[i : i + Config.FORWARDER_BATCH_SIZE]
                        secops.send_entities(batch)
                        logger.info(f"Forwarded batch of {len(batch)} IoC entities.")
                        total_events_sent += len(batch)
                    
                    # TEST MODE: Exit after sending required entities
                    pass
                        # Removed early exit from here - moved to after state save
                    

                total_processed += len(attributes)
                
                # Update timestamp to the latest seen attribute to avoid huge re-fetches if we crash?
                # Actually, standard is to update state ONLY after fully processing a time window.
                # OR update high-water mark.
                # MISP REST search filter by timestamp is inclusive usually.
                # We should update last_timestamp to the MAX timestamp seen in this batch + 1s preferably.
                
                max_ts = 0
                for attr in attributes:
                    ts = int(attr.get('timestamp', 0))
                    if ts > max_ts:
                        max_ts = ts
                
                if max_ts > 0:
                    state['last_timestamp'] = max_ts + 1 
                    save_state(state)
                    
                    # TEST MODE: Exit after sending required entities AND saving state
                    if Config.TEST_MODE and total_events_sent >= Config.MAX_TEST_EVENTS:
                        logger.info(f"TEST MODE: Successfully sent {total_events_sent} IoC entities to Google SecOps. State saved. Exiting.")
                        sys.exit(0)
                
                page += 1

            if total_processed == 0:
                logger.info("No new attributes found.")
            else:
                logger.info(f"Completed sync cycle. Total processed: {total_processed}")
            
        except Exception as e:
            logger.error(f"Error in main loop: {e}", exc_info=True)
        
        logger.info(f"Sleeping for {Config.FETCH_INTERVAL} seconds...")
        time.sleep(Config.FETCH_INTERVAL)

if __name__ == "__main__":
    main()
