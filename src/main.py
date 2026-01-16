import argparse
import json
import logging
import time
import json
import os
import signal
import sys
import subprocess
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

def update_log_level():
    """Update logging level from config."""
    level_name = Config.LOG_LEVEL.upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.getLogger().setLevel(level)
    logger.setLevel(level)

STATE_FILE = "misp_data/state.json"
            
def display_banner():
    """Displays the startup ASCII banner using custom.png."""
    try:
        banner_path = "assets/custom.png"
        if os.path.exists(banner_path):
            subprocess.run(
                ["chafa", banner_path, "--size=80x40", "--colors",
                 "none", "--symbols", "braille"],
                check=False
            )
        else:
            msg = ("The application tried to display a startup "
                   "banner, but could not find the image at "
                   f"{banner_path}.")
            logger.warning(msg)
    except Exception as e:
        msg = ("An attempt to display the startup banner was made, "
               f"but it didn't quite work: {e}")
        logger.debug(msg)

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"The application encountered an issue while trying to read its previous progress from {STATE_FILE}. It seems the file might be corrupted or inaccessible: {e}")
    return {}

def save_state(state):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f)
        
        ts = state.get('last_timestamp')
        dt_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else "N/A"
        logger.info(f"The application has successfully saved its current progress. The next check will pick up from indicators published after: {dt_str} (UTC).")
    except Exception as e:
        logger.error(f"The application tried to save its progress to {STATE_FILE}, but ran into a problem. This might mean it will re-process some data when it restarts: {e}")

def signal_handler(sig, frame):
    msg = ("A shutdown signal was received. The application is now "
           "gracefully closing its connections and stopping its work.")
    logger.info(msg)
    sys.exit(0)

def extract_entity_value(entity_data):
    """Extract primary identifier from entity structure."""
    if 'hostname' in entity_data:
        return entity_data['hostname']
    if 'ip' in entity_data:
        return entity_data['ip']
    if 'url' in entity_data:
        return entity_data['url']
    if 'file' in entity_data:
        f_data = entity_data['file']
        return next(iter(f_data.values())) if f_data else "N/A"
    return "N/A"

def parse_days_or_date(val):
    """Parses a value as days (int) or date (YYYY-MM-DD), returning days offset from now."""
    if not val:
        return 0
    val = str(val).strip()
    try:
        # Check if it looks like a date
        target_date = datetime.strptime(val, '%Y-%m-%d')
        delta = (datetime.utcnow() - target_date).days
        return max(0, delta)
    except ValueError:
        try:
            return int(val)
        except ValueError:
            logger.error(f"Invalid value: {val}. Must be integer days or YYYY-MM-DD.")
            return 0

def print_summary_table(items):
    """Prints a structured ASCII table of threat entities."""
    if not items:
        return
    headers = ["Type", "Value", "Collected Date", "Vendor", "Product"]
    col_widths = [15, 30, 15, 12, 10]
    header_line = " | ".join(
        h.ljust(w) for h, w in zip(headers, col_widths)
    )
    print("\n" + "="*len(header_line))
    print(header_line)
    print("-" * len(header_line))
    for item in items:
        row = [
            str(item.get('type', 'N/A'))[:col_widths[0]],
            str(item.get('value', 'N/A'))[:col_widths[1]],
            str(item.get('date', 'N/A'))[:col_widths[2]],
            str(item.get('vendor', 'Unknown'))[:col_widths[3]],
            str(item.get('product', 'MISP'))[:col_widths[4]]
        ]
        print(" | ".join(
            val.ljust(width) for val, width in zip(row, col_widths)
        ))
    print("="*len(header_line) + "\n")

def parse_args():
    parser = argparse.ArgumentParser(
        description='MISP to Google SecOps Forwarder'
    )
    parser.add_argument(
        '--config', type=str, help='Path to JSON configuration file'
    )
    parser.add_argument(
        '--fetch-interval', type=int,
        help='Polling interval in seconds'
    )
    parser.add_argument(
        '--fetch-page-size', type=int,
        help='Attributes per page request'
    )
    parser.add_argument(
        '--forwarder-batch-size', type=int,
        help='Events per Ingestion API call'
    )
    parser.add_argument(
        '--test-mode', action='store_true', help='Run in test mode'
    )
    parser.add_argument(
        '--max-test-events', type=int,
        help='Max events to process in test mode'
    )
    parser.add_argument(
        '--historical-polling-days', type=str,
        help='Days to look back on first run (0 = disable) or date YYYY-MM-DD'
    )

    return parser.parse_args()



def main():
    # First things first, show our banner!
    display_banner()
    
    args = parse_args()

    # Load Config (Args > File > Env > Defaults)
    config_path = args.config if args.config else "config.json"
    if os.path.exists(config_path):
        logger.info(f"The application is loading your custom configuration settings from {config_path}.")
        if not Config.reload_from_file(config_path):
            logger.error(f"Failed to load configuration from {config_path}. Using defaults.")
    else:
        logger.info(f"The application looked for {config_path} but didn't find it. It will use defaults or environment variables instead.")
    
    # Override with CLI args if provided
    if args.fetch_interval: Config.FETCH_INTERVAL = args.fetch_interval
    if args.fetch_page_size: Config.FETCH_PAGE_SIZE = args.fetch_page_size
    if args.forwarder_batch_size: Config.FORWARDER_BATCH_SIZE = args.forwarder_batch_size
    if args.test_mode: Config.TEST_MODE = True
    if args.max_test_events: Config.MAX_TEST_EVENTS = args.max_test_events
    if args.historical_polling_days: Config.HISTORICAL_POLLING_DAYS = args.historical_polling_days

    # Apply log level
    update_log_level()

    logger.info("The MISP to Google SecOps Forwarder is now initializing and getting ready to bridge your threat intelligence pipeline.")

    # Validate Config
    try:
        Config.validate()
    except ValueError as e:
        logger.critical(f"The application found some errors in its configuration and cannot continue safely: {e}")
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    misp = MispClient()
    secops = SecOpsManager()

    if not misp.test_connection():
        logger.error("The application tried to connect to MISP but couldn't establish a link. It will keep trying automatically during its normal operation.")



    state = load_state()
    # Determine start timestamp
    logger.info(f"Last timestamp: {state.get('last_timestamp', 0)},{state}")
    last_timestamp = state.get('last_timestamp', 0)
    
    if last_timestamp == 0:
        # First run? Check historical polling config
        hist_days = parse_days_or_date(Config.HISTORICAL_POLLING_DAYS)
        
        if hist_days > 0:
            logger.info(f"It looks like this is the first run! The application is configured to look back {hist_days} days to catch up on recent threats.")
            from datetime import timedelta
            start_dt = datetime.utcnow() - timedelta(days=hist_days)
            last_timestamp = int(start_dt.timestamp())
        else:
            logger.info("It looks like this is the first run! The application will start monitoring for new threats from this moment onward.")
            last_timestamp = int(datetime.utcnow().timestamp())
    else:
        dt_str = datetime.fromtimestamp(last_timestamp).strftime('%Y-%m-%d %H:%M:%S')
        logger.info(f"The application is entering its routine monitoring loop. It is currently picking up from where it left off, at the point in time: {dt_str} (UTC).")

    if Config.TEST_MODE:
        logger.info(f"The application is currently running in TEST MODE. It will process exactly {Config.MAX_TEST_EVENTS} entities and then automatically shut down.")

    total_events_sent = 0
    config_last_mtime = 0
    if config_path and os.path.exists(config_path):
        config_last_mtime = os.path.getmtime(config_path)

    # Track configs to detect changes

    last_historical_polling_days = Config.HISTORICAL_POLLING_DAYS
    logger.info(f"Historical polling days: {last_historical_polling_days}")

    def _reload_config():
        nonlocal config_last_mtime
        if not (config_path and os.path.exists(config_path)):
            return False
        
        current = os.path.getmtime(config_path)
        if current == config_last_mtime:
            return False
            
        logger.info("Config modification detected. Reloading...")
        if not Config.reload_from_file(config_path):
            logger.error(f"Failed to reload config from {config_path}.")
            return False
            
        config_last_mtime = current
        update_log_level()
        logger.info(f"Config reloaded. Batch: {Config.FORWARDER_BATCH_SIZE}")
        return True

    def _check_historical_polling():
        nonlocal last_timestamp, last_historical_polling_days
        if str(Config.HISTORICAL_POLLING_DAYS) == str(last_historical_polling_days):
            return False

        logger.info("Historical Polling changed. Resyncing...")
        offset = parse_days_or_date(Config.HISTORICAL_POLLING_DAYS)
        if offset > 0:
            from datetime import timedelta
            new_start = datetime.utcnow() - timedelta(days=offset)
            last_timestamp = int(new_start.timestamp())
            logger.info(f"Resetting sync start time to {new_start} (UTC).")
        
        last_historical_polling_days = Config.HISTORICAL_POLLING_DAYS
        return True



    def check_config_updates():
        if _reload_config():
            restart = _check_historical_polling()

            return restart
        return False
    while True:
        try:
            if check_config_updates():
                logger.info("Configuration change. Restarting loop.")
                continue

            logger.info("Checking MISP for new indicators...")
            
            sync_start_ts = int(datetime.utcnow().timestamp())
            page = 1
            total_processed = 0
            restart_loop = False
            
            while True:
                if check_config_updates():
                    logger.info("Configuration change detected during fetch. Restarting cycle...")
                    restart_loop = True
                    break

                attributes = misp.fetch_attributes(
                    last_timestamp=last_timestamp, 
                    page=page, 
                    limit=Config.FORWARDER_BATCH_SIZE
                )
                
                if not attributes:
                    break
                
                logger.info(f"Retrieved {len(attributes)} attributes (Page {page}).")
                
                entities = []
                display_items = []
                for attr in attributes:
                    entity = SecOpsManager.convert_to_entity(attr)
                    if entity:
                        entities.append(entity)
                        display_items.append({
                            'type': attr.get('type', 'unknown'),
                            'value': attr.get('value', 'N/A'),
                            'date': attr.get('timestamp', 'N/A') if 'date' not in attr else attr['date'],
                            'vendor': entity.get('metadata', {}).get('vendor_name', 'Unknown'),
                            'product': entity.get('metadata', {}).get('product_name', 'MISP')
                        })
                
                if entities:
                    print_summary_table(display_items)
                    for i in range(0, len(entities), Config.FORWARDER_BATCH_SIZE):
                        batch = entities[i : i + Config.FORWARDER_BATCH_SIZE]
                        secops.send_entities(batch)
                        total_events_sent += len(batch)
                        if Config.TEST_MODE and total_events_sent >= Config.MAX_TEST_EVENTS:
                            logger.info(f"Test limit ({Config.MAX_TEST_EVENTS}) reached. Exiting.")

                            sys.exit(0)
                
                total_processed += len(attributes)
                page += 1
            
            if restart_loop:
                continue

            if total_processed > 0:
                logger.info("Threat data delivered to SecOps.")
                state['last_timestamp'] = sync_start_ts
                save_state(state)
                last_timestamp = sync_start_ts
            else:
                logger.info("No new threat indicators found.")
                state['last_timestamp'] = sync_start_ts
                save_state(state)
                last_timestamp = sync_start_ts

            logger.info(f"Sync complete. Sleeping {Config.FETCH_INTERVAL}s.")
            time.sleep(Config.FETCH_INTERVAL)

        except KeyboardInterrupt:
            signal_handler(None, None)
        except Exception as e:
            logger.error(f"Unexpected error in loop: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
