import argparse
import json
import logging
import time
import os
import signal
import sys
import subprocess
from datetime import datetime, timedelta
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
            msg = (f"The application could not find the startup "
                   f"banner image at {banner_path}. Skipping.")
            logger.warning(msg)
    except Exception as e:
        msg = f"Unable to display the startup banner: {e}"
        logger.debug(msg)


def load_state():
    """Loads application state from a JSON file."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            msg = (f"Unable to read progress from {STATE_FILE}. "
                   f"File may be corrupted: {e}")
            logger.error(msg)
    return {}


def save_state(state):
    """Saves application state to a JSON file."""
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        msg = (f"Failed to save progress to {STATE_FILE}. "
               f"Data might be re-processed on restart: {e}")
        logger.error(msg)


def signal_handler(sig, frame):
    """Handles termination signals for graceful shutdown."""
    msg = ("Shutdown signal received. Closing connections "
           "and stopping operations.")
    logger.info(msg)
    sys.exit(0)


def extract_entity_value(entity_data):
    """Extract primary identifier from entity structure."""
    keys = ['hostname', 'ip', 'url']
    for key in keys:
        if key in entity_data:
            return entity_data[key]
    if 'file' in entity_data:
        f_data = entity_data['file']
        return next(iter(f_data.values())) if f_data else "N/A"
    return "N/A"


def parse_days_or_date(val):
    """Parses a value as days (int) or date (YYYY-MM-DD)."""
    if not val:
        return 0
    val = str(val).strip()
    try:
        target_date = datetime.strptime(val, '%Y-%m-%d')
        delta = (datetime.utcnow() - target_date).days
        return max(0, delta)
    except ValueError:
        try:
            return int(val)
        except ValueError:
            msg = f"Invalid value: {val}. Using 0."
            logger.error(msg)
            return 0


def log_summary_table(items):
    """Logs a structured ASCII table of threat entities."""
    if not items:
        return
    headers = ["Type", "Value", "Collected Date", "Vendor", "Product"]
    col_widths = [15, 30, 15, 12, 10]
    header_line = " | ".join(h.ljust(w) for h, w in zip(headers, col_widths))
    
    logger.info("-" * len(header_line))
    logger.info(header_line)
    logger.info("-" * len(header_line))
    for item in items:
        row = [
            str(item.get('type', 'N/A'))[:col_widths[0]],
            str(item.get('value', 'N/A'))[:col_widths[1]],
            str(item.get('date', 'N/A'))[:col_widths[2]],
            str(item.get('vendor', 'Unknown'))[:col_widths[3]],
            str(item.get('product', 'MISP'))[:col_widths[4]]
        ]
        logger.info(" | ".join(val.ljust(w) for val, w in zip(row, col_widths)))
    logger.info("-" * len(header_line))


def parse_args():
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description='MISP to Google SecOps Forwarder'
    )
    parser.add_argument('--config', type=str, help='Path to JSON config')
    parser.add_argument('--fetch-interval', type=int, help='Interval in s')
    parser.add_argument('--fetch-page-size', type=int, help='Page size')
    parser.add_argument('--forwarder-batch-size', type=int, help='Batch size')
    parser.add_argument('--test-mode', action='store_true', help='Test mode')
    parser.add_argument('--max-test-events', type=int, help='Max test events')
    parser.add_argument('--historical-polling-days', type=str,
                        help='Days or YYYY-MM-DD for backfill')
    return parser.parse_args()


class ConfigRestartException(Exception):
    """Raised when configuration changes require a process restart."""
    pass


def smart_sleep(seconds, check_config_func):
    """Sleeps for elements, checking config status every second."""
    for _ in range(int(seconds)):
        if check_config_func():
            raise ConfigRestartException()
        time.sleep(1)
    
    remaining = seconds - int(seconds)
    if remaining > 0:
        time.sleep(remaining)
        if check_config_func():
            raise ConfigRestartException()


CSV_FILE = "misp_data/pushed_events.csv"


def append_to_csv(entities):
    """Appends pushed entities to a CSV file for tracking."""
    if not entities:
        return
    try:
        file_exists = os.path.exists(CSV_FILE)
        os.makedirs(os.path.dirname(CSV_FILE), exist_ok=True)
        with open(CSV_FILE, 'a') as f:
            if not file_exists:
                f.write("timestamp,value,type,vendor,product,severity\n")
            now = datetime.utcnow().isoformat()
            for e in entities:
                metadata = e.get('metadata', {})
                val = extract_entity_value(e)
                etype = metadata.get('entity_type', 'UNKNOWN')
                vendor = metadata.get('vendor_name', 'N/A')
                product = metadata.get('product_name', 'N/A')
                severity = (metadata.get('threat', [{}])[0].get('severity', 'N/A')
                            if metadata.get('threat') else 'N/A')
                line = f"{now},{val},{etype},{vendor},{product},{severity}\n"
                f.write(line)
        logger.info(f"Appended {len(entities)} events to {CSV_FILE}")
    except Exception as e:
        logger.error(f"Failed to write to CSV tracking file: {e}")


def handle_historical_sync(state):
    """Detects if historical sync is needed and updates state."""
    current_hist = str(Config.HISTORICAL_POLLING_DAYS)
    saved_hist = state.get('last_historical_config', None)
    last_timestamp = state.get('last_timestamp', 0)

    if saved_hist != current_hist:
        msg = f"Config changed from '{saved_hist}' to '{current_hist}'."
        logger.info(msg)
        state['last_timestamp'] = 0 
        state['last_historical_config'] = current_hist
        save_state(state)
        last_timestamp = 0

    if last_timestamp == 0:
        days = parse_days_or_date(Config.HISTORICAL_POLLING_DAYS)
        if days > 0:
            logger.info(f"First run. Backfilling data from {days} days ago.")
            start_dt = datetime.utcnow() - timedelta(days=days)
            last_timestamp = int(start_dt.timestamp())
        else:
            last_timestamp = int(datetime.utcnow().timestamp())
    
    return last_timestamp


def process_misp_batch(misp, secops, last_timestamp, page):
    """Fetches a batch from MISP, converts, and sends to SecOps."""
    attributes = misp.fetch_attributes(
        last_timestamp=last_timestamp, 
        page=page, 
        limit=Config.FORWARDER_BATCH_SIZE
    )
    if not attributes:
        return 0, []

    entities = []
    display_items = []
    skipped_types = {}
    for attr in attributes:
        entity = SecOpsManager.convert_to_entity(attr)
        if entity:
            entities.append(entity)
            display_items.append({
                'type': attr.get('type', 'unknown'),
                'value': attr.get('value', 'N/A'),
                'date': (attr.get('timestamp', 'N/A') if 'date' not in attr 
                         else attr['date']),
                'vendor': entity.get('metadata', {}).get('vendor_name', 
                                                       'Unknown'),
                'product': entity.get('metadata', {}).get('product_name', 
                                                        'MISP')
            })
        else:
            atype = attr.get('type', 'unknown')
            skipped_types[atype] = skipped_types.get(atype, 0) + 1

    if skipped_types:
        msg = f"Skipped {sum(skipped_types.values())}: {skipped_types}"
        logger.warning(msg)

    if entities:
        log_summary_table(display_items)
        secops.send_entities(entities)
        append_to_csv(entities)
    
    return len(attributes), entities


def run_worker_loop(misp, secops, state, args, current_config_mtime):
    """Main processing loop with support for hot-reloading configuration."""
    config_path = args.config if args.config else "config.json"
    
    def check_for_changes():
        if not (config_path and os.path.exists(config_path)):
            return False
        return os.path.getmtime(config_path) != current_config_mtime
        
    last_timestamp = handle_historical_sync(state)
    total_events_sent = 0

    while True:
        if check_for_changes():
            raise ConfigRestartException()
             
        logger.info("Polling MISP for new threat indicators...")
        sync_start_ts = int(datetime.utcnow().timestamp())
        page = 1
        total_processed = 0
        
        while True:
            if check_for_changes():
                raise ConfigRestartException()
            
            count, entities = process_misp_batch(misp, secops, 
                                                 last_timestamp, page)
            if count == 0:
                break
                
            total_events_sent += len(entities)
            total_processed += count
            page += 1
            
            if (Config.TEST_MODE and 
                total_events_sent >= Config.MAX_TEST_EVENTS):
                logger.info(f"Test limit reached ({Config.MAX_TEST_EVENTS}).")
                sys.exit(0)
            
        if total_processed > 0:
            logger.info(f"Processed {total_processed} indicators.")
        else:
            logger.info("No new threat indicators found.")
            
        state['last_timestamp'] = sync_start_ts
        save_state(state)
        last_timestamp = sync_start_ts
        
        logger.info(f"Sync cycle complete. Waiting {Config.FETCH_INTERVAL}s.")
        smart_sleep(Config.FETCH_INTERVAL, check_for_changes)


def main():
    """Main entry point for the forwarder application."""
    display_banner()
    args = parse_args()
    config_path = args.config if args.config else "config.json"
    
    if os.path.exists(config_path):
        Config.reload_from_file(config_path)
    
    if args.fetch_interval: Config.FETCH_INTERVAL = args.fetch_interval
    if args.fetch_page_size: Config.FETCH_PAGE_SIZE = args.fetch_page_size
    if args.forwarder_batch_size: 
        Config.FORWARDER_BATCH_SIZE = args.forwarder_batch_size
    if args.test_mode: Config.TEST_MODE = True
    if args.max_test_events: Config.MAX_TEST_EVENTS = args.max_test_events
    if args.historical_polling_days: 
        Config.HISTORICAL_POLLING_DAYS = args.historical_polling_days
    
    update_log_level()
    
    try:
        Config.validate()
    except ValueError as e:
        logger.critical(f"Configuration Invalid: {e}")
        sys.exit(1)
        
    misp = MispClient()
    secops = SecOpsManager()
    
    if not misp.test_connection():
         logger.error("MISP connection failed. Retrying in cycle.")
         
    state = load_state()
    current_mtime = os.path.getmtime(config_path) if os.path.exists(config_path) else 0
    
    logger.info("MISP to Google SecOps Forwarder starting...")

    while True:
        try:
            run_worker_loop(misp, secops, state, args, current_mtime)
        except ConfigRestartException:
            logger.info("Configuration updated. Restarting loop.")
            if os.path.exists(config_path):
                Config.reload_from_file(config_path)
                current_mtime = os.path.getmtime(config_path)
            update_log_level()
        except KeyboardInterrupt:
            signal_handler(None, None)
        except Exception as e:
            logger.error(f"Unexpected Error: {e}")
            time.sleep(60)


if __name__ == "__main__":
    main()
