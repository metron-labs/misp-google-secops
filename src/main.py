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
    # Update logging level from config.
    level_name = Config.LOG_LEVEL.upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.getLogger().setLevel(level)
    logger.setLevel(level)

STATE_FILE = "misp_data/state.json"
            
def display_banner():
    # Displays the startup ASCII banner using custom.png.
    try:
        banner_path = "assets/custom.png"
        if os.path.exists(banner_path):
            subprocess.run(
                ["chafa", banner_path, "--size=80x40", "--colors",
                 "none", "--symbols", "braille"],
                check=False
            )
        else:
            msg = (
                "The application tried to display a startup "
                "banner, but could not find the image at "
                f"{banner_path}."
            )
            logger.warning(msg)
    except Exception as e:
        msg = (
            "An attempt to display the startup banner was made, "
            f"but it didn't quite work: {e}"
        )
        logger.debug(msg)

def load_state():
    # Load state from file.
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            msg = (
                "The application encountered an issue while trying "
                f"to read its previous progress from {STATE_FILE}. "
                f"It seems the file might be corrupted or "
                f"inaccessible: {e}"
            )
            logger.error(msg)
    return {}

def save_state(state):
    # Save state to file.
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f)
        
        ts = state.get('last_timestamp')
        if ts:
            dt_str = datetime.fromtimestamp(ts).strftime(
                '%Y-%m-%d %H:%M:%S'
            )
    except Exception as e:
        msg = (
            "The application tried to save its progress to "
            f"{STATE_FILE}, but ran into a problem. This might "
            f"mean it will re-process some data when it restarts: {e}"
        )
        logger.error(msg)

def signal_handler(sig, frame):
    # Handle shutdown signals gracefully.
    msg = (
        "A shutdown signal was received. The application is now "
        "gracefully closing its connections and stopping its work."
    )
    logger.info(msg)
    sys.exit(0)

def extract_entity_value(entity_data):
    # Extract primary identifier from nested entity structure.
    inner = entity_data.get('entity', entity_data)
    
    if 'hostname' in inner:
        return inner['hostname']
    if 'ip' in inner:
        return inner['ip']
    if 'url' in inner:
        return inner['url']
    if 'file' in inner:
        f_data = inner['file']
        return next(iter(f_data.values())) if f_data else "N/A"
    return "N/A"

def parse_days_or_date(val):
    # Parse value as days (int) or date (YYYY-MM-DD).
    if not val:
        return 0
    val = str(val).strip()
    try:
        target_date = datetime.strptime(val, '%Y-%m-%d')
        
        if target_date > datetime.utcnow():
            msg = (
                f"Invalid HISTORICAL_POLLING_DATE: '{val}' is in "
                "the future. Historical polling can only look back "
                "at past data. Please provide a date that is today "
                "or earlier. Disabling historical polling (using 0 "
                "days)."
            )
            logger.error(msg)
            return 0
            
        delta = (datetime.utcnow() - target_date).days
        return max(0, delta)
    except ValueError:
        try:
            days = int(val)
            if days < 0:
                msg = (
                    f"Invalid HISTORICAL_POLLING_DATE: Negative days "
                    f"({days}) are not allowed. Please use 0 to "
                    "disable historical polling or a positive number. "
                    "Disabling historical polling (using 0 days)."
                )
                logger.error(msg)
                return 0
            return days
        except ValueError:
            msg = (
                f"Invalid value: {val}. Must be integer days or "
                "YYYY-MM-DD."
            )
            logger.error(msg)
            return 0

def log_summary_table(items):
    # Logs a structured ASCII table of threat entities.
    if not items:
        return
    headers = ["Type", "Value", "Collected Date", "Vendor", "Product"]
    col_widths = [15, 30, 15, 12, 10]
    header_line = " | ".join(
        h.ljust(w) for h, w in zip(headers, col_widths)
    )
    logger.info("\n" + "="*len(header_line))
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
        logger.info(" | ".join(
            val.ljust(width) for val, width in zip(row, col_widths)
        ))
    logger.info("="*len(header_line) + "\n")

def parse_args():
    # Parse command line arguments.
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
        help='Days to look back on first run (0 = disable) or date'
    )

    return parser.parse_args()


class ConfigRestartException(Exception):
    # Raised when configuration changes require restart.
    pass

def smart_sleep(seconds, check_config_func):
    # Sleeps for seconds, checking config every second.
    for _ in range(int(seconds)):
        if check_config_func():
            raise ConfigRestartException()
        time.sleep(1)
    
    remaining = seconds - int(seconds)
    if remaining > 0:
        time.sleep(remaining)
        if check_config_func():
            raise ConfigRestartException()



def run_worker_loop(misp, secops, state, args, current_config_mtime):
    # The main processing loop.
    
    config_path = args.config if args.config else "config.json"
    
    def check_for_changes():
        # Check if config file has been modified.
        if not (config_path and os.path.exists(config_path)):
            return False
        
        mtime = os.path.getmtime(config_path)
        if mtime != current_config_mtime:
            return True
        return False
        
    last_timestamp = state.get('last_timestamp', 0)
    
    current_hist_setting = str(Config.HISTORICAL_POLLING_DATE)
    saved_hist_setting = state.get('last_historical_config', None)

    logger.debug(f"Checking historical configuration change. Current: '{current_hist_setting}', Saved: '{saved_hist_setting}'")
    
    if saved_hist_setting != current_hist_setting:
        msg = (
            f"Historical Polling config changed from "
            f"'{saved_hist_setting}' to '{current_hist_setting}'."
        )
        logger.info(msg)
        
        hist_days = parse_days_or_date(Config.HISTORICAL_POLLING_DATE)
        if hist_days > 0:
            start_dt = datetime.utcnow() - timedelta(days=hist_days)
            new_ts = int(start_dt.timestamp())
            msg = (
                f"Resetting sync start time to {start_dt} (UTC) "
                "based on new config."
            )
            logger.info(msg)
            last_timestamp = new_ts
            state['last_timestamp'] = last_timestamp

        state['last_historical_config'] = current_hist_setting
        save_state(state)
    
    elif last_timestamp == 0:
        hist_days = parse_days_or_date(Config.HISTORICAL_POLLING_DATE)
        if hist_days > 0:
             msg = (
                 f"First run detected. Backfilling from "
                 f"{hist_days} days ago."
             )
             logger.info(msg)
             start_dt = datetime.utcnow() - timedelta(days=hist_days)
             last_timestamp = int(start_dt.timestamp())
             logger.debug(f"Calculated start_dt: {start_dt}, last_timestamp: {last_timestamp}")
        else:
             last_timestamp = int(datetime.utcnow().timestamp())
             
    total_events_sent = 0

    while True:
        if check_for_changes():
             raise ConfigRestartException()
             
        logger.info("Checking MISP for new indicators...")
        sync_start_ts = int(datetime.utcnow().timestamp())
        page = 1
        total_processed = 0
        
        while True:
            if check_for_changes():
                 raise ConfigRestartException()
                 
            attributes = misp.fetch_attributes(
                last_timestamp=last_timestamp, 
                page=page, 
                limit=Config.FORWARDER_BATCH_SIZE
            )
            
            if not attributes:
                 break
            
            msg = (
                f"Retrieved {len(attributes)} attributes "
                f"(Page {page})."
            )
            logger.info(msg)
            
            pairs = []
            display_items = []
            skipped_types = {}
            
            for attr in attributes:
                entity = SecOpsManager.convert_to_entity(attr)
                if entity:
                    pairs.append((attr, entity))
                    date_val = (
                        attr.get('timestamp', 'N/A')
                        if 'date' not in attr
                        else attr['date']
                    )
                    vendor_val = entity.get('metadata', {}).get(
                        'vendor_name', 'Unknown'
                    )
                    product_val = entity.get('metadata', {}).get(
                        'product_name', 'MISP'
                    )
                    display_items.append({
                        'type': attr.get('type', 'unknown'),
                        'value': attr.get('value', 'N/A'),
                        'date': date_val,
                        'vendor': vendor_val,
                        'product': product_val
                    })
                else:
                    atype = attr.get('type', 'unknown')
                    skipped_types[atype] = skipped_types.get(atype, 0) + 1
            
            if skipped_types:
                msg = (
                    f"Skipped {sum(skipped_types.values())} "
                    f"attributes due to unsupported types: "
                    f"{skipped_types}"
                )
                logger.warning(msg)
            
            if not pairs and attributes:
                msg = "All fetched attributes were skipped. No data."
                logger.warning(msg)
            
            if pairs:
                log_summary_table(display_items)
                for i in range(0, len(pairs), Config.FORWARDER_BATCH_SIZE):
                    batch_pairs = pairs[i : i + Config.FORWARDER_BATCH_SIZE]
                    batch_entities = [p[1] for p in batch_pairs]
                    
                    secops.send_entities(batch_entities)
                    
                    total_events_sent += len(batch_entities)
                    
                    if (Config.TEST_MODE and
                        total_events_sent >= Config.MAX_TEST_EVENTS):
                        msg = (
                            f"Test limit ({Config.MAX_TEST_EVENTS}) "
                            "reached. Exiting."
                        )
                        logger.info(msg)
                        sys.exit(0)
                        
            total_processed += len(attributes)
            page += 1
            
        if total_processed > 0:
            logger.info("Threat data delivered to SecOps.")
        else:
            logger.info("No new threat indicators found.")
            
        state['last_timestamp'] = sync_start_ts
        save_state(state)
        last_timestamp = sync_start_ts
        
        msg = f"Sync complete. Sleeping {Config.FETCH_INTERVAL}s."
        logger.info(msg)
        smart_sleep(Config.FETCH_INTERVAL, check_for_changes)


def main():
    # Main entry point.
    display_banner()
    args = parse_args()
    
    config_path = args.config if args.config else "config.json"
    
    if os.path.exists(config_path):
        msg = (
            "The application is loading your custom configuration "
            f"settings from {config_path}."
        )
        logger.info(msg)
        Config.reload_from_file(config_path)
    
    if args.fetch_interval:
        Config.FETCH_INTERVAL = args.fetch_interval
    if args.fetch_page_size:
        Config.FETCH_PAGE_SIZE = args.fetch_page_size
    if args.forwarder_batch_size:
        Config.FORWARDER_BATCH_SIZE = args.forwarder_batch_size
    if args.test_mode:
        Config.TEST_MODE = True
    if args.max_test_events:
        Config.MAX_TEST_EVENTS = args.max_test_events
    if args.historical_polling_days:
        Config.HISTORICAL_POLLING_DATE = args.historical_polling_days
    
    update_log_level()
    
    try:
        Config.validate()
    except ValueError as e:
        logger.critical(f"Configuration Invalid: {e}")
        sys.exit(1)
        
    logger.info("Initializing MISP and SecOps connections...")
    misp = MispClient()
    secops = SecOpsManager()
    
    if not misp.test_connection():
         msg = "MISP connection failed. Application will retry."
         logger.error(msg)
         
    state = load_state()
    
    current_mtime = 0
    if os.path.exists(config_path):
        current_mtime = os.path.getmtime(config_path)
        
    msg = (
        "The MISP to Google SecOps Forwarder is now Starting "
    )
    logger.info(msg)

    while True:
        try:
            run_worker_loop(misp, secops, state, args, current_mtime)
            
        except ConfigRestartException:
            logger.info("Configuration updated")
            
            if os.path.exists(config_path):
                Config.reload_from_file(config_path)
                current_mtime = os.path.getmtime(config_path)
            
            update_log_level()
            
            try:
                Config.validate()
            except ValueError as e:
                msg = (
                    f"Reloaded configuration is invalid: {e}. "
                    "Attempting to proceed anyway."
                )
                logger.error(msg)

            logger.info("Restarting processing loop with new config")
            
        except KeyboardInterrupt:
            signal_handler(None, None)
        except Exception as e:
            logger.error(f"Unexpected Error: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
