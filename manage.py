#!/usr/bin/env python3
# Configuration Management CLI Tool
# Allows runtime updates to config.json
import argparse
import json
import logging
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("config-manager")

CONFIG_FILE = "config.json"

VALID_KEYS = {
    "FETCH_INTERVAL": int,
    "FETCH_PAGE_SIZE": int,
    "FORWARDER_BATCH_SIZE": int,
    "IOC_EXPIRATION_DAYS": int,
    "TEST_MODE": bool,
    "MAX_TEST_EVENTS": int,
    "HISTORICAL_POLLING_DATE": str,
    "LOG_LEVEL": str
}

def load_config():
    # Load current configuration.
    if not os.path.exists(CONFIG_FILE):
        logger.error(f"Error: Config file not found at {CONFIG_FILE}")
        sys.exit(1)
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error reading config: {e}")
        sys.exit(1)

def save_config(config):
    # Save configuration to file.
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        logger.info("Configuration updated successfully.")
    except Exception as e:
        logger.error(f"Error writing config: {e}")
        sys.exit(1)

def convert_value(key, value):
    # Convert string value to appropriate type.
    expected_type = VALID_KEYS.get(key)
    if expected_type is None:
        raise ValueError(f"Unknown configuration key: {key}")
    
    if expected_type == bool:
        if value.lower() in ['true', '1', 'yes']:
            return True
        elif value.lower() in ['false', '0', 'no']:
            return False
        else:
            raise ValueError(
                f"Invalid boolean value: {value}. "
                f"Use true/false, 1/0, or yes/no"
            )
    elif expected_type == int:
        try:
            return int(value)
        except ValueError:
            raise ValueError(
                f"Invalid integer value for {key}: {value}"
            )
    return value

def validate_value(key, value):
    # Validate configuration value before saving.
    from datetime import datetime
    
    if key == "HISTORICAL_POLLING_DATE":
        val_str = str(value).strip()
        
        # Allow disabled values
        if val_str in ["0", "0000-00-00"]:
            return value
        
        try:
            target_date = datetime.strptime(val_str, '%Y-%m-%d')
            if target_date > datetime.utcnow():
                raise ValueError(
                    f"Invalid HISTORICAL_POLLING_DATE: '{val_str}' is in "
                    "the future. Historical polling can only look back at "
                    "past data. Please provide a date that is today or earlier."
                )
        except ValueError as e:
            if "Invalid HISTORICAL_POLLING_DATE" in str(e):
                raise
            raise ValueError(
                f"Invalid HISTORICAL_POLLING_DATE: '{val_str}'. "
                "Must be in YYYY-MM-DD format or '0000-00-00' to disable."
            )
    
    elif key == "FORWARDER_BATCH_SIZE":
        MAX_BATCH_SIZE = 500
        if value > MAX_BATCH_SIZE:
            raise ValueError(
                f"Invalid FORWARDER_BATCH_SIZE: {value} exceeds maximum "
                f"allowed limit of {MAX_BATCH_SIZE}. This limit ensures "
                "compliance with Google SecOps API payload restrictions (4MB)."
            )
        if value < 1:
            raise ValueError(
                f"Invalid FORWARDER_BATCH_SIZE: {value}. "
                "Batch size must be at least 1."
            )
    
    elif key == "FETCH_INTERVAL":
        if value < 1:
            raise ValueError(
                f"Invalid FETCH_INTERVAL: {value}. "
                "Interval must be at least 1 second."
            )
    
    elif key == "IOC_EXPIRATION_DAYS":
        if value < 1:
            raise ValueError(
                f"Invalid IOC_EXPIRATION_DAYS: {value}. "
                "Expiration must be at least 1 day."
            )
    
    elif key == "LOG_LEVEL":
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if value.upper() not in valid_levels:
            raise ValueError(
                f"Invalid LOG_LEVEL: '{value}'. "
                f"Must be one of: {', '.join(valid_levels)}"
            )
    
    return value

def cmd_list(args):
    # List all configuration values.
    config = load_config()
    logger.info("\nCurrent Configuration:")
    logger.info("=" * 50)
    for key, value in sorted(config.items()):
        logger.info(f"{key:30} = {value}")
    logger.info("=" * 50)

def cmd_get(args):
    # Get a specific configuration value.
    config = load_config()
    key = args.key.upper()
    if key not in config:
        logger.error(f"Error: Key '{key}' not found in configuration")
        sys.exit(1)
    logger.info(f"{key} = {config[key]}")

def cmd_set(args):
    # Set a configuration value.
    config = load_config()
    key = args.key.upper()
    
    if key not in VALID_KEYS:
        logger.error(f"Error: Invalid configuration key: {key}")
        logger.info(f"Valid keys: {', '.join(VALID_KEYS.keys())}")
        sys.exit(1)
    
    try:
        new_value = convert_value(key, args.value)
        validate_value(key, new_value)
    except ValueError as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    
    old_value = config.get(key)
    config[key] = new_value
    save_config(config)
    logger.info(f"Updated {key}: {old_value} -> {new_value}")

def main():
    # Main entry point.
    parser = argparse.ArgumentParser(
        description='Manage MISP Forwarder configuration at runtime'
    )
    subparsers = parser.add_subparsers(
        dest='command', help='Available commands'
    )
    
    subparsers.add_parser('list', help='List all configuration values')
    
    get_parser = subparsers.add_parser(
        'get', help='Get a configuration value'
    )
    get_parser.add_argument('key', help='Configuration key')
    
    set_parser = subparsers.add_parser(
        'set', help='Set a configuration value'
    )
    set_parser.add_argument('key', help='Configuration key')
    set_parser.add_argument('value', help='New value')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'list':
        cmd_list(args)
    elif args.command == 'get':
        cmd_get(args)
    elif args.command == 'set':
        cmd_set(args)

if __name__ == '__main__':
    main()
