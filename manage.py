#!/usr/bin/env python3
"""
Configuration Management CLI Tool
Allows runtime updates to config.json
"""
import argparse
import json
import os
import sys

CONFIG_FILE = "/app/config.json"

VALID_KEYS = {
    "FETCH_INTERVAL": int,
    "FETCH_PAGE_SIZE": int,
    "FORWARDER_BATCH_SIZE": int,
    "IOC_EXPIRATION_DAYS": int,
    "TEST_MODE": bool,
    "MAX_TEST_EVENTS": int,
    "HISTORICAL_POLLING_DAYS": str,
    "LOG_LEVEL": str,
    "BACKFILL_DAYS": str,
    "BACKFILL_UNTIL_DAYS": str
}

def load_config():
    """Load current configuration."""
    if not os.path.exists(CONFIG_FILE):
        print(f"Error: Config file not found at {CONFIG_FILE}")
        sys.exit(1)
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading config: {e}")
        sys.exit(1)

def save_config(config):
    """Save configuration to file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        print("Configuration updated successfully.")
    except Exception as e:
        print(f"Error writing config: {e}")
        sys.exit(1)

def convert_value(key, value):
    """Convert string value to appropriate type."""
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

def cmd_list(args):
    """List all configuration values."""
    config = load_config()
    print("\nCurrent Configuration:")
    print("=" * 50)
    for key, value in sorted(config.items()):
        print(f"{key:30} = {value}")
    print("=" * 50)

def cmd_get(args):
    """Get a specific configuration value."""
    config = load_config()
    key = args.key.upper()
    if key not in config:
        print(f"Error: Key '{key}' not found in configuration")
        sys.exit(1)
    print(f"{key} = {config[key]}")

def cmd_set(args):
    """Set a configuration value."""
    config = load_config()
    key = args.key.upper()
    
    if key not in VALID_KEYS:
        print(f"Error: Invalid configuration key: {key}")
        print(f"Valid keys: {', '.join(VALID_KEYS.keys())}")
        sys.exit(1)
    
    try:
        new_value = convert_value(key, args.value)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    old_value = config.get(key)
    config[key] = new_value
    save_config(config)
    print(f"Updated {key}: {old_value} -> {new_value}")

def main():
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
