"""
Configuration validation utility.
Provides shared validation logic for manage.py and the main application.
"""
import logging
from datetime import datetime

logger = logging.getLogger("misp-forwarder-validation")

MAX_ALLOWED_BATCH_SIZE = 500

def validate_historical_date(val):
    """
    Validate HISTORICAL_POLLING_DATE.
    Returns delta in days if valid, raises ValueError otherwise.
    """
    if not val:
        return 0
    
    val_str = str(val).strip()
    
    # Check for disabled values
    if val_str in ["0", "0000-00-00"]:
        return 0
    
    try:
        target_date = datetime.strptime(val_str, '%Y-%m-%d')
        if target_date > datetime.utcnow():
            raise ValueError(
                f"Invalid HISTORICAL_POLLING_DATE: '{val_str}' is in the future. "
                "Historical polling can only look back at past data."
            )
        delta = (datetime.utcnow() - target_date).days
        return max(0, delta)
    except ValueError as e:
        if "is in the future" in str(e):
            raise
        raise ValueError(
            f"Invalid HISTORICAL_POLLING_DATE: '{val_str}'. "
            "Must be in YYYY-MM-DD format or '0000-00-00' to disable."
        )

def validate_batch_size(val):
    """
    Validate FORWARDER_BATCH_SIZE.
    Returns valid batch size or raises ValueError.
    """
    try:
        batch_size = int(val)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid FORWARDER_BATCH_SIZE: {val}. Must be an integer.")

    if batch_size > MAX_ALLOWED_BATCH_SIZE:
        raise ValueError(
            f"FORWARDER_BATCH_SIZE ({batch_size}) exceeds safety limit of {MAX_ALLOWED_BATCH_SIZE}."
        )
    if batch_size < 1:
        raise ValueError(f"FORWARDER_BATCH_SIZE ({batch_size}) must be at least 1.")
    
    return batch_size

def validate_fetch_interval(val):
    """Validate FETCH_INTERVAL."""
    try:
        interval = int(val)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid FETCH_INTERVAL: {val}. Must be an integer.")
    
    if interval < 1:
        raise ValueError(f"FETCH_INTERVAL ({interval}) must be at least 1 second.")
    return interval

def validate_expiration_days(val):
    """Validate IOC_EXPIRATION_DAYS."""
    try:
        days = int(val)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid IOC_EXPIRATION_DAYS: {val}. Must be an integer.")
    
    if days < 1:
        raise ValueError(f"IOC_EXPIRATION_DAYS ({days}) must be at least 1 day.")
    return days

def validate_log_level(val):
    """Validate LOG_LEVEL."""
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if str(val).upper() not in valid_levels:
        raise ValueError(
            f"Invalid LOG_LEVEL: '{val}'. Must be one of: {', '.join(valid_levels)}"
        )
    return str(val).upper()

def validate_config_value(key, value):
    """
    Generic validation wrapper for a configuration key/value pair.
    """
    if key == "HISTORICAL_POLLING_DATE":
        validate_historical_date(value)
    elif key == "FORWARDER_BATCH_SIZE":
        validate_batch_size(value)
    elif key == "FETCH_INTERVAL":
        validate_fetch_interval(value)
    elif key == "IOC_EXPIRATION_DAYS":
        validate_expiration_days(value)
    elif key == "LOG_LEVEL":
        validate_log_level(value)
    return value
