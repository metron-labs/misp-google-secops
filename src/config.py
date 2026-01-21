import os
from dotenv import load_dotenv
import json
import logging

logger = logging.getLogger(__name__)

# Load environment variables from .env file if present
load_dotenv()

class Config:
    """Application configuration loaded from environment variables."""
    
    # MISP Settings
    MISP_URL = os.getenv('MISP_URL')
    MISP_API_KEY = os.getenv('MISP_API_KEY')
    MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'true').lower() == 'true'
    
    # Google SecOps Settings
    GOOGLE_SA_CREDENTIALS = os.getenv('GOOGLE_SA_CREDENTIALS')
    GOOGLE_PROJECT_ID = os.getenv('GOOGLE_PROJECT_ID')
    GOOGLE_CUSTOMER_ID = os.getenv('GOOGLE_CUSTOMER_ID')
    SECOPS_ENTITY_API_URL = os.getenv('SECOPS_ENTITY_API_URL')
    
    # Polling & Processing Settings
    FETCH_INTERVAL = 3600  # Default 1 hour in seconds
    FETCH_PAGE_SIZE = 2
    FORWARDER_BATCH_SIZE = 2
    
    # IoC Settings
    IOC_EXPIRATION_DAYS = 30

    # Test Mode Settings
    TEST_MODE = False
    MAX_TEST_EVENTS = 3

    # Historical Polling Settings
    HISTORICAL_POLLING_DAYS = 0
    LOG_LEVEL = 'INFO'
    BACKFILL_DAYS = 0
    BACKFILL_UNTIL_DAYS = 0

    @staticmethod
    def reload_from_file(filepath):
        """Reload configuration from JSON file."""
        try:
            with open(filepath, 'r') as f:
                config_dict = json.load(f)
            Config.load_from_dict(config_dict)
            Config.load_from_dict(config_dict)
            return True
        except Exception as e:
            logger.error(f"DEBUG: Failed to reload config file: {e}")
            logger.exception(e)
            return False

    @staticmethod
    def load_from_dict(config_dict):
        """Update configuration from a dictionary (e.g., from JSON or CLI args)."""
        if not config_dict:
            return

        # Mapping of config keys to expected types
        key_types = {
            'MISP_URL': str,
            'MISP_API_KEY': str,
            'MISP_VERIFY_SSL': bool,
            'GOOGLE_SA_CREDENTIALS': str,
            'GOOGLE_PROJECT_ID': str,
            'GOOGLE_CUSTOMER_ID': str,
            'FETCH_INTERVAL': int,
            'FETCH_PAGE_SIZE': int,
            'FORWARDER_BATCH_SIZE': int,
            'IOC_EXPIRATION_DAYS': int,
            'TEST_MODE': bool,
            'MAX_TEST_EVENTS': int
        }

        for key, value in config_dict.items():
            if hasattr(Config, key) and value is not None:
                # If value came from JSON, types are likely already correct (e.g. int, bool)
                # But if we want to be safe or support CLI string overrides:
                expected_type = key_types.get(key)
                try:
                    # Handle boolean conversion from strings if necessary
                    if expected_type == bool and isinstance(value, str):
                        setattr(Config, key, value.lower() == 'true')
                    elif expected_type and not isinstance(value, expected_type) and expected_type is not str:
                            # Attempt cast if types don't match (e.g. "100" -> 100)
                            if expected_type == int:
                                # Special case for ints that might optionally be N/A or empty?
                                # For this specific app, strict ints are fine.
                                setattr(Config, key, expected_type(value))
                            else:
                                setattr(Config, key, expected_type(value))
                    else:
                        setattr(Config, key, value)
                except ValueError:
                    pass

    @staticmethod
    def validate():
        """Validate critical configuration."""
        missing = []
        if not Config.MISP_URL: missing.append('MISP_URL')
        if not Config.MISP_API_KEY: missing.append('MISP_API_KEY')
        if not Config.GOOGLE_SA_CREDENTIALS: missing.append('GOOGLE_SA_CREDENTIALS')
        if not Config.GOOGLE_CUSTOMER_ID: missing.append('GOOGLE_CUSTOMER_ID')
        
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")
