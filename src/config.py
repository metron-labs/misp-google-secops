import os
from dotenv import load_dotenv
import json
import logging

logger = logging.getLogger(__name__)

# Load environment variables from .env file if present
load_dotenv()

class Config:
    # Application configuration loaded from environment variables.
    
    # MISP Settings
    MISP_URL = os.getenv('MISP_URL')
    MISP_API_KEY = os.getenv('MISP_API_KEY')
    MISP_VERIFY_SSL = (
        os.getenv('MISP_VERIFY_SSL', 'true').lower() == 'true'
    )
    
    # Google SecOps Settings
    GOOGLE_SA_CREDENTIALS = os.getenv('GOOGLE_SA_CREDENTIALS')
    GOOGLE_PROJECT_ID = os.getenv('GOOGLE_PROJECT_ID')
    GOOGLE_CUSTOMER_ID = os.getenv('GOOGLE_CUSTOMER_ID')
    SECOPS_ENTITY_API_URL = os.getenv('SECOPS_ENTITY_API_URL')
    
    # Polling & Processing Settings
    FETCH_INTERVAL = 3600
    FETCH_PAGE_SIZE = 2
    FORWARDER_BATCH_SIZE = 2
    
    # IoC Settings
    IOC_EXPIRATION_DAYS = 30

    # Test Mode Settings
    TEST_MODE = False
    MAX_TEST_EVENTS = 3

    # Historical Polling Settings
    HISTORICAL_POLLING_DATE = 0

    # Log Level Settings
    LOG_LEVEL = 'INFO'

    @staticmethod
    def reload_from_file(filepath):
        # Reload configuration from JSON file.
        try:
            with open(filepath, 'r') as f:
                config_dict = json.load(f)
            Config.load_from_dict(config_dict)
            return True
        except Exception as e:
            logger.error(f"Failed to reload config file: {e}")
            logger.exception(e)
            return False

    @staticmethod
    def _convert_value(key, value, expected_type):
        # Convert value to expected type.
        if expected_type == bool and isinstance(value, str):
            return value.lower() == 'true'
        elif expected_type == int:
            return int(value)
        elif expected_type:
            return expected_type(value)
        return value

    @staticmethod
    def load_from_dict(config_dict):
        # Update configuration from dictionary.
        if not config_dict:
            return

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
            if not hasattr(Config, key) or value is None:
                continue
                
            expected_type = key_types.get(key)
            try:
                if isinstance(value, expected_type) or not expected_type:
                    setattr(Config, key, value)
                elif expected_type is not str:
                    converted = Config._convert_value(
                        key, value, expected_type
                    )
                    setattr(Config, key, converted)
                else:
                    setattr(Config, key, value)
            except (ValueError, TypeError):
                pass

    MAX_ALLOWED_BATCH_SIZE = 500

    @staticmethod
    def validate():
        # Validate critical configuration.
        if Config.FORWARDER_BATCH_SIZE > Config.MAX_ALLOWED_BATCH_SIZE:
            msg = (
                f"FORWARDER_BATCH_SIZE "
                f"({Config.FORWARDER_BATCH_SIZE}) exceeds safety "
                f"limit. Capping to {Config.MAX_ALLOWED_BATCH_SIZE} "
                f"to stay within API payload limits (4MB)."
            )
            logging.getLogger("misp-forwarder").warning(msg)
            Config.FORWARDER_BATCH_SIZE = Config.MAX_ALLOWED_BATCH_SIZE

        missing = []
        if not Config.MISP_URL:
            missing.append('MISP_URL')
        if not Config.MISP_API_KEY:
            missing.append('MISP_API_KEY')
        if not Config.GOOGLE_SA_CREDENTIALS:
            missing.append('GOOGLE_SA_CREDENTIALS')
        if not Config.GOOGLE_CUSTOMER_ID:
            missing.append('GOOGLE_CUSTOMER_ID')
        
        if missing:
            msg = f"Missing required environment variables: "
            msg += f"{', '.join(missing)}"
            raise ValueError(msg)
