import os
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

class Config:
    """Application configuration loaded from environment variables."""
    
    # MISP Settings
    MISP_URL = os.getenv('MISP_URL')
    MISP_API_KEY = os.getenv('MISP_API_KEY')
    MISP_VERIFY_SSL = os.getenv('MISP_VERIFY_SSL', 'true').lower() == 'true'
    
    # Google SecOps Settings
    GOOGLE_SA_CREDENTIALS = os.getenv('GOOGLE_SA_CREDENTIALS')  # Path to JSON key file
    GOOGLE_PROJECT_ID = os.getenv('GOOGLE_PROJECT_ID')
    GOOGLE_CUSTOMER_ID = os.getenv('GOOGLE_CUSTOMER_ID')
    
    # Polling & Processing Settings
    FETCH_INTERVAL = int(os.getenv('FETCH_INTERVAL', '3600'))  # Default 1 hour in seconds
    FETCH_PAGE_SIZE = int(os.getenv('FETCH_PAGE_SIZE', '100'))
    FORWARDER_BATCH_SIZE = int(os.getenv('FORWARDER_BATCH_SIZE', '100'))
    
    # IoC Settings
    IOC_EXPIRATION_DAYS = int(os.getenv('IOC_EXPIRATION_DAYS', '30'))

    # Test Mode Settings
    TEST_MODE = os.getenv('TEST_MODE', 'false').lower() == 'true'
    MAX_TEST_EVENTS = int(os.getenv('MAX_TEST_EVENTS', '3'))

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
