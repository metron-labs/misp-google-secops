# Centralized HTTP error handling utilities.
# Provides consistent error handling and logging for HTTP responses
# across all API clients (MISP, SecOps, etc.).

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class HTTPErrorHandler:
    # Centralized HTTP error handler for API responses.
    
    # Common HTTP status code messages
    COMMON_MESSAGES = {
        401: "Authentication failed. Credentials may be invalid or expired.",
        403: "Access forbidden. Insufficient permissions.",
        429: "API rate limit exceeded. Will retry with backoff.",
        500: "Internal server error.",
        502: "Bad gateway.",
        503: "Service unavailable.",
        504: "Gateway timeout.",
    }
    
    def __init__(
        self,
        service_name: str,
        custom_messages: Optional[Dict[int, str]] = None
    ):
        # Initialize HTTP error handler.
        # Args:
        #   service_name: Name of service (e.g., "MISP", "Google SecOps")
        #   custom_messages: Optional dict of status code to error messages
        self.service_name = service_name
        self.messages = {**self.COMMON_MESSAGES}
        if custom_messages:
            self.messages.update(custom_messages)
    
    def handle_response(self, response) -> None:
        # Handle HTTP response and raise appropriate errors.
        # Args:
        #   response: requests.Response object
        # Raises:
        #   requests.HTTPError: If response status is not successful
        status_code = response.status_code
        
        # Success - no action needed
        if status_code == 200:
            return
        
        # Get appropriate message
        if status_code in self.messages:
            message = self.messages[status_code]
        elif status_code >= 500:
            message = (
                f"Server error (HTTP {status_code}). "
                f"{self.service_name} may be experiencing technical "
                "difficulties."
            )
        else:
            message = (
                f"Unexpected response (HTTP {status_code}) from "
                f"{self.service_name}."
            )
        
        # Log with appropriate level
        log_level = logging.WARNING if status_code == 429 else logging.ERROR
        logger.log(log_level, f"{self.service_name}: {message}")
        
        # Raise for status
        response.raise_for_status()


# Pre-configured handlers for common services
MISP_ERROR_HANDLER = HTTPErrorHandler(
    service_name="MISP",
    custom_messages={
        401: (
            "Authentication failed with MISP. Your API key may be "
            "invalid or expired. Please verify MISP_API_KEY in your "
            "environment configuration."
        ),
        403: (
            "Access forbidden by MISP server. Your API key may not "
            "have sufficient permissions to access threat intelligence "
            "data. Please check your MISP user permissions."
        ),
        429: (
            "MISP API rate limit exceeded. The application will "
            "automatically retry after a brief delay."
        ),
    }
)

SECOPS_ERROR_HANDLER = HTTPErrorHandler(
    service_name="Google SecOps",
    custom_messages={
        401: (
            "Authentication failed with Google SecOps. Your "
            "service account credentials may be invalid or "
            "expired. Please verify your credentials.json file "
            "and ensure the service account has not been revoked."
        ),
        403: (
            "Access forbidden by Google SecOps. Your service "
            "account may not have the required 'Chronicle API' "
            "permissions. Please verify the service account has "
            "the correct IAM roles in Google Cloud Console."
        ),
        429: (
            "Google SecOps API rate limit exceeded. The "
            "application will automatically retry after a brief "
            "delay. Consider reducing FORWARDER_BATCH_SIZE if "
            "this persists."
        ),
    }
)
