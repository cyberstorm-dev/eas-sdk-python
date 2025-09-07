# Import the main EAS class and commonly used utilities
# Import configuration helpers and common functions
from . import config
from .config import (
    get_mainnet_chains,
    get_network_config,
    get_testnet_chains,
    list_supported_chains,
)
from .core import EAS

# Import exceptions for better error handling
from .exceptions import (
    EASError,
    EASSecurityError,
    EASTransactionError,
    EASValidationError,
)

# Import transaction result type
from .transaction import TransactionResult

# Version info
__version__ = "0.1.0"

# Make commonly used items available at package level
__all__ = [
    # Main class
    "EAS",
    # Configuration
    "config",
    "get_network_config",
    "list_supported_chains",
    "get_mainnet_chains",
    "get_testnet_chains",
    # Exceptions
    "EASError",
    "EASValidationError",
    "EASTransactionError",
    "EASSecurityError",
    # Types
    "TransactionResult",
    # Version
    "__version__",
]
