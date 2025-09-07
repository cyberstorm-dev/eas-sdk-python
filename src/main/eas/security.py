"""
Security utilities for EAS SDK - Comprehensive input validation and sanitization

This module provides secure validation functions to protect against:
- Environment variable injection attacks
- Weak private key validation
- RPC URL manipulation and SSRF attacks
- Contract address substitution attacks
- Information disclosure through logging
- Chain ID confusion attacks

All functions implement defense-in-depth security patterns.
"""

import hashlib
import logging
import os
import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse

# Import strong types from our types module
from .types import Address, ChainId, PrivateKey, RpcUrl, SchemaUID

# Import crypto libraries with error handling
try:
    from eth_account import Account
    from web3 import Web3
except ImportError as e:
    raise ImportError(f"Required cryptographic dependencies not found: {e}")


class SecurityError(Exception):
    """Security validation error - raised when input fails security checks"""

    def __init__(
        self,
        message: str,
        field_name: Optional[str] = None,
        field_value: Optional[str] = None,
    ):
        self.field_name = field_name
        self.field_value = field_value
        super().__init__(message)


class SecureEnvironmentValidator:
    """Secure validation for environment variables and user inputs"""

    # Strict validation patterns for all input types
    VALIDATION_PATTERNS = {
        "chain_name": r"^[a-z0-9\-]{1,50}$",  # Alphanumeric and hyphens only, max 50 chars
        "private_key": r"^0x[a-fA-F0-9]{64}$",  # Exactly 64 hex chars with 0x prefix
        "address": r"^0x[a-fA-F0-9]{40}$",  # Exactly 40 hex chars with 0x prefix
        "url": r"^https://[a-zA-Z0-9\.\-/_\:]+$",  # HTTPS only with safe chars
        "chain_id": r"^[1-9][0-9]{0,10}$",  # Positive integer, max 11 digits
        "hex_string": r"^0x[a-fA-F0-9]*$",  # Hex string with 0x prefix
        "schema_uid": r"^0x[a-fA-F0-9]{64}$",  # 32-byte hex string for schema UIDs
    }

    # Trusted RPC provider domains - only allow known, reputable providers
    TRUSTED_RPC_DOMAINS = {
        # Major infrastructure providers
        "infura.io",
        "alchemy.com",
        "quicknode.com",
        "ankr.com",
        "nodereal.io",
        "moralis.io",
        "chainstack.com",
        "getblock.io",
        "blastapi.io",
        "pokt.network",
        "drpc.org",
        # Official chain providers
        "base.org",
        "arbitrum.io",
        "optimism.io",
        "polygon-rpc.com",
        "mainnet.base.org",
        "sepolia.base.org",
        "goerli.base.org",
        "arb1.arbitrum.io",
        "sepolia-rollup.arbitrum.io",
        "goerli-rollup.arbitrum.io",
        "mainnet.optimism.io",
        "sepolia.optimism.io",
        "goerli.optimism.io",
        "polygon.llamarpc.com",
        "rpc-mumbai.maticvigil.com",
        "matic-mainnet.chainstacklabs.com",
        # Additional trusted providers (with strict subdomain validation)
        "rpc.ankr.com",
        "gateway.tenderly.co",
        "eth.llamarpc.com",
        "ethereum.publicnode.com",
        "nodes.mewapi.io",
        "cloudflare-eth.com",
        "eth-mainnet.public.blastapi.io",
        "api.mycryptoapi.com",
    }

    # Suspicious URL patterns that should be blocked
    SUSPICIOUS_URL_PATTERNS = [
        r"localhost",
        r"127\.0\.0\.1",
        r"0\.0\.0\.0",
        r"10\.",
        r"192\.168\.",
        r"172\.(1[6-9]|2[0-9]|3[01])\.",
        r"internal",
        r"admin",
        r"test",
        r"debug",
        r"dev\.",
        r"staging\.",
        r"local\.",
        r"temp\.",
        r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",  # Direct IP addresses
        r"\.local$",
        r"\.internal$",
        r"\.corp$",
        r"\.lan$",
    ]

    # Known weak private keys to reject
    WEAK_PRIVATE_KEY_PATTERNS = [
        b"\x00" * 32,  # All zeros
        b"\xff" * 32,  # All ones
        b"\x01" * 32,  # All ones (another pattern)
        # Add more known weak patterns as needed
    ]

    # Maximum allowed input lengths to prevent buffer overflow attacks
    MAX_INPUT_LENGTHS = {
        "chain_name": 50,
        "private_key": 66,  # 0x + 64 hex chars
        "address": 42,  # 0x + 40 hex chars
        "url": 500,  # Reasonable URL length
        "general": 1000,  # General purpose limit
        "env_var_name": 100,  # Environment variable names
        "env_var_value": 2000,  # Environment variable values
    }

    # Additional dangerous patterns to detect in environment variables
    DANGEROUS_ENV_PATTERNS = [
        r"\$\{[^}]*\}",  # Variable expansion ${VAR}
        r"\$\([^)]*\)",  # Command substitution $(cmd)
        r"`[^`]*`",  # Backtick command substitution
        r"[;&|><]",  # Command separators and redirectors
        r"\\[a-z]",  # Escape sequences like \n, \t
        r"\\x[0-9a-fA-F]{2}",  # Hex escape sequences like \x41
        r"\\[0-7]{1,3}",  # Octal escape sequences like \041
        r"\\u[0-9a-fA-F]{4}",  # Unicode escape sequences like \u0041
        r"[\x00-\x1f]",  # Control characters (null, newline, tab, etc.)
    ]

    @classmethod
    def validate_chain_name(cls, value: str) -> str:
        """
        Validate blockchain network name with strict pattern matching.

        Args:
            value: Chain name to validate

        Returns:
            Sanitized chain name in lowercase

        Raises:
            SecurityError: If validation fails
        """
        if not value:
            raise SecurityError("Chain name cannot be empty", "chain_name", value)

        # Length check
        if len(value) > cls.MAX_INPUT_LENGTHS["chain_name"]:
            raise SecurityError(
                f"Chain name too long (max {cls.MAX_INPUT_LENGTHS['chain_name']} chars)",
                "chain_name",
                value,
            )

        # Pattern validation - only allow safe characters
        if not re.match(cls.VALIDATION_PATTERNS["chain_name"], value.lower()):
            raise SecurityError(
                "Invalid chain name format. Only lowercase letters, numbers, and hyphens allowed",
                "chain_name",
                value,
            )

        # Check for suspicious patterns and dangerous characters
        if cls._contains_dangerous_patterns(value):
            raise SecurityError(
                "Chain name contains potentially dangerous patterns",
                "chain_name",
                value,
            )

        suspicious_patterns = [
            "..",
            "__",
            "--",
            "admin",
            "root",
            "system",
            "config",
            "env",
        ]
        value_lower = value.lower()
        for pattern in suspicious_patterns:
            if pattern in value_lower:
                raise SecurityError(
                    f"Chain name contains suspicious pattern: {pattern}",
                    "chain_name",
                    value,
                )

        return value.lower().strip()

    @classmethod
    def validate_private_key(cls, value: str) -> PrivateKey:
        """
        Validate private key with comprehensive cryptographic checks.

        Args:
            value: Private key to validate

        Returns:
            Validated private key

        Raises:
            SecurityError: If validation fails
        """
        if not value:
            raise SecurityError("Private key cannot be empty", "private_key")

        # Length check
        if len(value) > cls.MAX_INPUT_LENGTHS["private_key"]:
            raise SecurityError("Private key too long", "private_key")

        # Format validation
        if not re.match(cls.VALIDATION_PATTERNS["private_key"], value):
            raise SecurityError(
                "Invalid private key format. Expected 0x followed by 64 hex characters",
                "private_key",
            )

        # Cryptographic validation using eth_account
        try:
            # Validate that the key can be parsed (we don't need the account object)
            Account.from_key(value)

            # Check for weak keys
            key_bytes = bytes.fromhex(value[2:])

            # Check against known weak patterns
            for weak_pattern in cls.WEAK_PRIVATE_KEY_PATTERNS:
                if key_bytes == weak_pattern:
                    raise SecurityError("Weak private key detected", "private_key")

            # Check for low entropy (simple patterns)
            if cls._has_low_entropy(key_bytes):
                raise SecurityError(
                    "Private key has insufficient entropy", "private_key"
                )

            return PrivateKey(value)

        except ValueError as e:
            raise SecurityError(f"Invalid private key: {str(e)}", "private_key")
        except Exception as e:
            raise SecurityError(
                f"Private key validation failed: {str(e)}", "private_key"
            )

    @classmethod
    def _has_low_entropy(cls, key_bytes: bytes) -> bool:
        """Check if private key has dangerously low entropy"""
        # Simple entropy checks
        unique_bytes = len(set(key_bytes))
        if unique_bytes < 8:  # Very few unique bytes
            return True

        # Check for repeated patterns
        if len(key_bytes) >= 4:
            pattern = key_bytes[:4]
            if key_bytes.count(pattern) > 2:  # Pattern repeats too often
                return True

        return False

    @classmethod
    def validate_address(cls, value: str, checksum_required: bool = True) -> Address:
        """
        Validate Ethereum address with optional checksum verification.

        Args:
            value: Address to validate
            checksum_required: Whether to enforce EIP-55 checksum

        Returns:
            Checksummed address

        Raises:
            SecurityError: If validation fails
        """
        if not value:
            raise SecurityError("Address cannot be empty", "address")

        # Length check
        if len(value) > cls.MAX_INPUT_LENGTHS["address"]:
            raise SecurityError("Address too long", "address", value)

        # Format validation
        if not re.match(cls.VALIDATION_PATTERNS["address"], value):
            raise SecurityError(
                "Invalid address format. Expected 0x followed by 40 hex characters",
                "address",
                value,
            )

        # Validate and convert to checksum format
        try:
            if not Web3.is_address(value):
                raise SecurityError("Invalid Ethereum address", "address", value)

            if checksum_required:
                # Convert to proper checksum format
                checksum_address = Web3.to_checksum_address(value.lower())

                # If original was mixed case, verify it matches checksum
                if value != value.lower() and value != value.upper():
                    if value != checksum_address:
                        raise SecurityError(
                            "Invalid address checksum (EIP-55 validation failed)",
                            "address",
                            value,
                        )

                return Address(checksum_address)
            else:
                return Address(Web3.to_checksum_address(value.lower()))

        except Exception as e:
            if isinstance(e, SecurityError):
                raise
            raise SecurityError(
                f"Address validation failed: {str(e)}", "address", value
            )

    @classmethod
    def validate_rpc_url(cls, value: str, require_https: bool = True) -> RpcUrl:
        """
        Validate RPC URL against trusted providers and security patterns.

        Args:
            value: RPC URL to validate
            require_https: Whether to require HTTPS (default: True)

        Returns:
            Validated RPC URL

        Raises:
            SecurityError: If validation fails
        """
        if not value:
            raise SecurityError("RPC URL cannot be empty", "rpc_url")

        # Length check
        if len(value) > cls.MAX_INPUT_LENGTHS["url"]:
            raise SecurityError("RPC URL too long", "rpc_url", value)

        # Must use HTTPS for security (unless explicitly disabled)
        if require_https and not value.startswith("https://"):
            raise SecurityError("RPC URL must use HTTPS for security", "rpc_url", value)

        if not value.startswith(("http://", "https://")):
            raise SecurityError("Invalid RPC URL protocol", "rpc_url", value)

        # Parse and validate URL structure
        try:
            parsed = urlparse(value)

            if not parsed.netloc:
                raise SecurityError(
                    "Invalid RPC URL format - missing hostname", "rpc_url", value
                )

            # Check for suspicious patterns in URL using regex patterns
            url_lower = value.lower()
            for pattern in cls.SUSPICIOUS_URL_PATTERNS:
                if re.search(pattern, url_lower):
                    # Allow localhost/internal IPs only in development
                    if (
                        pattern
                        in [r"localhost", r"127\.0\.0\.1", r"10\.", r"192\.168\."]
                        and os.getenv("EAS_ENVIRONMENT") == "development"
                    ):
                        continue
                    raise SecurityError(
                        "RPC URL contains suspicious or private network pattern",
                        "rpc_url",
                        value,
                    )

        except SecurityError:
            raise
        except Exception as e:
            raise SecurityError(f"Malformed RPC URL: {str(e)}", "rpc_url", value)

        # Validate against trusted domains (only for production)
        if os.getenv("EAS_ENVIRONMENT") != "development":
            if not cls._is_trusted_rpc_domain(parsed.netloc):
                raise SecurityError(
                    f"Untrusted RPC provider: {parsed.netloc}. Only whitelisted providers allowed",
                    "rpc_url",
                    value,
                )

        return RpcUrl(value)

    @classmethod
    def _is_trusted_rpc_domain(cls, netloc: str) -> bool:
        """Check if RPC domain is in trusted list with enhanced validation"""
        # Remove port if present and normalize
        domain = netloc.lower().split(":")[0]

        # Block obvious malicious patterns
        if re.search(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", domain):  # Direct IP
            return False

        if any(
            suspicious in domain
            for suspicious in ["bit.ly", "tinyurl", "short", "redirect"]
        ):
            return False

        # Direct match against trusted domains
        if domain in cls.TRUSTED_RPC_DOMAINS:
            return True

        # Check for valid subdomain matches (but be strict about depth)
        for trusted_domain in cls.TRUSTED_RPC_DOMAINS:
            if domain.endswith(f".{trusted_domain}"):
                # Prevent subdomain abuse - limit to reasonable depth
                subdomain_parts = domain.replace(f".{trusted_domain}", "").split(".")
                if len(subdomain_parts) <= 3:  # Allow up to 3 subdomain levels
                    # Additional check: subdomains should look legitimate
                    for part in subdomain_parts:
                        if part and (
                            len(part) > 63 or not re.match(r"^[a-z0-9\-]+$", part)
                        ):
                            return False
                    return True

        return False

    @classmethod
    def _contains_dangerous_patterns(cls, value: str) -> bool:
        """Check if value contains dangerous patterns for injection attacks"""
        if not value:
            return False

        for pattern in cls.DANGEROUS_ENV_PATTERNS:
            if re.search(pattern, value):
                return True
        return False

    @classmethod
    def validate_environment_variable(
        cls, name: str, value: str, var_type: str = "general"
    ) -> str:
        """
        Comprehensive validation for environment variables.

        Args:
            name: Environment variable name
            value: Environment variable value
            var_type: Type of variable for specific validation

        Returns:
            Validated and sanitized value

        Raises:
            SecurityError: If validation fails
        """
        if not name:
            raise SecurityError(
                "Environment variable name cannot be empty", "env_var_name"
            )

        if not value:
            raise SecurityError(
                f"Environment variable {name} cannot be empty", "env_var_value"
            )

        # Length checks
        if len(name) > cls.MAX_INPUT_LENGTHS["env_var_name"]:
            raise SecurityError(
                f"Environment variable name too long: {name}", "env_var_name", name
            )

        if len(value) > cls.MAX_INPUT_LENGTHS["env_var_value"]:
            raise SecurityError(
                f"Environment variable {name} value too long", "env_var_value", value
            )

        # Check for dangerous patterns in both name and value
        if cls._contains_dangerous_patterns(name):
            raise SecurityError(
                f"Environment variable name contains dangerous patterns: {name}",
                "env_var_name",
                name,
            )

        if cls._contains_dangerous_patterns(value):
            raise SecurityError(
                f"Environment variable {name} contains potentially dangerous patterns",
                "env_var_value",
                value,
            )

        # Null byte check
        if "\x00" in value or "\x00" in name:
            raise SecurityError(
                f"Environment variable {name} contains null bytes",
                "env_var_value",
                value,
            )

        # Type-specific validation
        if var_type == "chain_name":
            return cls.validate_chain_name(value)
        elif var_type == "private_key":
            return cls.validate_private_key(value)
        elif var_type == "address":
            return cls.validate_address(value)
        elif var_type == "rpc_url":
            return cls.validate_rpc_url(value)
        elif var_type == "chain_id":
            chain_id = cls.validate_chain_id(value)
            return str(chain_id)
        else:
            # Generic validation - strip whitespace and basic sanitization
            sanitized_value = value.strip()

            # Additional checks for generic values
            if any(char in sanitized_value for char in ["<", ">", '"', "'", "&"]):
                raise SecurityError(
                    f"Environment variable {name} contains potentially unsafe characters",
                    "env_var_value",
                    value,
                )

            return sanitized_value

    @classmethod
    def validate_all_environment_variables(
        cls,
        required_vars: Dict[str, str],
        optional_vars: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """
        Validate all environment variables in batch with comprehensive security checks.

        Args:
            required_vars: Dict mapping env var names to their types
            optional_vars: Dict mapping optional env var names to their types

        Returns:
            Dict of validated environment variable values

        Raises:
            SecurityError: If any validation fails
            ValueError: If required variables are missing
        """
        validated_vars = {}
        missing_vars = []

        # Validate required variables
        for env_var, var_type in required_vars.items():
            raw_value = os.getenv(env_var)
            if not raw_value or not raw_value.strip():
                missing_vars.append(env_var)
                continue

            try:
                validated_vars[env_var] = cls.validate_environment_variable(
                    env_var, raw_value, var_type
                )
            except SecurityError as e:
                raise SecurityError(
                    f"Environment variable {env_var} validation failed: {str(e)}",
                    env_var,
                )

        if missing_vars:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing_vars)}"
            )

        # Validate optional variables if present
        if optional_vars:
            for env_var, var_type in optional_vars.items():
                raw_value = os.getenv(env_var)
                if raw_value and raw_value.strip():
                    try:
                        validated_vars[env_var] = cls.validate_environment_variable(
                            env_var, raw_value, var_type
                        )
                    except SecurityError as e:
                        raise SecurityError(
                            f"Environment variable {env_var} validation failed: {str(e)}",
                            env_var,
                        )

        return validated_vars

    @classmethod
    def validate_chain_id(
        cls, value: str, expected_chain_id: Optional[int] = None
    ) -> ChainId:
        """
        Validate chain ID format and value.

        Args:
            value: Chain ID as string
            expected_chain_id: Expected chain ID for verification

        Returns:
            Validated chain ID as integer

        Raises:
            SecurityError: If validation fails
        """
        if not value:
            raise SecurityError("Chain ID cannot be empty", "chain_id")

        # Pattern validation
        if not re.match(cls.VALIDATION_PATTERNS["chain_id"], str(value).strip()):
            raise SecurityError(
                "Invalid chain ID format. Must be a positive integer", "chain_id", value
            )

        try:
            chain_id = int(value)

            if chain_id <= 0:
                raise SecurityError(
                    "Chain ID must be positive", "chain_id", str(chain_id)
                )

            # Sanity check - chain IDs shouldn't be extremely large
            if chain_id > 2**32:  # Reasonable upper bound
                raise SecurityError("Chain ID too large", "chain_id", str(chain_id))

            # Validate against expected value if provided
            if expected_chain_id is not None and chain_id != expected_chain_id:
                raise SecurityError(
                    f"Chain ID mismatch: expected {expected_chain_id}, got {chain_id}",
                    "chain_id",
                    str(chain_id),
                )

            return ChainId(chain_id)

        except ValueError:
            raise SecurityError("Chain ID must be numeric", "chain_id", value)

    @classmethod
    def validate_schema_uid(cls, value: str) -> SchemaUID:
        """
        Validate schema UID format.

        Args:
            value: Schema UID to validate

        Returns:
            Validated schema UID

        Raises:
            SecurityError: If validation fails
        """
        if not value:
            raise SecurityError("Schema UID cannot be empty", "schema_uid")

        if not re.match(cls.VALIDATION_PATTERNS["schema_uid"], value):
            raise SecurityError(
                "Invalid schema UID format. Expected 0x followed by 64 hex characters",
                "schema_uid",
                value,
            )

        return SchemaUID(value)

    @classmethod
    def sanitize_for_logging(cls, value: str, field_type: str = "general") -> str:
        """
        Sanitize sensitive values for safe logging.

        Args:
            value: Value to sanitize
            field_type: Type of field for appropriate sanitization

        Returns:
            Sanitized value safe for logging
        """
        if not value:
            return "[EMPTY]"

        try:
            if field_type == "address":
                # Show first 6 and last 4 characters for addresses
                if len(value) >= 10:
                    return f"{value[:6]}...{value[-4:]}"
                return "[ADDR_TOO_SHORT]"

            elif field_type == "private_key":
                return "[PRIVATE_KEY_REDACTED]"

            elif field_type == "url":
                try:
                    parsed = urlparse(value)
                    return f"{parsed.scheme}://{parsed.netloc}/..."
                except (ValueError, AttributeError):
                    return "[INVALID_URL]"

            elif field_type == "transaction_hash":
                if len(value) >= 14:
                    return f"{value[:10]}...{value[-6:]}"
                return "[TX_HASH]"

            elif field_type == "schema_uid" or field_type == "uid":
                if len(value) >= 10:
                    return f"{value[:8]}...{value[-6:]}"
                return "[UID]"

            else:
                # Default: hash the value for logging
                hash_obj = hashlib.sha256(value.encode("utf-8")).hexdigest()
                return f"[HASH:{hash_obj[:8]}]"

        except Exception:
            return "[SANITIZATION_ERROR]"


class ContractAddressValidator:
    """Validates contract addresses against known good EAS contracts"""

    # Known EAS contract addresses per chain - verified from official sources
    KNOWN_EAS_CONTRACTS = {
        # Mainnet contracts
        1: {  # Ethereum
            "0xa1207f3bba224e2c9c3c6d5af63d0eb1582ce587": "EAS Contract",
            "0xa7b39296258348c78294f95b872b282326a97bdf": "Schema Registry",
        },
        8453: {  # Base
            "0x4200000000000000000000000000000000000021": "EAS Contract",
            "0x4200000000000000000000000000000000000020": "Schema Registry",
        },
        42161: {  # Arbitrum
            "0xbd75f629a22dc1ced33dda0b68c546a1c035c458": "EAS Contract",
            "0xa310da9c5b885e7fb3fba9d66e9ba6df512b78eb": "Schema Registry",
        },
        10: {  # Optimism
            "0x4e0275ea5a89e7a3c1b58411379d1a0eddc5b088": "EAS Contract",
            "0x8250f4af4b972684f7b336503e2d6dfedeb1487a": "Schema Registry",
        },
        137: {  # Polygon
            "0x5e634ef5355f45a855d02d66ecd687b1502af790": "EAS Contract",
            "0x7876eef51a891e737af8ba5a5e0f0fd29073d5a7": "Schema Registry",
        },
        # Testnet contracts
        11155111: {  # Sepolia
            "0xc2679fbd37d54388ce493f1db75320d236e1815e": "EAS Contract",
            "0x0a7e2ff54e76b8e6659aedc9103fb21c038050d0": "Schema Registry",
        },
        84532: {  # Base Sepolia
            "0x4200000000000000000000000000000000000021": "EAS Contract",
            "0x4200000000000000000000000000000000000020": "Schema Registry",
        },
        11155420: {  # Optimism Sepolia
            "0x4e0275ea5a89e7a3c1b58411379d1a0eddc5b088": "EAS Contract",
            "0x8250f4af4b972684f7b336503e2d6dfedeb1487a": "Schema Registry",
        },
        421614: {  # Arbitrum Sepolia
            "0xbd75f629a22dc1ced33dda0b68c546a1c035c458": "EAS Contract",
            "0xa310da9c5b885e7fb3fba9d66e9ba6df512b78eb": "Schema Registry",
        },
        80001: {  # Polygon Mumbai
            "0x5e634ef5355f45a855d02d66ecd687b1502af790": "EAS Contract",
            "0x7876eef51a891e737af8ba5a5e0f0fd29073d5a7": "Schema Registry",
        },
    }

    @classmethod
    def is_valid_eas_contract(cls, address: str, chain_id: int) -> bool:
        """
        Verify contract address is a known EAS contract.

        Args:
            address: Contract address to verify
            chain_id: Chain ID for the network

        Returns:
            True if address is a known EAS contract
        """
        if not address or chain_id not in cls.KNOWN_EAS_CONTRACTS:
            return False

        # Normalize address to lowercase for comparison
        address_lower = address.lower()
        known_contracts = cls.KNOWN_EAS_CONTRACTS[chain_id]

        return address_lower in {addr.lower() for addr in known_contracts.keys()}

    @classmethod
    def get_contract_type(cls, address: str, chain_id: int) -> Optional[str]:
        """
        Get the type of EAS contract (EAS Contract or Schema Registry).

        Args:
            address: Contract address
            chain_id: Chain ID

        Returns:
            Contract type string or None if unknown
        """
        if chain_id not in cls.KNOWN_EAS_CONTRACTS:
            return None

        address_lower = address.lower()
        known_contracts = cls.KNOWN_EAS_CONTRACTS[chain_id]

        for known_addr, contract_type in known_contracts.items():
            if address_lower == known_addr.lower():
                return contract_type

        return None


def create_secure_logger(name: str) -> logging.Logger:
    """
    Create a logger with security-aware configuration.

    Args:
        name: Logger name

    Returns:
        Configured logger with security filtering
    """
    logger = logging.getLogger(name)

    # Add custom filter to sanitize log messages
    class SecurityLogFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            # Sanitize common sensitive patterns in log messages
            if hasattr(record, "msg") and isinstance(record.msg, str):
                msg = record.msg

                # Remove potential private keys (0x followed by 64 hex chars)
                msg = re.sub(r"0x[a-fA-F0-9]{64}", "[PRIVATE_KEY_REDACTED]", msg)

                # Sanitize long addresses (keep first/last few chars)
                msg = re.sub(
                    r"0x[a-fA-F0-9]{40}",
                    lambda m: SecureEnvironmentValidator.sanitize_for_logging(
                        m.group(0), "address"
                    ),
                    msg,
                )

                record.msg = msg

            return True

    logger.addFilter(SecurityLogFilter())
    return logger


def validate_environment_security() -> Dict[str, Any]:
    """
    Perform comprehensive security validation of the current environment.

    Returns:
        Dict containing security validation results
    """
    import time

    results: Dict[str, Any] = {
        "timestamp": time.time(),
        "environment": os.getenv("EAS_ENVIRONMENT", "unknown"),
        "checks": {},
        "warnings": [],
        "errors": [],
    }

    # Check for development vs production environment
    env_type = os.getenv("EAS_ENVIRONMENT")
    if not env_type:
        results["warnings"].append(
            "EAS_ENVIRONMENT not set - defaulting to production security"
        )
    elif env_type not in ["development", "testing", "production"]:
        results["warnings"].append(f"Unknown EAS_ENVIRONMENT: {env_type}")

    # Check file permissions on .env file if it exists
    env_file = ".env"
    if os.path.exists(env_file):
        file_mode = oct(os.stat(env_file).st_mode)[-3:]
        if file_mode != "600":
            results["warnings"].append(
                f".env file permissions too permissive: {file_mode} (should be 600)"
            )
        results["checks"]["env_file_permissions"] = file_mode

    # Check for common environment variables and their security
    sensitive_env_vars = [
        "EAS_PRIVATE_KEY",
        "PRIVATE_KEY",
        "MNEMONIC",
        "SEED_PHRASE",
        "API_KEY",
        "SECRET_KEY",
        "ACCESS_TOKEN",
        "PASSWORD",
    ]

    for var in sensitive_env_vars:
        if os.getenv(var):
            # Check if it looks like a real sensitive value vs placeholder
            value = os.getenv(var)
            if value and not any(
                placeholder in value.lower()
                for placeholder in [
                    "your_",
                    "placeholder",
                    "example",
                    "test",
                    "demo",
                    "sample",
                ]
            ):
                results["checks"][f"{var}_present"] = True
            else:
                results["warnings"].append(f"{var} appears to be a placeholder value")

    return results


# Export key classes and functions
__all__ = [
    "SecurityError",
    "SecureEnvironmentValidator",
    "ContractAddressValidator",
    "create_secure_logger",
    "validate_environment_security",
]
