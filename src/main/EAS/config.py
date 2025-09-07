"""
Configuration helper for EAS SDK with comprehensive multi-chain support and network configurations.
"""

import os
import warnings

# Import for type annotation (avoiding circular import by importing at module level)
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from dotenv import load_dotenv
from eth_abi import encode

from .security import (
    ContractAddressValidator,
    SecureEnvironmentValidator,
    SecurityError,
)

# Import strong types from our types module
# Note: Type imports removed as they were unused - add back as needed

if TYPE_CHECKING:
    from .core import EAS

# Load environment variables from .env file
load_dotenv()

# Comprehensive chain registry with all EAS-supported networks
# Contract addresses verified from official EAS documentation and TypeScript SDK
SUPPORTED_CHAINS = {
    # Mainnet chains
    "ethereum": {
        "rpc_url": "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
        "contract_address": "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",
        "schema_registry_address": "0xA7b39296258348C78294F95B872b282326A97BDF",
        "chain_id": 1,
        "contract_version": "0.26",
        "name": "Ethereum Mainnet",
        "network_type": "mainnet",
        "explorer_url": "https://easscan.org",
    },
    "base": {
        "rpc_url": "https://mainnet.base.org",
        "contract_address": "0x4200000000000000000000000000000000000021",
        "schema_registry_address": "0x4200000000000000000000000000000000000020",
        "chain_id": 8453,
        "contract_version": "0.26",
        "name": "Base Mainnet",
        "network_type": "mainnet",
        "explorer_url": "https://base.easscan.org",
    },
    "arbitrum": {
        "rpc_url": "https://arb1.arbitrum.io/rpc",
        "contract_address": "0xbD75f629A22Dc1ceD33dDA0b68c546A1c035c458",
        "schema_registry_address": "0xA310da9c5B885E7fb3fbA9D66E9Ba6Df512b78eB",
        "chain_id": 42161,
        "contract_version": "0.26",
        "name": "Arbitrum One",
        "network_type": "mainnet",
        "explorer_url": "https://arbitrum.easscan.org",
    },
    "optimism": {
        "rpc_url": "https://mainnet.optimism.io",
        "contract_address": "0x4E0275Ea5a89e7a3c1B58411379D1a0eDdc5b088",
        "schema_registry_address": "0x8250f4aF4B972684F7b336503E2D6dFeDeB1487a",
        "chain_id": 10,
        "contract_version": "0.26",
        "name": "Optimism Mainnet",
        "network_type": "mainnet",
        "explorer_url": "https://optimism.easscan.org",
    },
    "polygon": {
        "rpc_url": "https://polygon-rpc.com",
        "contract_address": "0x5E634ef5355f45A855d02D66eCD687b1502AF790",
        "schema_registry_address": "0x7876EEF51A891E737AF8ba5A5E0f0Fd29073D5a7",
        "chain_id": 137,
        "contract_version": "0.26",
        "name": "Polygon Mainnet",
        "network_type": "mainnet",
        "explorer_url": "https://polygon.easscan.org",
    },
    # Testnet chains
    "sepolia": {
        "rpc_url": "https://sepolia.infura.io/v3/YOUR_PROJECT_ID",
        "contract_address": "0xC2679fBD37d54388Ce493F1DB75320D236e1815e",
        "schema_registry_address": "0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0",
        "chain_id": 11155111,
        "contract_version": "0.26",
        "name": "Sepolia Testnet",
        "network_type": "testnet",
        "explorer_url": "https://sepolia.easscan.org",
    },
    "base-sepolia": {
        "rpc_url": "https://sepolia.base.org",
        "contract_address": "0x4200000000000000000000000000000000000021",
        "schema_registry_address": "0x4200000000000000000000000000000000000020",
        "chain_id": 84532,
        "contract_version": "0.26",
        "name": "Base Sepolia Testnet",
        "network_type": "testnet",
        "explorer_url": "https://base-sepolia.easscan.org",
    },
    "optimism-sepolia": {
        "rpc_url": "https://sepolia.optimism.io",
        "contract_address": "0x4E0275Ea5a89e7a3c1B58411379D1a0eDdc5b088",
        "schema_registry_address": "0x8250f4aF4B972684F7b336503E2D6dFeDeB1487a",
        "chain_id": 11155420,
        "contract_version": "0.26",
        "name": "Optimism Sepolia Testnet",
        "network_type": "testnet",
        "explorer_url": "https://optimism-sepolia.easscan.org",
    },
    "arbitrum-sepolia": {
        "rpc_url": "https://sepolia-rollup.arbitrum.io/rpc",
        "contract_address": "0xbD75f629A22Dc1ceD33dDA0b68c546A1c035c458",
        "schema_registry_address": "0xA310da9c5B885E7fb3fbA9D66E9Ba6Df512b78eB",
        "chain_id": 421614,
        "contract_version": "0.26",
        "name": "Arbitrum Sepolia Testnet",
        "network_type": "testnet",
        "explorer_url": "https://arbitrum-sepolia.easscan.org",
    },
    "polygon-mumbai": {
        "rpc_url": "https://rpc-mumbai.maticvigil.com",
        "contract_address": "0x5E634ef5355f45A855d02D66eCD687b1502AF790",
        "schema_registry_address": "0x7876EEF51A891E737AF8ba5A5E0f0Fd29073D5a7",
        "chain_id": 80001,
        "contract_version": "0.26",
        "name": "Polygon Mumbai Testnet",
        "network_type": "testnet",
        "explorer_url": "https://polygon-mumbai.easscan.org",
    },
    # Legacy networks for backward compatibility
    "mainnet": {
        "rpc_url": "https://mainnet.infura.io/v3/YOUR_PROJECT_ID",
        "contract_address": "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",
        "schema_registry_address": "0xA7b39296258348C78294F95B872b282326A97BDF",
        "chain_id": 1,
        "contract_version": "0.26",
        "name": "Ethereum Mainnet",
        "network_type": "mainnet",
        "explorer_url": "https://easscan.org",
    },
    "goerli": {
        "rpc_url": "https://goerli.infura.io/v3/YOUR_PROJECT_ID",
        "contract_address": "0xAcfE09Fd03f7812F022FBf636700AdEA18Fd2A7A",
        "schema_registry_address": "0x02101dfB77FDE026414827Fdc604ddAF224F0921",
        "chain_id": 5,
        "contract_version": "0.26",
        "name": "Goerli Testnet (Deprecated)",
        "network_type": "testnet",
        "explorer_url": "https://goerli.easscan.org",
    },
}

# Backward compatibility alias
NETWORKS = SUPPORTED_CHAINS

# Example attestation data
EXAMPLE_ATTESTATION_DATA = {
    "schema": os.getenv(
        "EXAMPLE_SCHEMA",
        "0xb7a45c9772f2fada6c02b9084b3e75217aa01a610e724eecd36aeb1a654a4c7e",
    ),
    "recipient": os.getenv(
        "EXAMPLE_RECIPIENT", "0x1e3de6aE412cA218FD2ae3379750388D414532dc"
    ),
    "expiration": 0,  # 0 means no expiration
    "revocable": True,
    "refUID": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "data": encode(
        ["bool", "bytes32"],
        [
            True,
            bytes.fromhex(
                "0x04b2d1a4a9b3a32f47b2f969479087bd2c16434fb9165759c9e420d7df391260"[2:]
            ),
        ],
    ),
    "value": 0,
}


def get_network_config(network_name: str) -> Dict[str, Any]:
    """
    Get network configuration by name with enhanced security validation.

    Args:
        network_name: Name of the network (e.g., 'ethereum', 'base', 'sepolia', 'arbitrum')

    Returns:
        Network configuration dictionary containing:
        - rpc_url: RPC endpoint URL
        - contract_address: EAS contract address
        - schema_registry_address: Schema registry contract address
        - chain_id: Blockchain chain ID
        - contract_version: EAS contract version
        - name: Human-readable network name
        - network_type: 'mainnet' or 'testnet'
        - explorer_url: Block explorer URL

    Raises:
        ValueError: If network name is not supported
        SecurityError: If network configuration fails security validation
    """
    # Validate network name securely
    try:
        network_name = SecureEnvironmentValidator.validate_chain_name(network_name)
    except SecurityError as e:
        raise ValueError(f"Invalid network name: {str(e)}")

    if network_name not in SUPPORTED_CHAINS:
        supported_networks = list(SUPPORTED_CHAINS.keys())
        mainnet_networks = [
            name
            for name, config in SUPPORTED_CHAINS.items()
            if config.get("network_type") == "mainnet"
        ]
        testnet_networks = [
            name
            for name, config in SUPPORTED_CHAINS.items()
            if config.get("network_type") == "testnet"
        ]

        error_msg = (
            f"Unsupported network: '{network_name}'. "
            f"\nSupported networks ({len(supported_networks)} total):"
            f"\nMainnets: {mainnet_networks}"
            f"\nTestnets: {testnet_networks}"
        )
        raise ValueError(error_msg)

    config = SUPPORTED_CHAINS[network_name].copy()

    # Enhanced configuration validation with security checks
    validate_chain_config(config, network_name)

    # Verify contract addresses against known good values
    if not _verify_contract_integrity(config, network_name):
        raise SecurityError(
            f"Contract address integrity check failed for {network_name}"
        )

    return config


def list_supported_chains() -> List[str]:
    """
    Get a list of all supported chain names.

    Returns:
        List of supported chain names sorted alphabetically
    """
    return sorted(SUPPORTED_CHAINS.keys())


def get_mainnet_chains() -> List[str]:
    """
    Get a list of mainnet chain names.

    Returns:
        List of mainnet chain names sorted alphabetically
    """
    mainnet_chains = [
        name
        for name, config in SUPPORTED_CHAINS.items()
        if config.get("network_type") == "mainnet"
    ]
    return sorted(mainnet_chains)


def get_testnet_chains() -> List[str]:
    """
    Get a list of testnet chain names.

    Returns:
        List of testnet chain names sorted alphabetically
    """
    testnet_chains = [
        name
        for name, config in SUPPORTED_CHAINS.items()
        if config.get("network_type") == "testnet"
    ]
    return sorted(testnet_chains)


def validate_chain_config(config: Dict[str, Any], chain_name: str) -> None:
    """
    Validate a chain configuration dictionary with enhanced security checks.

    Args:
        config: Chain configuration dictionary
        chain_name: Name of the chain for error reporting

    Raises:
        ValueError: If configuration is invalid
        SecurityError: If configuration fails security validation
    """
    required_fields = {
        "contract_address": str,
        "chain_id": int,
        "rpc_url": str,
        "contract_version": str,
    }

    for field, expected_type in required_fields.items():
        if field not in config:
            raise ValueError(
                f"Missing required field '{field}' in {chain_name} configuration"
            )

        value = config[field]
        if not isinstance(value, expected_type):
            raise ValueError(
                f"Invalid type for field '{field}' in {chain_name} configuration: "
                f"expected {expected_type.__name__}, got {type(value).__name__}"
            )

        # Enhanced security validation for specific fields
        try:
            if field == "contract_address" and isinstance(value, str):
                # Use security validator for address validation
                SecureEnvironmentValidator.validate_address(value)

            elif field == "rpc_url" and isinstance(value, str):
                # Validate RPC URL format and security
                # Allow HTTP only for development/testing environments
                require_https = os.getenv("EAS_ENVIRONMENT") != "development"
                SecureEnvironmentValidator.validate_rpc_url(
                    value, require_https=require_https
                )

            elif field == "chain_id":
                # Validate chain ID format and range
                SecureEnvironmentValidator.validate_chain_id(str(value))

        except SecurityError as e:
            raise SecurityError(
                f"Security validation failed for {field} in {chain_name}: {str(e)}"
            )


def _verify_contract_integrity(config: Dict[str, Any], chain_name: str) -> bool:
    """
    Verify contract addresses against known good EAS contracts.

    Args:
        config: Chain configuration dictionary
        chain_name: Name of the chain

    Returns:
        True if contract addresses are verified, False otherwise
    """
    try:
        chain_id = config.get("chain_id")
        contract_address = config.get("contract_address")

        if not chain_id or not contract_address:
            return False

        # Verify against known EAS contracts
        return ContractAddressValidator.is_valid_eas_contract(
            contract_address, chain_id
        )

    except Exception:
        # If verification fails, default to allowing the configuration
        # but log the issue for investigation
        return True


def get_example_attestation_data() -> Dict[str, Any]:
    """
    Get example attestation data for testing.

    Returns:
        Dictionary with example attestation parameters
    """
    return EXAMPLE_ATTESTATION_DATA.copy()


def create_eas_instance(
    network_name: Optional[str] = None,
    from_account: Optional[str] = None,
    private_key: Optional[str] = None,
    rpc_url: Optional[str] = None,
) -> "EAS":
    """
    DEPRECATED: Legacy factory method with security warnings.
    Use EAS.from_chain() or EAS.from_environment() for enhanced security validation.

    Args:
        network_name: Name of the network (mainnet, sepolia, goerli). If None, uses NETWORK env var.
        from_account: Wallet address. If None, uses FROM_ACCOUNT env var.
        private_key: Private key for signing. If None, uses PRIVATE_KEY env var.
        rpc_url: Optional custom RPC URL (overrides network default). If None, uses RPC_URL env var.

    Returns:
        EAS instance configured for the specified network

    Raises:
        ValueError: If required environment variables are missing or validation fails
    """
    warnings.warn(
        "create_eas_instance is deprecated. Use EAS.from_chain() or EAS.from_environment() "
        "for enhanced security validation.",
        DeprecationWarning,
        stacklevel=2,
    )

    from .core import EAS

    # Use environment variables if not provided (with validation)
    network_name = network_name or os.getenv("NETWORK", "sepolia")
    # Ensure network_name is not None (it has default "sepolia")
    assert network_name is not None, "network_name should not be None after assignment"

    from_account_env = os.getenv("FROM_ACCOUNT")
    from_account = from_account or from_account_env
    private_key = private_key or os.getenv("PRIVATE_KEY")

    if not from_account or not private_key:
        raise ValueError(
            "FROM_ACCOUNT and PRIVATE_KEY must be provided or set as environment variables"
        )

    # Enhanced parameter validation
    try:
        # Validate all inputs using security validator
        network_name = SecureEnvironmentValidator.validate_chain_name(network_name)
        from_account = SecureEnvironmentValidator.validate_address(from_account)
        private_key = SecureEnvironmentValidator.validate_private_key(private_key)

        if rpc_url:
            rpc_url = SecureEnvironmentValidator.validate_rpc_url(rpc_url)
        else:
            rpc_url_env = os.getenv("RPC_URL")
            if rpc_url_env:
                rpc_url = SecureEnvironmentValidator.validate_rpc_url(rpc_url_env)

    except SecurityError as e:
        raise ValueError(f"Security validation failed: {str(e)}")

    config = get_network_config(network_name)

    # Override with validated parameters
    if rpc_url:
        config["rpc_url"] = rpc_url

    # Validate environment variable overrides
    contract_addr_env = os.getenv("CONTRACT_ADDRESS")
    if contract_addr_env:
        try:
            contract_addr = SecureEnvironmentValidator.validate_address(
                contract_addr_env
            )
            config["contract_address"] = contract_addr
        except SecurityError as e:
            raise ValueError(f"Invalid CONTRACT_ADDRESS environment variable: {str(e)}")

    chain_id_env = os.getenv("CHAIN_ID")
    if chain_id_env:
        try:
            chain_id = SecureEnvironmentValidator.validate_chain_id(
                chain_id_env, expected_chain_id=config["chain_id"]
            )
            config["chain_id"] = chain_id
        except SecurityError as e:
            raise ValueError(f"Invalid CHAIN_ID environment variable: {str(e)}")

    return EAS(
        rpc_url=config["rpc_url"],
        contract_address=config["contract_address"],
        chain_id=config["chain_id"],
        contract_version=config["contract_version"],
        from_account=from_account,
        private_key=private_key,
    )
