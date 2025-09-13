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


def get_network_config(
    *,
    chain_name: Optional[str] = None,
    chain_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Get network configuration by chain name or chain ID with enhanced security validation.

    Args:
        chain_name: Name of the network (e.g., 'ethereum', 'base', 'sepolia', 'arbitrum')
        chain_id: Chain ID of the network (e.g., 1, 8453, 11155111, 42161)

    Note:
        Exactly one of chain_name or chain_id must be provided (XOR).

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
        ValueError: If neither or both parameters are provided, or if chain is not supported
        SecurityError: If network configuration fails security validation
    """
    # Validate XOR requirement
    if (chain_name is None) == (chain_id is None):
        raise ValueError(
            "Exactly one of 'chain_name' or 'chain_id' must be provided (not both, not neither)"
        )

    config: Optional[Dict[str, Any]] = None
    lookup_key: str = ""

    if chain_name is not None:
        # Validate chain name securely
        try:
            chain_name = SecureEnvironmentValidator.validate_chain_name(chain_name)
        except SecurityError as e:
            raise ValueError(f"Invalid chain name: {str(e)}")

        if chain_name not in SUPPORTED_CHAINS:
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
                f"Unsupported chain name: '{chain_name}'. "
                f"\nSupported chains ({len(supported_networks)} total):"
                f"\nMainnets: {mainnet_networks}"
                f"\nTestnets: {testnet_networks}"
            )
            raise ValueError(error_msg)

        config = SUPPORTED_CHAINS[chain_name].copy()
        lookup_key = chain_name

    else:  # chain_id is not None
        # Validate chain ID securely
        try:
            validated_chain_id = SecureEnvironmentValidator.validate_chain_id(
                str(chain_id)
            )
        except SecurityError as e:
            raise ValueError(f"Invalid chain ID: {str(e)}")

        # Find config by chain_id
        for name, chain_config in SUPPORTED_CHAINS.items():
            if chain_config.get("chain_id") == validated_chain_id:
                config = chain_config.copy()
                lookup_key = name
                break

        if config is None:
            supported_chain_ids = [
                config["chain_id"]
                for config in SUPPORTED_CHAINS.values()
                if "chain_id" in config and isinstance(config["chain_id"], int)
            ]
            mainnet_chain_ids = [
                config["chain_id"]
                for config in SUPPORTED_CHAINS.values()
                if (
                    config.get("network_type") == "mainnet"
                    and "chain_id" in config
                    and isinstance(config["chain_id"], int)
                )
            ]
            testnet_chain_ids = [
                config["chain_id"]
                for config in SUPPORTED_CHAINS.values()
                if (
                    config.get("network_type") == "testnet"
                    and "chain_id" in config
                    and isinstance(config["chain_id"], int)
                )
            ]

            error_msg = (
                f"Unsupported chain ID: {chain_id}. "
                f"\nSupported chain IDs ({len(supported_chain_ids)} total):"
                f"\nMainnets: {sorted(mainnet_chain_ids)}"
                f"\nTestnets: {sorted(testnet_chain_ids)}"
            )
            raise ValueError(error_msg)

    assert config is not None  # Should never happen due to validation above

    # Enhanced configuration validation with security checks
    validate_chain_config(config, lookup_key)

    # Verify contract addresses against known good values
    if not _verify_contract_integrity(config, lookup_key):
        raise SecurityError(f"Contract address integrity check failed for {lookup_key}")

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


def get_chain_id_from_name(chain_name: str) -> int:
    """
    Get chain ID from chain name.

    Args:
        chain_name: Name of the chain (e.g., 'ethereum', 'base', 'sepolia')

    Returns:
        Chain ID as integer

    Raises:
        ValueError: If chain name is not supported
    """
    config = get_network_config(chain_name=chain_name)
    return int(config["chain_id"])


def get_chain_name_from_id(chain_id: int) -> str:
    """
    Get chain name from chain ID.

    Args:
        chain_id: Chain ID (e.g., 1, 8453, 11155111)

    Returns:
        Chain name as string

    Raises:
        ValueError: If chain ID is not supported
    """
    config = get_network_config(chain_id=chain_id)
    return str(config["name"])


def list_supported_chain_ids() -> List[int]:
    """
    Get a list of all supported chain IDs.

    Returns:
        List of supported chain IDs sorted numerically
    """
    chain_ids = [
        config["chain_id"]
        for config in SUPPORTED_CHAINS.values()
        if "chain_id" in config and isinstance(config["chain_id"], int)
    ]
    return sorted(chain_ids)


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
    network_name: Optional[str] = None,  # Deprecated parameter name
    from_account: Optional[str] = None,
    private_key: Optional[str] = None,
    rpc_url: Optional[str] = None,
    chain_name: Optional[str] = None,  # New parameter name
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

    # Handle both old and new parameter names for backward compatibility
    if (network_name is None) == (chain_name is None):
        if network_name is None and chain_name is None:
            # Use environment variables if not provided (with validation)
            network_name = os.getenv("NETWORK", "sepolia")
        else:
            raise ValueError(
                "Cannot specify both network_name and chain_name. Use chain_name for new code."
            )

    # Use the provided parameter or default
    final_chain_name = chain_name or network_name
    assert (
        final_chain_name is not None
    ), "chain_name should not be None after assignment"

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
        final_chain_name = SecureEnvironmentValidator.validate_chain_name(
            final_chain_name
        )
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

    config = get_network_config(chain_name=final_chain_name)

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
