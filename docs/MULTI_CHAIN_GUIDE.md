# EAS Python SDK - Multi-Chain Support Guide

The EAS Python SDK provides comprehensive multi-chain support with **security features**, enabling you to interact with EAS contracts across all major blockchain networks where EAS is deployed.

## ⚠️ SECURITY NOTICE

**This SDK includes comprehensive security validation to protect against common attack vectors including environment variable injection, weak private keys, malicious RPC endpoints, and information disclosure. All examples in this guide use placeholder values - NEVER use example private keys or addresses in production!**

## 🌐 Supported Networks

### Mainnet Chains
- **Ethereum** (`ethereum`) - Chain ID: 1
- **Base** (`base`) - Chain ID: 8453  
- **Arbitrum** (`arbitrum`) - Chain ID: 42161
- **Optimism** (`optimism`) - Chain ID: 10
- **Polygon** (`polygon`) - Chain ID: 137

### Testnet Chains
- **Sepolia** (`sepolia`) - Chain ID: 11155111
- **Base Sepolia** (`base-sepolia`) - Chain ID: 84532
- **Optimism Sepolia** (`optimism-sepolia`) - Chain ID: 11155420
- **Arbitrum Sepolia** (`arbitrum-sepolia`) - Chain ID: 421614
- **Polygon Mumbai** (`polygon-mumbai`) - Chain ID: 80001

### Legacy Networks (Backward Compatibility)
- **Mainnet** (`mainnet`) - Alias for Ethereum
- **Goerli** (`goerli`) - Chain ID: 5 (deprecated)

## 🏭 Factory Methods

### EAS.from_chain()

Create an EAS instance by specifying the chain name. The SDK automatically resolves the correct contract addresses and configuration.

```python
from EAS.core import EAS
from EAS.security import SecurityError

# ⚠️ SECURITY: Generate secure private keys - NEVER use example values!
from eth_account import Account
account = Account.create()
secure_private_key = account.key.hex()
secure_address = account.address

try:
    # Basic usage - Ethereum mainnet with security validation
    eas = EAS.from_chain(
        chain_name='ethereum',
        private_key=secure_private_key,  # Use generated key
        from_account=secure_address     # Use generated address
    )
    
    # Base mainnet
    eas = EAS.from_chain(
        chain_name='base', 
        private_key=secure_private_key,
        from_account=secure_address
    )
    
    # With custom RPC URL (must be HTTPS and from trusted provider)
    eas = EAS.from_chain(
        chain_name='base',
        private_key=secure_private_key,
        from_account=secure_address,
        rpc_url='https://base.llamarpc.com'  # Trusted provider
    )
    
except SecurityError as e:
    print(f"Security validation failed: {e}")
except ValueError as e:
    print(f"Configuration error: {e}")
```

### EAS.from_environment()

Create an EAS instance using environment variables for configuration.

```python
from EAS.core import EAS
from EAS.security import SecurityError
import os

# ⚠️ SECURITY: Use secure key generation and proper environment setup
# NEVER hardcode private keys in your application code!

# Set environment variables securely
os.environ['EAS_CHAIN'] = 'ethereum'
# Load private key from secure storage (e.g., AWS Secrets Manager, HashiCorp Vault)
# os.environ['EAS_PRIVATE_KEY'] = load_from_secure_storage('eas_private_key')
# os.environ['EAS_FROM_ACCOUNT'] = load_from_secure_storage('eas_from_account')

# Only HTTPS RPC URLs from trusted providers are allowed
os.environ['EAS_RPC_URL'] = 'https://mainnet.infura.io/v3/YOUR_PROJECT_ID'

try:
    # Create EAS instance with automatic security validation
    eas = EAS.from_environment()
    print("EAS instance created successfully with security validation")
    
except SecurityError as e:
    print(f"Security validation failed: {e}")
    # Log security errors for monitoring
except ValueError as e:
    print(f"Configuration error: {e}")
```

#### Environment Variables

| Variable | Required | Description | Security Notes |
|----------|----------|-------------|----------------|
| `EAS_CHAIN` | ✅ | Chain name (e.g., 'ethereum', 'base', 'sepolia') | Validated against injection attacks |
| `EAS_PRIVATE_KEY` | ✅ | Private key for transaction signing | ⚠️ Cryptographically validated, checked for weak keys |
| `EAS_FROM_ACCOUNT` | ✅ | Account address for transactions | EIP-55 checksum validation |
| `EAS_RPC_URL` | ❌ | Custom RPC URL (overrides chain default) | ⚠️ Must be HTTPS, only trusted providers allowed |
| `EAS_CONTRACT_ADDRESS` | ❌ | Custom contract address (overrides chain default) | Validated against known EAS contracts |

## 📋 Configuration System

### List Supported Chains

```python
from EAS.config import list_supported_chains, get_mainnet_chains, get_testnet_chains

# Get all supported chains
all_chains = list_supported_chains()
print(f"Supported chains: {all_chains}")

# Get mainnet chains only
mainnet_chains = get_mainnet_chains()
print(f"Mainnet chains: {mainnet_chains}")

# Get testnet chains only  
testnet_chains = get_testnet_chains()
print(f"Testnet chains: {testnet_chains}")
```

### Get Chain Configuration

```python
from EAS.config import get_network_config

# Get configuration for a specific chain
config = get_network_config('ethereum')
print(f"Chain ID: {config['chain_id']}")
print(f"Contract Address: {config['contract_address']}")
print(f"RPC URL: {config['rpc_url']}")
print(f"Network Type: {config['network_type']}")
print(f"Explorer URL: {config['explorer_url']}")
```

## 🔄 Migration Guide

### From Old SDK (4 hardcoded networks)

```python
# OLD WAY - Limited to 4 networks
from EAS.config import create_eas_instance

eas = create_eas_instance(
    network_name='mainnet',  # Only mainnet, sepolia, goerli, base-sepolia
    from_account=account,
    private_key=private_key
)
```

### To Multi-Chain SDK (12+ networks)

```python
# CURRENT WAY - Supports all EAS-deployed chains
from EAS.core import EAS

# Method 1: Direct chain specification
eas = EAS.from_chain(
    chain_name='ethereum',  # or 'base', 'arbitrum', 'optimism', 'polygon', etc.
    private_key=private_key,
    from_account=account
)

# Method 2: Environment-based configuration
eas = EAS.from_environment()

# Method 3: Custom overrides
eas = EAS.from_chain(
    chain_name='base',
    private_key=private_key,
    from_account=account,
    rpc_url='https://my-base-rpc.com',
    contract_address='0x...'  # if needed
)
```

## 🔒 Security Features & Best Practices

The EAS SDK includes comprehensive security validation to protect against common attack vectors:

### Security Validations

- **Environment Variable Injection Protection**: Validates all inputs against injection attacks
- **Cryptographic Private Key Validation**: Verifies private keys using `eth_account` library
- **Weak Key Detection**: Rejects keys with insufficient entropy or known weak patterns
- **RPC URL Security**: Only allows HTTPS URLs from trusted providers
- **Contract Address Verification**: Validates against known EAS contract addresses
- **Information Disclosure Prevention**: Sanitizes sensitive data in logs
- **Chain ID Validation**: Prevents network confusion attacks

### Trusted RPC Providers

Only the following RPC providers are allowed in production:

- **Infrastructure Providers**: infura.io, alchemy.com, quicknode.com, ankr.com
- **Official Chain Providers**: base.org, arbitrum.io, optimism.io, polygon-rpc.com
- **Additional Trusted**: moralis.io, chainstack.com, getblock.io

### Private Key Security

```python
# ✅ SECURE: Generate cryptographically secure private keys
from eth_account import Account

# Generate new account with secure random private key
account = Account.create()
private_key = account.key.hex()
address = account.address

# ✅ SECURE: Load from secure storage
import os
private_key = os.environ.get('PRIVATE_KEY')  # From secure env vars
# Or load from secure storage services:
# private_key = aws_secrets_manager.get_secret('eas-private-key')
# private_key = vault_client.read('secret/eas-private-key')

# ❌ NEVER DO: Hardcode private keys
private_key = '0x1234567890...'  # NEVER!

# ❌ NEVER DO: Use example or test keys in production
private_key = '0x0000000000000000000000000000000000000000000000000000000000000001'
```

### Environment Variable Security

```python
# ✅ SECURE: Validate environment variables
try:
    eas = EAS.from_environment()
    # Automatic validation of all environment variables
except SecurityError as e:
    logging.error(f"Security validation failed: {e}")
    # Handle security errors appropriately

# ✅ SECURE: Set restrictive file permissions for .env files
# chmod 600 .env

# ❌ INSECURE: Don't commit .env files to version control
# Add .env to .gitignore
```

### RPC Security

```python
# ✅ SECURE: Use trusted HTTPS RPC providers
trusted_rpcs = {
    'ethereum': 'https://mainnet.infura.io/v3/YOUR_PROJECT_ID',
    'base': 'https://mainnet.base.org',
    'arbitrum': 'https://arb1.arbitrum.io/rpc'
}

# ❌ INSECURE: HTTP URLs are rejected
# ❌ INSECURE: Untrusted domains are rejected
# ❌ INSECURE: Localhost/internal IPs blocked in production
```

### Development vs Production

```python
# Set environment to allow development-only features
os.environ['EAS_ENVIRONMENT'] = 'development'  # Allows localhost RPC
os.environ['EAS_ENVIRONMENT'] = 'production'   # Strict security (default)
```

### Logging Security

```python
from EAS.security import SecureEnvironmentValidator

# All sensitive data is automatically sanitized in logs
logger.info(
    "transaction_submitted",
    from_account=SecureEnvironmentValidator.sanitize_for_logging(address, "address"),
    tx_hash=SecureEnvironmentValidator.sanitize_for_logging(tx_hash, "transaction_hash")
)

# Output: from_account=0x1234...7890, tx_hash=0xabcdef12...567890
# Private keys are always redacted: [PRIVATE_KEY_REDACTED]
```

### Error Handling with Security Context

```python
from EAS.core import EAS
from EAS.security import SecurityError
from EAS.config import get_network_config

try:
    # Security validation happens automatically
    eas = EAS.from_chain('ethereum', private_key, account)
except SecurityError as e:
    # Handle security validation failures
    logging.error(f"Security validation failed: {e}")
    # Don't expose sensitive details to users
    raise ValueError("Configuration validation failed")
except ValueError as e:
    # Handle general configuration errors
    print(f"Error: {e}")

try:
    config = get_network_config('ethereum')
except SecurityError as e:
    logging.error(f"Network configuration security error: {e}")
    raise ValueError("Invalid network configuration")
```

## 🛡️ Error Handling

The multi-chain system includes comprehensive error handling with security awareness:

```python
from EAS.core import EAS
from EAS.security import SecurityError

try:
    eas = EAS.from_chain('invalid_chain', private_key, account)
except ValueError as e:
    print(f"Error: {e}")
    # Output includes list of supported chains

try:
    eas = EAS.from_chain('ethereum', 'weak-key', account)  
except SecurityError as e:
    logging.error(f"Security validation failed: {e}")
    # Handle security errors without exposing details

try:
    eas = EAS.from_environment()
except ValueError as e:
    print(f"Environment error: {e}")
    # Output lists missing environment variables
```

## 🔧 Advanced Usage

### Multi-Chain Application

```python
from EAS.core import EAS

# Dictionary of EAS instances for different chains
eas_instances = {}

chains = ['ethereum', 'base', 'arbitrum', 'optimism', 'polygon']
for chain in chains:
    eas_instances[chain] = EAS.from_chain(
        chain_name=chain,
        private_key=private_key,
        from_account=from_account
    )

# Use different instances for different chains
ethereum_eas = eas_instances['ethereum']
base_eas = eas_instances['base']

# Create attestations on different chains
ethereum_attestation = ethereum_eas.create_attestation(...)
base_attestation = base_eas.create_attestation(...)
```

### Custom Configuration

```python
from EAS.core import EAS

# Use custom RPC providers for better performance
custom_rpcs = {
    'ethereum': 'https://eth-mainnet.alchemyapi.io/v2/your-api-key',
    'base': 'https://base-mainnet.blastapi.io/your-project-id',
    'arbitrum': 'https://arb-mainnet.g.alchemy.com/v2/your-api-key'
}

for chain, rpc_url in custom_rpcs.items():
    eas = EAS.from_chain(
        chain_name=chain,
        private_key=private_key,
        from_account=from_account,
        rpc_url=rpc_url
    )
```

## 📊 Contract Addresses Reference

| Chain | Chain ID | Contract Address | Schema Registry |
|-------|----------|------------------|-----------------|
| Ethereum | 1 | `0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587` | `0xA7b39296258348C78294F95B872b282326A97BDF` |
| Base | 8453 | `0x4200000000000000000000000000000000000021` | `0x4200000000000000000000000000000000000020` |
| Arbitrum | 42161 | `0xbD75f629A22Dc1ceD33dDA0b68c546A1c035c458` | `0xA310da9c5B885E7fb3fbA9D66E9Ba6Df512b78eB` |
| Optimism | 10 | `0x4E0275Ea5a89e7a3c1B58411379D1a0eDdc5b088` | `0x8250f4aF4B972684F7b336503E2D6dFeDeB1487a` |
| Polygon | 137 | `0x5E634ef5355f45A855d02D66eCD687b1502AF790` | `0x7876EEF51A891E737AF8ba5A5E0f0Fd29073D5a7` |
| Sepolia | 11155111 | `0xC2679fBD37d54388Ce493F1DB75320D236e1815e` | `0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0` |

*All contract addresses verified from official EAS documentation*

## ✨ Benefits

- **🌐 Multi-Chain Support**: Support for 12+ blockchain networks
- **🔒 Enterprise Security**: Comprehensive security validation against common attack vectors
- **🛡️ Input Validation**: Protection against environment variable injection and malicious inputs
- **🔑 Cryptographic Validation**: Private key strength verification and weak key detection
- **🌐 RPC Security**: HTTPS-only trusted provider allowlist prevents SSRF attacks
- **🏭 Factory Methods**: Easy instantiation with `from_chain()` and `from_environment()`
- **📝 Secure Logging**: Automatic sanitization prevents information disclosure
- **🔧 Automatic Resolution**: Contract addresses resolved automatically with integrity verification
- **🔄 Backward Compatible**: Existing code continues to work with added security
- **⚡ Type Safe**: Full type hints and proper documentation
- **🌍 Environment Support**: Secure configuration via environment variables
- **🎯 Production Ready**: Security-hardened and validated for production use

## 🚀 Getting Started

1. **Import the EAS class:**
   ```python
   from EAS.core import EAS
   ```

2. **Choose your chain:**
   ```python
   # List available chains
   from EAS.config import list_supported_chains
   print(list_supported_chains())
   ```

3. **Create EAS instance:**
   ```python
   eas = EAS.from_chain('ethereum', private_key, from_account)
   ```

4. **Start building:**
   ```python
   # Your existing EAS code works unchanged
   attestation = eas.create_attestation(...)
   ```

The EAS Python SDK provides seamless multi-chain support while maintaining full backward compatibility. Start building cross-chain attestation applications today!