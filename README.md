# Ethereum Attestation Service (EAS) SDK

## Overview

The EAS SDK is a Python library for seamlessly interacting with the Ethereum Attestation Service (EAS), enabling developers to create, manage, and verify on-chain and off-chain attestations across multiple blockchain networks.

## Features

- 🌐 Multi-chain support (Ethereum, Base, Sepolia, and more)
- 🔒 Secure environment and input validation
- 💡 Easy-to-use methods for creating attestations
- 📝 On-chain and off-chain attestation support
- 🚀 Batch attestation and revocation capabilities
- 🕒 Flexible timestamping functionality
- 🔄 Typed attestation data conversion from GraphQL to protobuf

## Installation

Install the EAS SDK using pip:

```bash
pip install eas-sdk
```

## Quick Start

### Basic Initialization

```python
from EAS import EAS

# Initialize EAS for a specific chain
eas = EAS.from_chain(
    chain='base-sepolia',
    private_key='YOUR_PRIVATE_KEY',
    from_account='YOUR_ETHEREUM_ADDRESS'
)
```

### Creating an Attestation

```python
# Register a schema first
schema_uid = eas.register_schema(
    schema="uint256 id,string name",
    network_name="base-sepolia"
)

# Create an attestation
result = eas.attest(
    schema_uid=schema_uid,
    recipient='0x1234...',
    data_values={
        'types': ['uint256', 'string'],
        'values': [42, 'John Doe']
    }
)

print(f"Attestation created: {result.tx_hash}")
```

### Off-Chain Attestation

```python
# Create an off-chain attestation
offchain_attestation = eas.attest_offchain({
    'schema': schema_uid,
    'recipient': '0x1234...',
    'data': b'Offchain data'
})
```

### Batch Operations

```python
# Batch attestation
eas.multi_attest([
    {
        'schema_uid': schema_uid,
        'attestations': [
            {
                'recipient': '0x1234...',
                'data': b'First attestation'
            },
            {
                'recipient': '0x5678...',
                'data': b'Second attestation'
            }
        ]
    }
])

# Batch revocation
eas.multi_revoke([
    {'uid': '0x...first_attestation_uid'},
    {'uid': '0x...second_attestation_uid'}
])
```

## Command Line Interface (CLI)

The EAS SDK includes a comprehensive CLI tool `eas-tools` for interacting with EAS data directly from the command line.

### Installation and Setup

After installing the SDK, the `eas-tools` command is automatically available:

```bash
pip install eas-sdk
eas-tools --help
```

### CLI Overview

The CLI is organized into logical command groups:

```bash
eas-tools [global-options] <command-group> <command> [options]
```

**Command Groups:**
- `schema` - Schema operations (view, generate code)
- `attestation` - Attestation operations (view, decode)
- `query` - Bulk search operations
- `revoke` - Revocation operations  
- `dev` - Development tools

**Global Options:**
- `--network, -n` - Network to use (mainnet, sepolia, base-sepolia, etc.)
- `--help` - Show help information
- `--version` - Show version

### Schema Commands

**View Schema Information:**
```bash
# View schema details
eas-tools -n base-sepolia schema show 0x86ad448d1844cd6d7c13cf5d8effbc70a596af78bd0a01b747e2acb5f74c6d9b

# Output formats: eas (default), json, yaml
eas-tools schema show 0x86ad... --format json
```

**Generate Code from Schema:**
```bash
# Generate TypeScript/protobuf definitions
eas-tools schema generate 0x86ad... --format proto
```

### Attestation Commands

**View Attestation Information:**
```bash
# View attestation details
eas-tools -n base-sepolia attestation show 0xceffa19c412727fa6ea41ce8f685a397d93d744c5314f19c39fa7b007a985c41

# Output formats: eas (default), json, yaml  
eas-tools attestation show 0xceff... --format json
```

**Decode Attestation Data:**
```bash
# Parse attestation data using its schema
eas-tools attestation decode 0xceff19c412727fa6ea41ce8f685a397d93d744c5314f19c39fa7b007a985c41

# Advanced decoding options
eas-tools attestation decode 0xceff... --format proto --encoding protobuf
```

### Query Commands

The query system provides powerful filtering capabilities for bulk data retrieval.

**Search Attestations:**
```bash
# Find all attestations for a schema
eas-tools -n base-sepolia query attestations --schema 0x86ad...

# Find attestations by attester/sender
eas-tools query attestations --sender 0x0E9A64...
eas-tools query attestations --attester 0x0E9A64...  # same as --sender

# Find attestations for a recipient  
eas-tools query attestations --recipient 0x742D35...

# Filter by status
eas-tools query attestations --active          # non-revoked attestations
eas-tools query attestations --revoked         # revoked attestations
eas-tools query attestations --revocable       # revocable attestations
eas-tools query attestations --expired         # expired attestations

# Time-based filtering (Unix timestamps)
eas-tools query attestations --expires-before 1735689600
eas-tools query attestations --expires-after 1735689600
eas-tools query attestations --created-after 1726147200

# Combine filters
eas-tools query attestations --sender 0x0E9A64... --active --revocable

# Pagination and output
eas-tools query attestations --limit 50 --offset 100 --format json
```

**Search Schemas:**
```bash
# Find schemas by creator
eas-tools query schemas --creator 0x1234...

# Filter by properties
eas-tools query schemas --revocable
eas-tools query schemas --resolvable       # schemas with resolver contracts

# Time-based filtering
eas-tools query schemas --created-after 1726147200

# Output options
eas-tools query schemas --format json --limit 25
```

### Revocation Commands

The revoke command allows you to revoke attestations directly from the CLI.

**Basic Revocation:**
```bash
# Revoke using environment variables for credentials
export EAS_PRIVATE_KEY=0x1234...
export EAS_CHAIN=base-sepolia
eas-tools revoke 0xceff19c412727fa6ea41ce8f685a397d93d744c5314f19c39fa7b007a985c41

# Revoke using command line options
eas-tools -n base-sepolia revoke 0xceff... --private-key 0x1234...

# Dry run to preview transaction
eas-tools revoke 0xceff... --dry-run
```

**Environment Variables for Revocation:**
```bash
export EAS_PRIVATE_KEY=your_private_key
export EAS_FROM_ACCOUNT=your_address  # optional, derived from private key
export EAS_CHAIN=base-sepolia
```

**Error Handling:**
The CLI provides user-friendly error messages for common contract errors:
- "The attestation has already been revoked"
- "Access denied - you don't have permission to revoke this attestation"  
- "Invalid attestation - the attestation UID doesn't exist or is malformed"
- "This attestation is not revocable"

### Development Commands

**List Supported Networks:**
```bash
# Show all supported networks
eas-tools dev chains

# Filter by network type
eas-tools dev chains --mainnet
eas-tools dev chains --testnet
```

**Development Environment:**
```bash
# Set up development environment
eas-tools dev setup

# Interactive Python shell with EAS SDK
eas-tools dev shell

# Run tests
eas-tools dev test
```

### Real-World Examples

**Find and Revoke Your Own Attestations:**
```bash
# 1. Find your active attestations
eas-tools -n base-sepolia query attestations --sender 0xYourAddress... --active --format json

# 2. Revoke a specific attestation
eas-tools -n base-sepolia revoke 0xAttestationUID... --private-key 0xYourKey...
```

**Analyze a Schema:**
```bash
# 1. View schema structure
eas-tools schema show 0xSchemaUID... --format yaml

# 2. Find all attestations using this schema
eas-tools query attestations --schema 0xSchemaUID... --format json

# 3. Generate code definitions
eas-tools schema generate 0xSchemaUID... --format proto
```

**Monitor Attestation Activity:**
```bash
# Find recent attestations (last 24 hours)
YESTERDAY=$(date -d '1 day ago' +%s)
eas-tools query attestations --created-after $YESTERDAY --format table

# Find expiring attestations (next 30 days)  
MONTH_FROM_NOW=$(date -d '30 days' +%s)
eas-tools query attestations --expires-before $MONTH_FROM_NOW --format json
```

### Network Support

The CLI supports all EAS networks:

- `mainnet` - Ethereum Mainnet
- `sepolia` - Ethereum Sepolia Testnet  
- `base` - Base Mainnet
- `base-sepolia` - Base Sepolia Testnet
- `optimism` - Optimism Mainnet
- `arbitrum` - Arbitrum One
- `polygon` - Polygon Mainnet

Use the `--network` or `-n` flag with any command:

```bash
eas-tools -n mainnet query attestations --sender 0x...
eas-tools -n base-sepolia revoke 0x...
```

## Configuration

### Environment Variables

You can also configure EAS using environment variables:

```bash
export EAS_CHAIN=base-sepolia
export EAS_PRIVATE_KEY=your_private_key
export EAS_FROM_ACCOUNT=your_ethereum_address
```

Then initialize EAS without parameters:

```python
eas = EAS.from_environment()
```

## Advanced Configuration

### Custom Network Support

```python
# Use a custom RPC endpoint and contract address
eas = EAS.from_chain(
    chain='custom_network',
    private_key='your_private_key',
    from_account='your_address',
    rpc_url='https://custom-rpc.network',
    contract_address='0x..custom_contract_address'
)
```

## Supported Chains

```python
# List all supported chains
print(EAS.list_supported_chains())

# Get configuration for a specific chain
base_config = EAS.get_network_config('base')
```

## Security Features

- Input validation for all parameters
- Secure environment variable handling
- Comprehensive error logging
- Contract address validation

## Attestation Data Conversion

Convert EAS attestation data from GraphQL responses to strongly-typed protobuf messages:

```python
from src.main.EAS.attestation_converter import AttestationConverter, from_graphql_json

# Convert GraphQL decodedDataJson to typed objects
converter = AttestationConverter(
    lambda data: YourProtobufType(
        domain=data.get("domain", ""),
        identifier=data.get("identifier", "")
    )
)

graphql_data = from_graphql_json('your_decoded_data_json')
typed_result = converter.convert(graphql_data)
```

For detailed usage examples and advanced patterns, see [Attestation Converter Documentation](docs/attestation_converter.md).

## Error Handling

The SDK provides detailed exceptions:

- `EASValidationError`: Input validation failures
- `EASTransactionError`: Blockchain interaction problems
- `SecurityError`: Security-related issues

## Performance Considerations

- Uses gas estimation with a 20% buffer
- Supports batch operations for gas efficiency
- Provides fallback mechanisms for gas estimation

## Contribution

Contributions are welcome! Please read our [Contribution Guidelines](CONTRIBUTING.md) before submitting a pull request.

## License

[Insert your project's license here]

## Support

For issues, questions, or support, please file an issue on our GitHub repository.