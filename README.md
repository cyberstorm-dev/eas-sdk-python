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