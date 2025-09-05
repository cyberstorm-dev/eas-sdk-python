# Attestation Data Converter

A clean, principled system for converting EAS (Ethereum Attestation Service) attestation data from various formats into strongly-typed objects using user-provided conversion strategies.

## Overview

This module addresses Issue #30 by providing typed parsing of `decodedDataJson` from EAS GraphQL responses. The design emphasizes:

- **Lambda-based conversion**: Users provide conversion functions for maximum flexibility
- **Multiple data sources**: Supports both GraphQL JSON and raw hex data  
- **Type safety**: Generic typing ensures compile-time safety
- **Clean separation**: No dependencies on specific target types (protobuf, etc.)
- **Fail-fast**: Clear error boundaries and validation

## Architecture

### Core Components

1. **`AttestationConverter<T>`** - Generic converter that applies user-provided conversion functions
2. **`AttestationData` Protocol** - Interface for different data source formats
3. **`GraphQLAttestationData`** - Handles EAS GraphQL `decodedDataJson` format  
4. **`HexAttestationData`** - Handles raw hex attestation data with schema
5. **Utility converters** - Pre-built converters for common patterns

### Data Flow

```
GraphQL JSON ──┐
               ├──► AttestationConverter ──► User's Target Type
Raw Hex Data ──┘       ^
                       │
               User-Provided Lambda
```

## Usage Examples

### Basic GraphQL Conversion

```python
from src.main.EAS.attestation_converter import AttestationConverter, from_graphql_json

# Simple field extraction
converter = AttestationConverter(lambda data: data["domain"].upper())

json_data = from_graphql_json('[{"name": "domain", "value": "github.com"}]')
result = converter.convert(json_data)  # Returns: "GITHUB.COM"
```

### Real Cyberstorm Identity Conversion

```python
from dataclasses import dataclass
from src.main.EAS.attestation_converter import AttestationConverter, from_graphql_json

@dataclass
class Identity:
    domain: str
    identifier: str
    registrant: str

# Real data from base-sepolia attestation 0xdc2edaf...
real_graphql_data = '''[
    {"name": "domain", "type": "string", "value": "github.com"},
    {"name": "identifier", "type": "string", "value": "alice"}, 
    {"name": "registrant", "type": "address", "value": "0xa11CE9cF23bDDF504871Be93A2d257D200c05649"}
]'''

# Convert to strongly-typed Identity
identity_converter = AttestationConverter(
    lambda data: Identity(
        domain=data.get("domain", ""),
        identifier=data.get("identifier", ""), 
        registrant=data.get("registrant", "")
    )
)

data = from_graphql_json(real_graphql_data)
identity = identity_converter.convert(data)

print(f"Identity: {identity.domain}/{identity.identifier}")
# Output: Identity: github.com/alice
```

### Multiple Data Sources

```python
from src.main.EAS.attestation_converter import AttestationConverter, from_graphql_json, from_hex

# Same converter works with any data source
converter = AttestationConverter(
    lambda data: f"{data['domain']}/{data['identifier']}"
)

# GraphQL source
graphql_data = from_graphql_json('[{"name": "domain", "value": "github.com"}]')
result1 = converter.convert(graphql_data)

# Hex source (when hex parsing is fully implemented)
hex_data = from_hex("0x123abc...", "string domain,string identifier") 
result2 = converter.convert(hex_data)

# Both produce same result
assert result1 == result2
```

### Advanced Conversion with Validation

```python
from src.main.EAS.converters import ValidatingConverter

class IdentityConverter(ValidatingConverter):
    def __init__(self):
        super().__init__(
            required_fields={"domain", "identifier"},
            optional_fields={"registrant", "proof_url"}
        )
    
    def convert_validated(self, data):
        return Identity(
            domain=data["domain"],
            identifier=data["identifier"],
            registrant=data.get("registrant", "")
        )

# Converter will validate required fields before conversion
converter = AttestationConverter(IdentityConverter())
```

### Utility Converters

```python
from src.main.EAS.converters import (
    field_extractor, 
    dict_converter,
    filtering_converter,
    transforming_converter
)

# Extract single field
domain_extractor = field_extractor("domain", "unknown")
domain = domain_extractor.convert(data)

# Get raw dictionary
raw_converter = dict_converter()
raw_data = raw_converter.convert(data)

# Filter to specific fields only  
filtered_converter = filtering_converter({"domain", "identifier"})
filtered_data = filtered_converter.convert(data)

# Transform field values
transform_converter = transforming_converter({
    "domain": str.upper,
    "identifier": str.lower
})
transformed_data = transform_converter.convert(data)
```

## Error Handling

The system is designed to fail fast with clear error messages:

```python
# Invalid JSON
try:
    data = from_graphql_json("invalid json")
    result = converter.convert(data)
except ValueError as e:
    print(f"Parsing error: {e}")

# Missing required fields (with ValidatingConverter)
try:
    data = from_graphql_json('[{"name": "domain", "value": "github.com"}]') # Missing identifier
    result = validating_converter.convert(data)
except ValueError as e:
    print(f"Validation error: {e}")  # "Missing required fields: {'identifier'}"

# Converter exceptions are propagated
def failing_converter(data):
    raise RuntimeError("Business logic error")

converter = AttestationConverter(failing_converter)
# RuntimeError will be raised, not swallowed
```

## Full GraphQL to Protobuf Pipeline

Here's a complete example showing the full pipeline from GraphQL query to final protobuf message with EAS metadata:

```python
from src.main.EAS.attestation_converter import AttestationConverter, from_graphql_json
from src.main.EAS.generated.eas.v1.messages_pb2 import Attestation
from your_pb2 import Identity  # Your compiled protobuf from tests/fixtures

# 1. Simulate GraphQL response (in practice, this comes from your EAS GraphQL client)
graphql_response = {
    "data": {
        "attestation": {
            "id": "0xdc2edaf99444585bc3e5294a127fe1e02a0f6ae41acd808213c23eb064250f0a",
            "schemaId": "0xb9ed8e12969c41616868a07201ce0fb3528fac320c3cbc0409ae1b0df5e48ae0", 
            "attester": "0x0E9A64F1822b18bB17AfA81035d706F0F4148bD9",
            "recipient": "0xa11CE9cF23bDDF504871Be93A2d257D200c05649",
            "time": 1725463790,
            "revocable": True,
            "data": "0x123abc...",  # Raw hex data
            "decodedDataJson": '''[
                {"name": "domain", "type": "string", "value": "github.com"},
                {"name": "identifier", "type": "string", "value": "alice"},
                {"name": "registrant", "type": "address", "value": "0xa11CE9cF23bDDF504871Be93A2d257D200c05649"},
                {"name": "proof_url", "type": "string", "value": "https://gist.githubusercontent.com/alice/45d377c67a76b2a33db7d213a47e54ba/raw/5eb3f18675f06125989d3b41fe9c22440c923e0a/cyberstorm-identity-registration.txt"},
                {"name": "attestor", "type": "address", "value": "0x0E9A64F1822b18bB17AfA81035d706F0F4148bD9"}
            ]'''
        }
    }
}

# 2. Create converter that builds complete Identity with EAS metadata
def create_full_identity_converter():
    def convert(data):
        return Identity(
            domain=data.get("domain", ""),
            identifier=data.get("identifier", ""),
            registrant=data.get("registrant", ""),
            proof_url=data.get("proof_url", ""),
            attestor=data.get("attestor", ""),
            # Convert hex signatures to bytes if present
            registrant_signature=bytes.fromhex(data.get("registrant_signature", "")[2:]) if data.get("registrant_signature", "").startswith("0x") else b"",
            attestor_signature=bytes.fromhex(data.get("attestor_signature", "")[2:]) if data.get("attestor_signature", "").startswith("0x") else b"",
            # Include EAS attestation metadata
            eas_attestation=Attestation(
                id=graphql_response["data"]["attestation"]["id"],
                schema_id=graphql_response["data"]["attestation"]["schemaId"], 
                attester=graphql_response["data"]["attestation"]["attester"],
                recipient=graphql_response["data"]["attestation"]["recipient"],
                time=graphql_response["data"]["attestation"]["time"],
                revocable=graphql_response["data"]["attestation"]["revocable"],
                data=graphql_response["data"]["attestation"]["data"]
            )
        )
    return convert

# 3. Execute the full conversion pipeline
converter = AttestationConverter(create_full_identity_converter())
attestation_data = from_graphql_json(graphql_response["data"]["attestation"]["decodedDataJson"])
complete_identity = converter.convert(attestation_data)

# 4. Result: Complete strongly-typed Identity protobuf with all data
print(f"Identity: {complete_identity.domain}/{complete_identity.identifier}")
print(f"Proof URL: {complete_identity.proof_url}")
print(f"EAS Attestation ID: {complete_identity.eas_attestation.id}")
print(f"Attestation Time: {complete_identity.eas_attestation.time}")
print(f"Is Revocable: {complete_identity.eas_attestation.revocable}")

# Full type safety - IDE autocomplete works perfectly
assert complete_identity.domain == "github.com"
assert complete_identity.identifier == "alice"  
assert complete_identity.eas_attestation.schema_id.startswith("0x")
```

This demonstrates the complete inversion: from raw GraphQL response to fully-typed protobuf message with both the decoded attestation data AND the EAS metadata - exactly what Issue #30 requested!

## Testing

Comprehensive tests cover:
- GraphQL JSON parsing (various formats)
- Error handling and validation  
- Converter functionality
- Real attestation data from blockchain
- Factory functions and utilities

Run tests with:
```bash
python -m pytest tests/test_attestation_converter.py -v
```

## Design Benefits

### For Issue #30 Requirements

✅ **Type safety**: Get strongly-typed objects instead of raw dicts  
✅ **Schema validation**: User-controlled validation in converter functions  
✅ **Reusability**: Same converter works with any schema/target combination  
✅ **Maintainability**: Centralized parsing logic, clear separation of concerns

### Architectural Improvements

✅ **No magic assumptions**: Users control field mapping completely  
✅ **Extensible**: Easy to add new data sources via the Protocol interface  
✅ **Testable**: All dependencies are injected, converters are pure functions  
✅ **Fail-fast**: Clear error boundaries, no silent failures  
✅ **Type-agnostic**: Works with any target type, not just protobuf

## Comparison to Original Proposal

| Original Proposal | This Implementation |
|------------------|-------------------|
| Generic field mapping assumptions | User-controlled conversion logic |
| Single function approach | Composable converter classes |
| Magic field name matching | Explicit field handling |
| Protobuf-specific | Type-agnostic |
| Inflexible | Highly flexible via lambdas |

## Future Enhancements

- Complete hex parsing implementation for complex types
- Schema registry for caching parsed schemas
- Performance optimizations for large datasets
- Integration with EAS GraphQL client
- More pre-built converter utilities