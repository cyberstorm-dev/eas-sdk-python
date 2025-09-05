# EAS SDK Integration Guide

This guide demonstrates the complete workflow for working with EAS attestations using protobuf encoding.

## Example: Repository Registration Attestation

We'll work with attestation `0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed` as our example.

### Step 1: Look up the attestation

First, let's examine the attestation to understand its structure:

```bash
eas-tools show-attestation 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --network base-sepolia
```

This will show us that the attestation uses schema `0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01`.

### Step 2: Generate protobuf definition

Generate the protobuf definition for the schema:

```bash
eas-tools generate-schema 0x2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 --format proto --network base-sepolia
```

This outputs something like:
```protobuf
message message_2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 {
  string domain = 1;
  string path = 2;
  string registrant = 3;
  string proofUrl = 4;
  string validator = 5;
  string registrantSignature = 6;
  string validatorSignature = 7;
}
```

### Step 3: Create custom protobuf file

Create the directory structure and file `src/proto/repository/v1/repository.proto` with both the default message and a custom-named message:

```bash
mkdir -p src/proto/repository/v1
```

```protobuf
syntax = "proto3";

package repository.v1;

// Default message name (auto-generated)
message message_2d0c6308e44797efaad90e4d1402391da661cd884c453d32373d0aa088b66a01 {
  string domain = 1;
  string path = 2;
  string registrant = 3;
  string proofUrl = 4;
  string validator = 5;
  bytes registrantSignature = 6;
  bytes validatorSignature = 7;
}

// Custom message name (more meaningful)
message RepositoryRegistration {
  string domain = 1;
  string path = 2;
  string registrant = 3;
  string proofUrl = 4;
  string validator = 5;
  bytes registrantSignature = 6;
  bytes validatorSignature = 7;
}
```

### Step 4: Generate Python protobuf files

Compile the protobuf definition to Python:

```bash
protoc --python_out=src/main/EAS/generated/ --proto_path=src/proto src/proto/repository/v1/repository.proto
```

This creates `src/main/EAS/generated/repository/v1/repository_pb2.py` containing both message classes.

**Note**: The directory structure `src/proto/repository/v1/` generates `src/main/EAS/generated/repository/v1/repository_pb2.py`, which matches the expected module path for namespace `repository.v1`.

### Step 5: Encode using default message name

Now we can encode the attestation data using the default message name by specifying the namespace:

```bash
eas-tools encode-schema 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --format json --network base-sepolia --namespace repository.v1
```

This will output the parsed attestation data as JSON:
```json
{
  "domain": "github.com",
  "path": "/cyberstorm-dev/test-repo",
  "registrant": "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD",
  "proofUrl": "https://github.com/cyberstorm-dev/test-repo",
  "validator": "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD",
  "registrantSignature": "a7ed1c8919c3140b04025b23a78e08c1a51aa61d767519d17067affb7fb57f8647f3f0d051285dc32d9d4e7ce4c5d1caf10d29fa7186729c69fc07848d0ec0e11c",
  "validatorSignature": "2dffd2e13afcd3dbe7d99db4c3abcff98c0dc73917915d3e8108846ba21ec1591d699dfc7d6a0062cd610500f8907ebdca124ccb4b809045ade02c9c83f1fa761b"
}
```

### Step 6: Encode using custom message name

Now encode using the custom message name:

```bash
eas-tools encode-schema 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --format json --network base-sepolia --message-type repository.v1.RepositoryRegistration
```

This will output the same JSON data, but using the custom message class.

### Step 7: Protobuf encoding

You can also encode the data as protobuf in various formats:

```bash
# Base64 encoded protobuf
eas-tools encode-schema 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --format proto --encoding base64 --network base-sepolia --namespace repository.v1

# Hex encoded protobuf
eas-tools encode-schema 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --format proto --encoding hex --network base-sepolia --namespace repository.v1

# Binary protobuf (displayed as hex)
eas-tools encode-schema 0x12b4b8b2090f9bbde32db55cfc8e40ab7bda4512f6d8517226e9a9109fc9f8ed --format proto --encoding binary --network base-sepolia --namespace repository.v1
```

## Key Concepts

### Namespace Resolution

- **Default namespace**: `vendor.v1` (looks for `vendor_v1_pb2.py`)
- **Custom namespace**: `repository.v1` (looks for `repository_v1_pb2.py`)
- **Message type**: `repository.v1.RepositoryRegistration` (looks for `RepositoryRegistration` class in `repository_v1_pb2.py`)

### File Structure

```
src/main/EAS/generated/
├── __init__.py
├── eas/
│   └── v1/
│       └── messages_pb2.py            # Default EAS messages
├── repository/
│   └── v1/
│       └── repository_pb2.py          # Custom protobuf messages (namespace: repository.v1)
└── __pycache__/
```

### Workflow Summary

1. **Discover**: Use `show-attestation` to find schema ID
2. **Generate**: Use `generate-schema` to create protobuf definition
3. **Customize**: Create custom `.proto` file with meaningful message names
4. **Compile**: Use `protoc` to generate Python classes
5. **Encode**: Use `encode-schema` with namespace or message-type to encode data

This workflow provides type safety, meaningful naming, and flexible encoding options for EAS attestation data. 