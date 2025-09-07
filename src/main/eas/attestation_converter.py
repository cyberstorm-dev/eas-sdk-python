"""
Clean, principled attestation data conversion system.

Converts attestation data from various formats (hex, GraphQL JSON) to strongly-typed
protobuf messages using user-provided conversion strategies.
"""

import json
import re
from typing import Any, Callable, Dict, Generic, List, Protocol, TypeVar

from web3 import Web3

from .type_parser import EASType, EASTypeParser

T = TypeVar("T")


class AttestationData(Protocol):
    """Protocol for different attestation data formats."""

    def to_dict(self) -> Dict[str, Any]:
        """Convert attestation data to normalized dictionary format."""
        ...


class HexAttestationData:
    """Raw hex attestation data with schema definition."""

    def __init__(self, hex_data: str, schema_definition: str):
        self.hex_data = hex_data
        self.schema_definition = schema_definition

    def to_dict(self) -> Dict[str, Any]:
        """Parse hex attestation data according to schema."""
        return parse_hex_attestation_data(self.hex_data, self.schema_definition)


class GraphQLAttestationData:
    """GraphQL decodedDataJson attestation data."""

    def __init__(self, decoded_json: str):
        self.decoded_json = decoded_json

    def to_dict(self) -> Dict[str, Any]:
        """Parse GraphQL decodedDataJson to normalized format."""
        fields = json.loads(self.decoded_json)
        if not isinstance(fields, list):
            raise ValueError("GraphQL decodedDataJson must be a list of field objects")

        result = {}
        for field in fields:
            if (
                not isinstance(field, dict)
                or "name" not in field
                or "value" not in field
            ):
                raise ValueError("Invalid GraphQL field format")

            name = field["name"]
            value_obj = field["value"]

            # Handle nested value structure
            if isinstance(value_obj, dict) and "value" in value_obj:
                value = value_obj["value"]
            else:
                value = value_obj

            result[name] = value

        return result


class AttestationConverter(Generic[T]):
    """Converts attestation data to target type using injected conversion strategy."""

    def __init__(self, converter: Callable[[Dict[str, Any]], T]):
        """
        Initialize with conversion function.

        Args:
            converter: Function that takes normalized dict and returns target type
        """
        self._converter = converter

    def convert(self, data: AttestationData) -> T:
        """
        Convert attestation data to target type.

        Args:
            data: Attestation data in any supported format

        Returns:
            Converted data as target type

        Raises:
            ValueError: If data format is invalid
            Exception: Any exception from converter function
        """
        normalized_data = data.to_dict()
        return self._converter(normalized_data)


# Factory functions for clean API
def from_hex(hex_data: str, schema_definition: str) -> HexAttestationData:
    """
    Create attestation data from hex and schema.

    Args:
        hex_data: Hex-encoded attestation data (with or without 0x prefix)
        schema_definition: EAS schema definition string

    Returns:
        HexAttestationData instance
    """
    return HexAttestationData(hex_data, schema_definition)


def from_graphql_json(decoded_json: str) -> GraphQLAttestationData:
    """
    Create attestation data from GraphQL decodedDataJson.

    Args:
        decoded_json: JSON string from GraphQL decodedDataJson field

    Returns:
        GraphQLAttestationData instance
    """
    return GraphQLAttestationData(decoded_json)


# Clean hex parsing implementation (refactored from deleted data_parser.py)
def parse_hex_attestation_data(data_hex: str, schema_definition: str) -> Dict[str, Any]:
    """
    Parse hex attestation data according to schema definition.

    Args:
        data_hex: Hex-encoded attestation data
        schema_definition: EAS schema definition string

    Returns:
        Dictionary containing parsed field values

    Raises:
        ValueError: If hex data is invalid or insufficient for schema
    """
    # Parse schema definition
    fields = EASTypeParser.parse_schema_definition(schema_definition)

    # Clean hex string
    if data_hex.startswith("0x"):
        data_hex = data_hex[2:]

    # Convert to bytes
    try:
        data_bytes = bytes.fromhex(data_hex)
    except ValueError as e:
        raise ValueError(f"Invalid hex data: {e}")

    # Parse fields according to schema
    result = {}
    offset = 0

    for field in fields:
        try:
            value, new_offset = _parse_field_value(data_bytes, offset, field.type)
            result[field.name] = value
            offset = new_offset
        except Exception as e:
            raise ValueError(f"Failed to parse field '{field.name}': {e}")

    return result


def _parse_field_value(
    data_bytes: bytes, offset: int, field_type: EASType
) -> tuple[Any, int]:
    """Parse a single field value from bytes."""
    base_type = field_type.base_type
    is_array = field_type.is_array
    dimensions = field_type.dimensions

    if base_type == "address":
        return (
            _parse_address_array(data_bytes, offset, dimensions)
            if is_array
            else _parse_address(data_bytes, offset)
        )
    elif base_type == "string":
        return (
            _parse_string_array(data_bytes, offset, dimensions)
            if is_array
            else _parse_string(data_bytes, offset)
        )
    elif base_type == "bool":
        return (
            _parse_bool_array(data_bytes, offset, dimensions)
            if is_array
            else _parse_bool(data_bytes, offset)
        )
    elif base_type.startswith(("uint", "int")):
        return (
            _parse_integer_array(data_bytes, offset, field_type, dimensions)
            if is_array
            else _parse_integer(data_bytes, offset, field_type)
        )
    elif base_type.startswith("bytes"):
        return (
            _parse_bytes_array(data_bytes, offset, field_type, dimensions)
            if is_array
            else _parse_bytes(data_bytes, offset, field_type)
        )
    else:
        raise ValueError(f"Unsupported field type: {base_type}")


def _parse_address(data_bytes: bytes, offset: int) -> tuple[str, int]:
    """Parse an address field."""
    if offset + 32 > len(data_bytes):
        raise ValueError("Insufficient data for address")

    address_bytes = data_bytes[offset : offset + 32]
    address = Web3.to_checksum_address(address_bytes[-20:])
    return address, offset + 32


def _parse_address_array(
    data_bytes: bytes, offset: int, dimensions: List[int]
) -> tuple[List[str], int]:
    """Parse an address array field."""
    if not dimensions:
        # Dynamic array
        array_offset = int.from_bytes(data_bytes[offset : offset + 32], "big")
        length = int.from_bytes(data_bytes[array_offset : array_offset + 32], "big")

        addresses = []
        current_offset = array_offset + 32
        for _ in range(length):
            address, current_offset = _parse_address(data_bytes, current_offset)
            addresses.append(address)

        return addresses, offset + 32
    else:
        # Fixed-size array
        addresses = []
        current_offset = offset
        for _ in range(dimensions[0]):
            address, current_offset = _parse_address(data_bytes, current_offset)
            addresses.append(address)

        return addresses, current_offset


def _parse_string(data_bytes: bytes, offset: int) -> tuple[str, int]:
    """Parse a string field."""
    if offset + 32 > len(data_bytes):
        raise ValueError("Insufficient data for string offset")

    string_offset = int.from_bytes(data_bytes[offset : offset + 32], "big")
    length = int.from_bytes(data_bytes[string_offset : string_offset + 32], "big")

    string_data = data_bytes[string_offset + 32 : string_offset + 32 + length]
    string_value = string_data.decode("utf-8")

    return string_value, offset + 32


def _parse_string_array(
    data_bytes: bytes, offset: int, dimensions: List[int]
) -> tuple[List[str], int]:
    """Parse a string array field."""
    if not dimensions:
        # Dynamic array
        array_offset = int.from_bytes(data_bytes[offset : offset + 32], "big")
        length = int.from_bytes(data_bytes[array_offset : array_offset + 32], "big")

        strings = []
        current_offset = array_offset + 32
        for _ in range(length):
            string, current_offset = _parse_string(data_bytes, current_offset)
            strings.append(string)

        return strings, offset + 32
    else:
        # Fixed-size array
        strings = []
        current_offset = offset
        for _ in range(dimensions[0]):
            string, current_offset = _parse_string(data_bytes, current_offset)
            strings.append(string)

        return strings, current_offset


def _parse_bool(data_bytes: bytes, offset: int) -> tuple[bool, int]:
    """Parse a boolean field."""
    if offset + 32 > len(data_bytes):
        raise ValueError("Insufficient data for boolean")

    bool_bytes = data_bytes[offset : offset + 32]
    bool_value = bool(int.from_bytes(bool_bytes, "big"))
    return bool_value, offset + 32


def _parse_bool_array(
    data_bytes: bytes, offset: int, dimensions: List[int]
) -> tuple[List[bool], int]:
    """Parse a boolean array field."""
    if not dimensions:
        # Dynamic array
        array_offset = int.from_bytes(data_bytes[offset : offset + 32], "big")
        length = int.from_bytes(data_bytes[array_offset : array_offset + 32], "big")

        bools = []
        current_offset = array_offset + 32
        for _ in range(length):
            bool_val, current_offset = _parse_bool(data_bytes, current_offset)
            bools.append(bool_val)

        return bools, offset + 32
    else:
        # Fixed-size array
        bools = []
        current_offset = offset
        for _ in range(dimensions[0]):
            bool_val, current_offset = _parse_bool(data_bytes, current_offset)
            bools.append(bool_val)

        return bools, current_offset


def _parse_integer(
    data_bytes: bytes, offset: int, field_type: EASType
) -> tuple[int, int]:
    """Parse an integer field."""
    base_type = field_type.base_type

    # Extract bit size
    if base_type.startswith("uint"):
        bit_size = int(base_type[4:])
    elif base_type.startswith("int"):
        bit_size = int(base_type[3:])
    else:
        raise ValueError(f"Invalid integer type: {base_type}")

    # ABI encoding uses 32-byte slots
    byte_size = 32

    if offset + byte_size > len(data_bytes):
        raise ValueError(f"Insufficient data for {base_type}")

    value_bytes = data_bytes[offset : offset + byte_size]
    value = int.from_bytes(value_bytes, "big")

    # Handle signed integers (two's complement)
    if base_type.startswith("int"):
        max_value = 2 ** (bit_size - 1)
        if value >= max_value:
            value = value - (2**bit_size)

    return value, offset + byte_size


def _parse_integer_array(
    data_bytes: bytes, offset: int, field_type: EASType, dimensions: List[int]
) -> tuple[List[int], int]:
    """Parse an integer array field."""
    if not dimensions:
        # Dynamic array
        array_offset = int.from_bytes(data_bytes[offset : offset + 32], "big")
        length = int.from_bytes(data_bytes[array_offset : array_offset + 32], "big")

        integers = []
        current_offset = array_offset + 32
        for _ in range(length):
            integer, current_offset = _parse_integer(
                data_bytes, current_offset, field_type
            )
            integers.append(integer)

        return integers, offset + 32
    else:
        # Fixed-size array
        integers = []
        current_offset = offset
        for _ in range(dimensions[0]):
            integer, current_offset = _parse_integer(
                data_bytes, current_offset, field_type
            )
            integers.append(integer)

        return integers, current_offset


def _parse_bytes(
    data_bytes: bytes, offset: int, field_type: EASType
) -> tuple[str, int]:
    """Parse a bytes field."""
    base_type = field_type.base_type

    if base_type == "bytes":
        # Dynamic bytes
        bytes_offset = int.from_bytes(data_bytes[offset : offset + 32], "big")
        length = int.from_bytes(data_bytes[bytes_offset : bytes_offset + 32], "big")
        bytes_data = data_bytes[bytes_offset + 32 : bytes_offset + 32 + length]
        return bytes_data.hex(), offset + 32
    else:
        # Fixed-size bytes (e.g., bytes32)
        match = re.match(r"bytes(\d+)", base_type)
        if not match:
            raise ValueError(f"Invalid bytes type: {base_type}")

        size = int(match.group(1))
        if offset + size > len(data_bytes):
            raise ValueError(f"Insufficient data for {base_type}")

        bytes_data = data_bytes[offset : offset + size]
        return bytes_data.hex(), offset + size


def _parse_bytes_array(
    data_bytes: bytes, offset: int, field_type: EASType, dimensions: List[int]
) -> tuple[List[str], int]:
    """Parse a bytes array field."""
    if not dimensions:
        # Dynamic array
        array_offset = int.from_bytes(data_bytes[offset : offset + 32], "big")
        length = int.from_bytes(data_bytes[array_offset : array_offset + 32], "big")

        bytes_list = []
        current_offset = array_offset + 32
        for _ in range(length):
            bytes_data, current_offset = _parse_bytes(
                data_bytes, current_offset, field_type
            )
            bytes_list.append(bytes_data)

        return bytes_list, offset + 32
    else:
        # Fixed-size array
        bytes_list = []
        current_offset = offset
        for _ in range(dimensions[0]):
            bytes_data, current_offset = _parse_bytes(
                data_bytes, current_offset, field_type
            )
            bytes_list.append(bytes_data)

        return bytes_list, current_offset
