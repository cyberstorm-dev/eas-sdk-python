"""
EAS Type Parser

A dedicated parser for Ethereum Attestation Service (EAS) schema types.
Handles complex types like int40[2][], address[], uint256[], etc.
"""

import re
from dataclasses import dataclass
from typing import List


@dataclass
class EASType:
    """Represents a parsed EAS type."""

    base_type: str  # e.g., "int40", "address", "string"
    dimensions: List[int]  # e.g., [2] for int40[2], [] for simple types
    is_array: bool  # True if the type ends with []

    def __str__(self) -> str:
        """Return the string representation of the type."""
        result = self.base_type
        for dim in self.dimensions:
            result += f"[{dim}]"
        if self.is_array:
            result += "[]"
        return result

    def to_protobuf_type(self) -> str:
        """Convert to protobuf type."""
        # EAS to protobuf type mapping
        type_mapping = {
            "address": "string",
            "string": "string",
            "bool": "bool",
            "bytes32": "bytes",
            "bytes": "bytes",
            "uint8": "uint32",
            "uint16": "uint32",
            "uint24": "uint32",
            "uint32": "uint32",
            "uint40": "uint64",
            "uint48": "uint64",
            "uint56": "uint64",
            "uint64": "uint64",
            "uint72": "uint64",
            "uint80": "uint64",
            "uint88": "uint64",
            "uint96": "uint64",
            "uint104": "uint64",
            "uint112": "uint64",
            "uint120": "uint64",
            "uint128": "uint64",
            "uint136": "uint64",
            "uint144": "uint64",
            "uint152": "uint64",
            "uint160": "uint64",
            "uint168": "uint64",
            "uint176": "uint64",
            "uint184": "uint64",
            "uint192": "uint64",
            "uint200": "uint64",
            "uint208": "uint64",
            "uint216": "uint64",
            "uint224": "uint64",
            "uint232": "uint64",
            "uint240": "uint64",
            "uint248": "uint64",
            "uint256": "uint64",
            "int8": "int32",
            "int16": "int32",
            "int24": "int32",
            "int32": "int32",
            "int40": "int64",
            "int48": "int64",
            "int56": "int64",
            "int64": "int64",
            "int72": "int64",
            "int80": "int64",
            "int88": "int64",
            "int96": "int64",
            "int104": "int64",
            "int112": "int64",
            "int120": "int64",
            "int128": "int64",
            "int136": "int64",
            "int144": "int64",
            "int152": "int64",
            "int160": "int64",
            "int168": "int64",
            "int176": "int64",
            "int184": "int64",
            "int192": "int64",
            "int200": "int64",
            "int208": "int64",
            "int216": "int64",
            "int224": "int64",
            "int232": "int64",
            "int240": "int64",
            "int248": "int64",
            "int256": "int64",
        }
        return type_mapping.get(self.base_type, "string")


@dataclass
class EASField:
    """Represents a parsed EAS field."""

    name: str
    type: EASType

    def __str__(self) -> str:
        """Return the string representation of the field."""
        return f"{self.type} {self.name}"


class EASTypeParser:
    """Parser for EAS schema types and fields."""

    # Regex patterns for parsing
    TYPE_PATTERN = re.compile(r"^([a-zA-Z][a-zA-Z0-9]*)((?:\[\d+\])*)(\[\])?$")
    FIELD_PATTERN = re.compile(
        r"^([a-zA-Z][a-zA-Z0-9]*(?:\[\d+\])*(?:\[\])?)\s+([a-zA-Z_][a-zA-Z0-9_]*)$"
    )

    @classmethod
    def parse_type(cls, type_str: str) -> EASType:
        """
        Parse an EAS type string into an EASType object.

        Args:
            type_str: Type string like "int40[2][]", "address[]", "string"

        Returns:
            EASType object

        Raises:
            ValueError: If the type string is invalid
        """
        match = cls.TYPE_PATTERN.match(type_str)
        if not match:
            raise ValueError(f"Invalid EAS type: {type_str}")

        base_type = match.group(1)
        dimensions_str = match.group(2) or ""
        is_array = bool(match.group(3))

        # Parse dimensions
        dimensions = []
        if dimensions_str:
            # Extract numbers from [2][3][4] -> [2, 3, 4]
            dim_matches = re.findall(r"\[(\d+)\]", dimensions_str)
            dimensions = [int(dim) for dim in dim_matches]

        return EASType(base_type=base_type, dimensions=dimensions, is_array=is_array)

    @classmethod
    def parse_field(cls, field_str: str) -> EASField:
        """
        Parse an EAS field string into an EASField object.

        Args:
            field_str: Field string like "int40[2][] polygonArea", "address registrant"

        Returns:
            EASField object

        Raises:
            ValueError: If the field string is invalid
        """
        match = cls.FIELD_PATTERN.match(field_str)
        if not match:
            raise ValueError(f"Invalid EAS field: {field_str}")

        type_str = match.group(1)
        name = match.group(2)

        eas_type = cls.parse_type(type_str)
        return EASField(name=name, type=eas_type)

    @classmethod
    def parse_schema_definition(cls, schema_def: str) -> List[EASField]:
        """
        Parse a complete EAS schema definition string.

        Args:
            schema_def: Schema definition like "string domain,address registrant,int40[2][] polygonArea"

        Returns:
            List of EASField objects

        Raises:
            ValueError: If the schema definition is invalid
        """
        fields = []

        # Split by comma and clean up
        field_definitions = [f.strip() for f in schema_def.split(",")]

        for field_def in field_definitions:
            if not field_def:
                continue

            try:
                field = cls.parse_field(field_def)
                fields.append(field)
            except ValueError as e:
                raise ValueError(f"Failed to parse field '{field_def}': {e}")

        return fields

    @classmethod
    def validate_type(cls, type_str: str) -> bool:
        """
        Validate if a type string is a valid EAS type.

        Args:
            type_str: Type string to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            cls.parse_type(type_str)
            return True
        except ValueError:
            return False

    @classmethod
    def validate_field(cls, field_str: str) -> bool:
        """
        Validate if a field string is a valid EAS field.

        Args:
            field_str: Field string to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            cls.parse_field(field_str)
            return True
        except ValueError:
            return False


# Convenience functions for backward compatibility
def parse_eas_type(type_str: str) -> EASType:
    """Parse an EAS type string."""
    return EASTypeParser.parse_type(type_str)


def parse_eas_field(field_str: str) -> EASField:
    """Parse an EAS field string."""
    return EASTypeParser.parse_field(field_str)


def parse_eas_schema_definition(schema_def: str) -> List[EASField]:
    """Parse an EAS schema definition string."""
    return EASTypeParser.parse_schema_definition(schema_def)
