"""
Base classes and utilities for building attestation data converters.

Provides reusable converter base classes with validation and utility functions
for common conversion patterns. Does not depend on specific target types.
"""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional, Set, TypeVar

from .attestation_converter import AttestationConverter

T = TypeVar("T")


class ValidatingConverter(ABC):
    """Base class for converters with field validation."""

    def __init__(
        self,
        required_fields: Optional[Set[str]] = None,
        optional_fields: Optional[Set[str]] = None,
    ):
        """
        Initialize with field requirements.

        Args:
            required_fields: Set of field names that must be present
            optional_fields: Set of field names that may be present
        """
        self.required_fields = required_fields or set()
        self.optional_fields = optional_fields or set()

    def validate_fields(self, data: Dict[str, Any]) -> None:
        """
        Validate that required fields are present.

        Args:
            data: Normalized attestation data

        Raises:
            ValueError: If required fields are missing
        """
        missing_fields = self.required_fields - data.keys()
        if missing_fields:
            raise ValueError(f"Missing required fields: {missing_fields}")

        # Optionally validate unknown fields
        if self.optional_fields:
            known_fields = self.required_fields | self.optional_fields
            unknown_fields = data.keys() - known_fields
            if unknown_fields:
                raise ValueError(f"Unknown fields: {unknown_fields}")

    @abstractmethod
    def convert_validated(self, data: Dict[str, Any]) -> Any:
        """Convert validated data to target type."""
        pass

    def __call__(self, data: Dict[str, Any]) -> Any:
        """Convert with validation."""
        self.validate_fields(data)
        return self.convert_validated(data)


class FieldMapper:
    """Utility class for mapping field names and types."""

    def __init__(self, field_mappings: Optional[Dict[str, str]] = None):
        """
        Initialize with field name mappings.

        Args:
            field_mappings: Dict mapping source field names to target field names
        """
        self.field_mappings = field_mappings or {}

    def map_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply field mappings to data.

        Args:
            data: Source data dictionary

        Returns:
            Data with mapped field names
        """
        mapped_data = {}
        for source_name, value in data.items():
            target_name = self.field_mappings.get(source_name, source_name)
            mapped_data[target_name] = value
        return mapped_data


def field_extractor(field_name: str, default: Any = None) -> AttestationConverter[Any]:
    """
    Create a converter that extracts a single field.

    Args:
        field_name: Name of field to extract
        default: Default value if field is missing

    Returns:
        AttestationConverter that extracts the specified field
    """
    return AttestationConverter(lambda data: data.get(field_name, default))


def dict_converter() -> AttestationConverter[Dict[str, Any]]:
    """
    Create a converter that returns the raw dictionary.

    Useful for debugging or when you want to work with raw data.

    Returns:
        AttestationConverter that returns the input dictionary
    """
    return AttestationConverter(lambda data: data)


def filtering_converter(
    allowed_fields: Set[str],
) -> AttestationConverter[Dict[str, Any]]:
    """
    Create a converter that filters data to only include allowed fields.

    Args:
        allowed_fields: Set of field names to include

    Returns:
        AttestationConverter that returns filtered dictionary
    """

    def filter_fields(data: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in data.items() if k in allowed_fields}

    return AttestationConverter(filter_fields)


def transforming_converter(
    transformations: Dict[str, Callable[[Any], Any]],
) -> AttestationConverter[Dict[str, Any]]:
    """
    Create a converter that applies transformations to field values.

    Args:
        transformations: Dict mapping field names to transformation functions

    Returns:
        AttestationConverter that returns transformed dictionary
    """

    def transform_fields(data: Dict[str, Any]) -> Dict[str, Any]:
        result = data.copy()
        for field_name, transform_func in transformations.items():
            if field_name in result:
                result[field_name] = transform_func(result[field_name])
        return result

    return AttestationConverter(transform_fields)


def bytes_converter() -> AttestationConverter[bytes]:
    """
    Create a converter that converts hex string fields to bytes.

    Useful for signature fields and other binary data.

    Returns:
        AttestationConverter that converts hex strings to bytes
    """

    def to_bytes(data: Dict[str, Any]) -> bytes:
        # Simple example - convert first hex field found
        for value in data.values():
            if isinstance(value, str) and value.startswith("0x"):
                return bytes.fromhex(value[2:])
        return b""

    return AttestationConverter(to_bytes)
