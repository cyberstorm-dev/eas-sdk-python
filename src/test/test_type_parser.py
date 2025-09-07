"""
Tests for type_parser module.
"""

import pytest

from main.EAS.type_parser import (
    EASField,
    EASType,
    EASTypeParser,
    parse_eas_field,
    parse_eas_schema_definition,
    parse_eas_type,
)


class TestEASType:
    """Test cases for EASType class."""

    def test_eas_type_creation(self):
        """Test creating EASType objects."""
        # Simple type
        eas_type = EASType(base_type="string", dimensions=[], is_array=False)
        assert eas_type.base_type == "string"
        assert eas_type.dimensions == []
        assert eas_type.is_array is False
        assert str(eas_type) == "string"

        # Array type
        eas_type = EASType(base_type="address", dimensions=[], is_array=True)
        assert eas_type.base_type == "address"
        assert eas_type.dimensions == []
        assert eas_type.is_array is True
        assert str(eas_type) == "address[]"

        # Complex type with dimensions
        eas_type = EASType(base_type="int40", dimensions=[2], is_array=True)
        assert eas_type.base_type == "int40"
        assert eas_type.dimensions == [2]
        assert eas_type.is_array is True
        assert str(eas_type) == "int40[2][]"

    def test_to_protobuf_type(self):
        """Test conversion to protobuf types."""
        # Basic types
        assert EASType("address", [], False).to_protobuf_type() == "string"
        assert EASType("string", [], False).to_protobuf_type() == "string"
        assert EASType("bool", [], False).to_protobuf_type() == "bool"
        assert EASType("bytes32", [], False).to_protobuf_type() == "bytes"

        # Integer types
        assert EASType("uint8", [], False).to_protobuf_type() == "uint32"
        assert EASType("uint32", [], False).to_protobuf_type() == "uint32"
        assert EASType("uint40", [], False).to_protobuf_type() == "uint64"
        assert EASType("uint256", [], False).to_protobuf_type() == "uint64"
        assert EASType("int8", [], False).to_protobuf_type() == "int32"
        assert EASType("int32", [], False).to_protobuf_type() == "int32"
        assert EASType("int40", [], False).to_protobuf_type() == "int64"
        assert EASType("int256", [], False).to_protobuf_type() == "int64"

        # Unknown type falls back to string
        assert EASType("unknown_type", [], False).to_protobuf_type() == "string"


class TestEASField:
    """Test cases for EASField class."""

    def test_eas_field_creation(self):
        """Test creating EASField objects."""
        eas_type = EASType("string", [], False)
        field = EASField(name="domain", type=eas_type)
        assert field.name == "domain"
        assert field.type == eas_type
        assert str(field) == "string domain"

        # Array field
        eas_type = EASType("address", [], True)
        field = EASField(name="registrants", type=eas_type)
        assert field.name == "registrants"
        assert field.type == eas_type
        assert str(field) == "address[] registrants"


class TestEASTypeParser:
    """Test cases for EASTypeParser class."""

    def test_parse_type_simple(self):
        """Test parsing simple types."""
        # Basic types
        assert EASTypeParser.parse_type("string") == EASType("string", [], False)
        assert EASTypeParser.parse_type("address") == EASType("address", [], False)
        assert EASTypeParser.parse_type("bool") == EASType("bool", [], False)
        assert EASTypeParser.parse_type("uint256") == EASType("uint256", [], False)

    def test_parse_type_arrays(self):
        """Test parsing array types."""
        # Simple arrays
        assert EASTypeParser.parse_type("string[]") == EASType("string", [], True)
        assert EASTypeParser.parse_type("address[]") == EASType("address", [], True)
        assert EASTypeParser.parse_type("uint256[]") == EASType("uint256", [], True)

    def test_parse_type_complex_arrays(self):
        """Test parsing complex array types."""
        # Fixed-size arrays
        assert EASTypeParser.parse_type("int40[2]") == EASType("int40", [2], False)
        assert EASTypeParser.parse_type("uint256[10]") == EASType(
            "uint256", [10], False
        )

        # Array of fixed-size arrays
        assert EASTypeParser.parse_type("int40[2][]") == EASType("int40", [2], True)
        assert EASTypeParser.parse_type("uint256[10][]") == EASType(
            "uint256", [10], True
        )

        # Multi-dimensional fixed arrays
        assert EASTypeParser.parse_type("int40[2][3]") == EASType(
            "int40", [2, 3], False
        )
        assert EASTypeParser.parse_type("int40[2][3][]") == EASType(
            "int40", [2, 3], True
        )

    def test_parse_type_invalid(self):
        """Test parsing invalid types."""
        with pytest.raises(ValueError, match="Invalid EAS type"):
            EASTypeParser.parse_type("")

        with pytest.raises(ValueError, match="Invalid EAS type"):
            EASTypeParser.parse_type("123string")

        with pytest.raises(ValueError, match="Invalid EAS type"):
            EASTypeParser.parse_type("string[")

        with pytest.raises(ValueError, match="Invalid EAS type"):
            EASTypeParser.parse_type("string[abc]")

    def test_parse_field_simple(self):
        """Test parsing simple fields."""
        field = EASTypeParser.parse_field("string domain")
        assert field.name == "domain"
        assert field.type == EASType("string", [], False)

        field = EASTypeParser.parse_field("address registrant")
        assert field.name == "registrant"
        assert field.type == EASType("address", [], False)

    def test_parse_field_arrays(self):
        """Test parsing array fields."""
        field = EASTypeParser.parse_field("string[] domains")
        assert field.name == "domains"
        assert field.type == EASType("string", [], True)

        field = EASTypeParser.parse_field("address[] registrants")
        assert field.name == "registrants"
        assert field.type == EASType("address", [], True)

    def test_parse_field_complex_arrays(self):
        """Test parsing complex array fields."""
        field = EASTypeParser.parse_field("int40[2][] polygonArea")
        assert field.name == "polygonArea"
        assert field.type == EASType("int40", [2], True)

        field = EASTypeParser.parse_field("uint256[10][] amounts")
        assert field.name == "amounts"
        assert field.type == EASType("uint256", [10], True)

    def test_parse_field_invalid(self):
        """Test parsing invalid fields."""
        with pytest.raises(ValueError, match="Invalid EAS field"):
            EASTypeParser.parse_field("")

        with pytest.raises(ValueError, match="Invalid EAS field"):
            EASTypeParser.parse_field("string")

        with pytest.raises(ValueError, match="Invalid EAS field"):
            EASTypeParser.parse_field("123string domain")

    def test_parse_schema_definition_simple(self):
        """Test parsing simple schema definitions."""
        fields = EASTypeParser.parse_schema_definition(
            "string domain,address registrant"
        )
        assert len(fields) == 2
        assert fields[0].name == "domain"
        assert fields[0].type == EASType("string", [], False)
        assert fields[1].name == "registrant"
        assert fields[1].type == EASType("address", [], False)

    def test_parse_schema_definition_with_arrays(self):
        """Test parsing schema definitions with arrays."""
        fields = EASTypeParser.parse_schema_definition(
            "string domain,address[] registrants,uint256[] amounts"
        )
        assert len(fields) == 3
        assert fields[0].name == "domain"
        assert fields[0].type == EASType("string", [], False)
        assert fields[1].name == "registrants"
        assert fields[1].type == EASType("address", [], True)
        assert fields[2].name == "amounts"
        assert fields[2].type == EASType("uint256", [], True)

    def test_parse_schema_definition_complex(self):
        """Test parsing complex schema definitions."""
        schema_def = (
            "uint8 holdType,uint8 useType,uint64 expiration,int40[2][] polygonArea"
        )
        fields = EASTypeParser.parse_schema_definition(schema_def)
        assert len(fields) == 4
        assert fields[0].name == "holdType"
        assert fields[0].type == EASType("uint8", [], False)
        assert fields[1].name == "useType"
        assert fields[1].type == EASType("uint8", [], False)
        assert fields[2].name == "expiration"
        assert fields[2].type == EASType("uint64", [], False)
        assert fields[3].name == "polygonArea"
        assert fields[3].type == EASType("int40", [2], True)

    def test_parse_schema_definition_with_spaces(self):
        """Test parsing schema definitions with extra spaces."""
        fields = EASTypeParser.parse_schema_definition(
            "  string  domain  ,  address  registrant  "
        )
        assert len(fields) == 2
        assert fields[0].name == "domain"
        assert fields[0].type == EASType("string", [], False)
        assert fields[1].name == "registrant"
        assert fields[1].type == EASType("address", [], False)

    def test_parse_schema_definition_empty_fields(self):
        """Test parsing schema definitions with empty fields."""
        fields = EASTypeParser.parse_schema_definition(
            "string domain,,address registrant"
        )
        assert len(fields) == 2
        assert fields[0].name == "domain"
        assert fields[1].name == "registrant"

    def test_parse_schema_definition_invalid(self):
        """Test parsing invalid schema definitions."""
        with pytest.raises(ValueError, match="Failed to parse field"):
            EASTypeParser.parse_schema_definition("string domain,123invalid field")

    def test_validate_type(self):
        """Test type validation."""
        assert EASTypeParser.validate_type("string") is True
        assert EASTypeParser.validate_type("address[]") is True
        assert EASTypeParser.validate_type("int40[2][]") is True
        assert EASTypeParser.validate_type("") is False
        assert EASTypeParser.validate_type("123string") is False
        assert EASTypeParser.validate_type("string[") is False

    def test_validate_field(self):
        """Test field validation."""
        assert EASTypeParser.validate_field("string domain") is True
        assert EASTypeParser.validate_field("address[] registrants") is True
        assert EASTypeParser.validate_field("int40[2][] polygonArea") is True
        assert EASTypeParser.validate_field("") is False
        assert EASTypeParser.validate_field("string") is False
        assert EASTypeParser.validate_field("123string domain") is False


class TestConvenienceFunctions:
    """Test cases for convenience functions."""

    def test_parse_eas_type(self):
        """Test parse_eas_type convenience function."""
        eas_type = parse_eas_type("int40[2][]")
        assert eas_type == EASType("int40", [2], True)

    def test_parse_eas_field(self):
        """Test parse_eas_field convenience function."""
        field = parse_eas_field("int40[2][] polygonArea")
        assert field.name == "polygonArea"
        assert field.type == EASType("int40", [2], True)

    def test_parse_eas_schema_definition(self):
        """Test parse_eas_schema_definition convenience function."""
        fields = parse_eas_schema_definition("string domain,address registrant")
        assert len(fields) == 2
        assert fields[0].name == "domain"
        assert fields[1].name == "registrant"
