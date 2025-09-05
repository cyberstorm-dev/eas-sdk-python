"""
Tests for schema_generator module.
"""

import pytest

from main.EAS.schema_generator import (
    eas_to_protobuf_type,
    generate_eas_format,
    generate_json_format,
    generate_proto_format,
    generate_schema_code,
    generate_yaml_format,
    parse_eas_schema_definition,
)


class TestSchemaGenerator:
    """Test cases for schema_generator module."""

    def test_parse_eas_schema_definition_simple(self):
        """Test parsing simple EAS schema definition."""
        schema_def = "string domain,address registrant"
        fields = parse_eas_schema_definition(schema_def)

        assert len(fields) == 2
        assert fields[0].name == "domain"
        assert fields[0].type.base_type == "string"
        assert fields[0].type.is_array is False
        assert fields[1].name == "registrant"
        assert fields[1].type.base_type == "address"
        assert fields[1].type.is_array is False

    def test_parse_eas_schema_definition_with_arrays(self):
        """Test parsing EAS schema definition with arrays."""
        schema_def = "string domain,address[] registrants,uint256[] amounts"
        fields = parse_eas_schema_definition(schema_def)

        assert len(fields) == 3
        assert fields[0].name == "domain"
        assert fields[0].type.base_type == "string"
        assert fields[0].type.is_array is False
        assert fields[1].name == "registrants"
        assert fields[1].type.base_type == "address"
        assert fields[1].type.is_array is True
        assert fields[2].name == "amounts"
        assert fields[2].type.base_type == "uint256"
        assert fields[2].type.is_array is True

    def test_parse_eas_schema_definition_with_nested_arrays(self):
        """Test parsing EAS schema definition with nested arrays."""
        schema_def = "uint8 holdType,int40[2][] polygonArea"
        fields = parse_eas_schema_definition(schema_def)

        assert len(fields) == 2
        assert fields[0].name == "holdType"
        assert fields[0].type.base_type == "uint8"
        assert fields[0].type.is_array is False
        assert fields[1].name == "polygonArea"
        assert fields[1].type.base_type == "int40"
        assert fields[1].type.dimensions == [2]
        assert fields[1].type.is_array is True

    def test_eas_to_protobuf_type_mapping(self):
        """Test EAS to protobuf type mapping."""
        from main.EAS.type_parser import EASType

        assert eas_to_protobuf_type(EASType("address", [], False)) == "string"
        assert eas_to_protobuf_type(EASType("string", [], False)) == "string"
        assert eas_to_protobuf_type(EASType("bool", [], False)) == "bool"
        assert eas_to_protobuf_type(EASType("bytes32", [], False)) == "bytes"
        assert eas_to_protobuf_type(EASType("uint8", [], False)) == "uint32"
        assert eas_to_protobuf_type(EASType("uint256", [], False)) == "uint64"
        assert eas_to_protobuf_type(EASType("int8", [], False)) == "int32"
        assert eas_to_protobuf_type(EASType("int256", [], False)) == "int64"
        assert (
            eas_to_protobuf_type(EASType("unknown_type", [], False)) == "string"
        )  # Default fallback

    def test_generate_eas_format(self):
        """Test generating EAS format."""
        from main.EAS.type_parser import EASField, EASType

        fields = [
            EASField("domain", EASType("string", [], False)),
            EASField("registrant", EASType("address", [], False)),
            EASField("amounts", EASType("uint256", [], True)),
        ]

        result = generate_eas_format(fields)
        expected = "string domain\naddress registrant\nuint256[] amounts"
        assert result == expected

    def test_generate_json_format(self):
        """Test generating JSON format."""
        from main.EAS.type_parser import EASField, EASType

        fields = [
            EASField("domain", EASType("string", [], False)),
            EASField("registrant", EASType("address", [], False)),
            EASField("amounts", EASType("uint256", [], True)),
        ]

        result = generate_json_format(fields)
        import json

        expected = json.dumps(
            {
                "fields": [
                    {"name": "domain", "type": "string", "is_array": False},
                    {"name": "registrant", "type": "address", "is_array": False},
                    {"name": "amounts", "type": "uint256[]", "is_array": True},
                ]
            },
            indent=2,
        )
        assert result == expected

    def test_generate_yaml_format(self):
        """Test generating YAML format."""
        from main.EAS.type_parser import EASField, EASType

        fields = [
            EASField("domain", EASType("string", [], False)),
            EASField("registrant", EASType("address", [], False)),
        ]

        result = generate_yaml_format(fields)
        import yaml

        expected = yaml.dump(
            {
                "fields": [
                    {"name": "domain", "type": "string", "is_array": False},
                    {"name": "registrant", "type": "address", "is_array": False},
                ]
            },
            default_flow_style=False,
            sort_keys=False,
        )
        assert result == expected

    def test_generate_proto_format(self):
        """Test generating protobuf format."""
        from main.EAS.type_parser import EASField, EASType

        fields = [
            EASField("domain", EASType("string", [], False)),
            EASField("registrant", EASType("address", [], False)),
            EASField("amounts", EASType("uint256", [], True)),
        ]

        result = generate_proto_format(fields, "0x1234567890abcdef")
        expected = """message message_1234567890abcdef {
  string domain = 1;
  string registrant = 2;
  repeated uint64 amounts = 3;
}"""
        assert result == expected

    def test_generate_proto_format_with_complex_types(self):
        """Test generating protobuf format with complex types (should fail)."""
        from main.EAS.type_parser import EASField, EASType

        fields = [
            EASField("domain", EASType("string", [], False)),
            EASField("coordinates", EASType("int40", [2], False)),
        ]

        with pytest.raises(
            ValueError,
            match="Protobuf generation does not support complex types with fixed dimensions",
        ):
            generate_proto_format(fields, "0x1234567890abcdef")

    def test_generate_schema_code_eas(self):
        """Test generating EAS format code."""
        schema_def = "string domain,address registrant"
        result = generate_schema_code(schema_def, "eas")
        expected = "string domain\naddress registrant"
        assert result == expected

    def test_generate_schema_code_json(self):
        """Test generating JSON format code."""
        schema_def = "string domain,address registrant"
        result = generate_schema_code(schema_def, "json")
        import json

        expected = json.dumps(
            {
                "fields": [
                    {"name": "domain", "type": "string", "is_array": False},
                    {"name": "registrant", "type": "address", "is_array": False},
                ]
            },
            indent=2,
        )
        assert result == expected

    def test_generate_schema_code_yaml(self):
        """Test generating YAML format code."""
        schema_def = "string domain,address registrant"
        result = generate_schema_code(schema_def, "yaml")
        import yaml

        expected = yaml.dump(
            {
                "fields": [
                    {"name": "domain", "type": "string", "is_array": False},
                    {"name": "registrant", "type": "address", "is_array": False},
                ]
            },
            default_flow_style=False,
            sort_keys=False,
        )
        assert result == expected

    def test_generate_schema_code_proto(self):
        """Test generating protobuf format code."""
        schema_def = "string domain,address registrant"
        result = generate_schema_code(schema_def, "proto", "0x1234567890abcdef")
        expected = """message message_1234567890abcdef {
  string domain = 1;
  string registrant = 2;
}"""
        assert result == expected

    def test_generate_schema_code_proto_with_simple_arrays(self):
        """Test generating protobuf format code with simple arrays."""
        schema_def = "string domain,address[] registrants,uint256[] amounts"
        result = generate_schema_code(schema_def, "proto", "0x1234567890abcdef")
        expected = """message message_1234567890abcdef {
  string domain = 1;
  repeated string registrants = 2;
  repeated uint64 amounts = 3;
}"""
        assert result == expected

    def test_generate_schema_code_proto_with_complex_types(self):
        """Test generating protobuf format code with complex types (should fail)."""
        schema_def = "string domain,int40[2] coordinates"
        with pytest.raises(
            ValueError,
            match="Protobuf generation does not support complex types with fixed dimensions",
        ):
            generate_schema_code(schema_def, "proto", "0x1234567890abcdef")

    def test_generate_schema_code_proto_without_uid(self):
        """Test generating protobuf format code without schema UID."""
        schema_def = "string domain,address registrant"
        with pytest.raises(ValueError, match="Schema UID is required for proto format"):
            generate_schema_code(schema_def, "proto")

    def test_generate_schema_code_unsupported_format(self):
        """Test generating code with unsupported format."""
        schema_def = "string domain,address registrant"
        with pytest.raises(ValueError, match="Unsupported format: invalid"):
            generate_schema_code(schema_def, "invalid")
