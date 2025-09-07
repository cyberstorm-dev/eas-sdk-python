"""
Schema generator for converting EAS schema definitions to different output formats.
"""

from typing import List

from .type_parser import EASField, EASType, EASTypeParser


def parse_eas_schema_definition(schema_def: str) -> List[EASField]:
    """
    Parse EAS schema definition string into EASField objects.

    Args:
        schema_def: Schema definition string (e.g., "string domain,address registrant")

    Returns:
        List of EASField objects
    """
    return EASTypeParser.parse_schema_definition(schema_def)


def eas_to_protobuf_type(eas_type: EASType) -> str:
    """
    Convert EAS type to protobuf type.

    Args:
        eas_type: EAS type object

    Returns:
        Corresponding protobuf type
    """
    return eas_type.to_protobuf_type()


def generate_eas_format(fields: List[EASField]) -> str:
    """
    Generate EAS format (newline-separated fields).

    Args:
        fields: List of EASField objects

    Returns:
        EAS format string
    """
    lines = []
    for field in fields:
        lines.append(str(field))

    return "\n".join(lines)


def generate_json_format(fields: List[EASField]) -> str:
    """
    Generate JSON format.

    Args:
        fields: List of EASField objects

    Returns:
        JSON format string
    """
    import json

    schema_obj = {
        "fields": [
            {
                "name": field.name,
                "type": str(field.type),
                "is_array": field.type.is_array,
            }
            for field in fields
        ]
    }

    return json.dumps(schema_obj, indent=2)


def generate_yaml_format(fields: List[EASField]) -> str:
    """
    Generate YAML format.

    Args:
        fields: List of EASField objects

    Returns:
        YAML format string
    """
    import yaml

    schema_obj = {
        "fields": [
            {
                "name": field.name,
                "type": str(field.type),
                "is_array": field.type.is_array,
            }
            for field in fields
        ]
    }

    return yaml.dump(schema_obj, default_flow_style=False, sort_keys=False)


def generate_proto_format(fields: List[EASField], schema_uid: str) -> str:
    """
    Generate protobuf format.

    Args:
        fields: List of EASField objects
        schema_uid: Schema UID for message naming

    Returns:
        Protobuf format string

    Raises:
        ValueError: If any field has complex types that can't be represented in protobuf
    """
    # Check for unsupported complex types
    unsupported_fields = []
    for field in fields:
        if field.type.dimensions:
            unsupported_fields.append(f"{field.name} ({str(field.type)})")

    if unsupported_fields:
        fields_str = ", ".join(unsupported_fields)
        raise ValueError(
            f"Protobuf generation does not support complex types with fixed dimensions. "
            f"Unsupported fields: {fields_str}. "
            f"Consider using 'eas', 'json', or 'yaml' format instead."
        )

    # Create message name from schema UID
    message_name = f"message_{schema_uid.replace('0x', '')}"

    lines = [f"message {message_name} {{"]

    for i, field in enumerate(fields, 1):
        protobuf_type = eas_to_protobuf_type(field.type)

        if field.type.is_array:
            # For arrays, use repeated keyword
            lines.append(f"  repeated {protobuf_type} {field.name} = {i};")
        else:
            lines.append(f"  {protobuf_type} {field.name} = {i};")

    lines.append("}")

    return "\n".join(lines)


def generate_schema_code(
    schema_definition: str, output_format: str, schema_uid: str = ""
) -> str:
    """
    Generate code from EAS schema definition.

    Args:
        schema_definition: EAS schema definition string
        output_format: Output format ('eas', 'json', 'yaml', 'proto')
        schema_uid: Schema UID (required for proto format)

    Returns:
        Generated code string
    """
    # Parse the schema definition
    fields = parse_eas_schema_definition(schema_definition)

    if output_format == "eas":
        return generate_eas_format(fields)
    elif output_format == "json":
        return generate_json_format(fields)
    elif output_format == "yaml":
        return generate_yaml_format(fields)
    elif output_format == "proto":
        if not schema_uid:
            raise ValueError("Schema UID is required for proto format")
        return generate_proto_format(fields, schema_uid)
    else:
        raise ValueError(f"Unsupported format: {output_format}")
