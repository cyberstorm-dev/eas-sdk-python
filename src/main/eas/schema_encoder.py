"""
Schema encoder for EAS data using type resolution.
"""

import base64
import importlib
import json
from typing import Any, Dict, Optional, Union, cast

import yaml  # type: ignore[import-untyped]

# Removed unused imports: generate_proto_format, EASField, EASTypeParser


def resolve_protobuf_type(schema_uid: str, namespace: str = "vendor.v1") -> type:
    """
    Resolve a protobuf message type by schema UID and namespace.

    Args:
        schema_uid: The schema UID
        namespace: The protobuf namespace (e.g., "vendor.v1")

    Returns:
        The protobuf message class

    Raises:
        ImportError: If the module cannot be imported
        AttributeError: If the message class is not found
    """
    # Convert namespace to module path
    # For namespace "repository.v1", look for "repository/v1/repository_pb2.py"
    parts = namespace.split(".")
    if len(parts) == 2:
        # Two-part namespace like "repository.v1"
        module_path = f"{parts[0]}.{parts[1]}.{parts[0]}"
    else:
        # Fallback to old format for single-part namespaces
        module_path = namespace.replace(".", "_")

    # Try to import the module
    try:
        if len(parts) == 2:
            module = importlib.import_module(f"main.EAS.generated.{module_path}_pb2")
        else:
            module = importlib.import_module(f"main.EAS.generated.{module_path}_pb2")
    except ImportError:
        raise ImportError(
            f"Protobuf module not found: main.EAS.generated.{module_path}_pb2"
        )

    # Get the message class name
    message_name = f"message_{schema_uid.replace('0x', '')}"

    # Try to get the message class
    try:
        message_class = getattr(module, message_name)
        return cast(type, message_class)
    except AttributeError:
        raise AttributeError(
            f"Message class '{message_name}' not found in module '{module_path}'"
        )


def encode_data_protobuf(
    data: Dict[str, Any], message_class: type, output_format: str = "binary"
) -> Union[bytes, str]:
    """
    Encode data using a protobuf message class.

    Args:
        data: Dictionary containing field values
        message_class: The protobuf message class to use
        output_format: Output format ('binary', 'base64', 'hex', 'json')

    Returns:
        Encoded data in the specified format
    """
    # Create protobuf message
    message = message_class()

    # Set field values
    for field_name, value in data.items():
        if hasattr(message, field_name):
            # Convert hex strings to bytes for bytes fields
            if message.DESCRIPTOR.fields_by_name[field_name].type == 12:  # TYPE_BYTES
                if isinstance(value, str) and value.startswith("0x"):
                    value = bytes.fromhex(value[2:])
                elif isinstance(value, str):
                    value = bytes.fromhex(value)

            if isinstance(value, list):
                # Handle repeated fields
                getattr(message, field_name).extend(value)
            else:
                setattr(message, field_name, value)
        else:
            raise ValueError(f"Field '{field_name}' not found in protobuf message")

    # Serialize
    serialized = message.SerializeToString()

    # Return in requested format
    if output_format == "binary":
        return cast(Union[bytes, str], serialized)
    elif output_format == "base64":
        return cast(Union[bytes, str], base64.b64encode(serialized).decode("utf-8"))
    elif output_format == "hex":
        return cast(Union[bytes, str], serialized.hex())
    elif output_format == "json":
        # Convert message to dict and return as JSON
        result = {}
        for field_name in message.DESCRIPTOR.fields_by_name:
            value = getattr(message, field_name)
            if hasattr(value, "__iter__") and not isinstance(value, (str, bytes)):
                # Convert repeated fields to list
                result[field_name] = list(value)
            else:
                result[field_name] = value
        return json.dumps(result, indent=2)
    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def encode_data_json(data: Dict[str, Any], output_format: str = "json") -> str:
    """
    Encode data as JSON.

    Args:
        data: Dictionary containing field values
        output_format: Output format ('json', 'yaml')

    Returns:
        Encoded data as string
    """
    if output_format == "json":
        return json.dumps(data, indent=2)
    elif output_format == "yaml":
        return cast(str, yaml.dump(data, default_flow_style=False, sort_keys=False))
    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def encode_data_yaml(data: Dict[str, Any], output_format: str = "yaml") -> str:
    """
    Encode data as YAML.

    Args:
        data: Dictionary containing field values
        output_format: Output format ('json', 'yaml')

    Returns:
        Encoded data as string
    """
    if output_format == "json":
        return json.dumps(data, indent=2)
    elif output_format == "yaml":
        return cast(str, yaml.dump(data, default_flow_style=False, sort_keys=False))
    else:
        raise ValueError(f"Unsupported output format: {output_format}")


def encode_schema_data(
    schema_uid: str,
    data: Dict[str, Any],
    format_type: str = "protobuf",
    namespace: Optional[str] = None,
    message_type: Optional[str] = None,
    output_format: str = "binary",
) -> Union[bytes, str]:
    """
    Encode EAS data using the specified format.

    Args:
        schema_uid: The schema UID
        data: Dictionary containing field values
        format_type: Type of encoding ('protobuf', 'json', 'yaml')
        namespace: The protobuf namespace (e.g., "vendor.v1") - only for protobuf
        message_type: Full message type name (e.g., "vendor.v1.message_0x1234") - only for protobuf
        output_format: Output format ('binary', 'base64', 'hex', 'json', 'yaml')

    Returns:
        Encoded data in the specified format

    Note:
        For protobuf: Either namespace or message_type must be provided, but not both.
        For json/yaml: output_format can be 'json' or 'yaml' regardless of format_type.
    """
    if format_type == "protobuf":
        if namespace and message_type:
            raise ValueError("Cannot specify both namespace and message_type")
        if not namespace and not message_type:
            namespace = "vendor.v1"  # Default namespace

        if message_type:
            # Parse message_type to get module and class name
            parts = message_type.split(".")
            if len(parts) < 2:
                raise ValueError(f"Invalid message_type format: {message_type}")

            # Last part is the class name, rest is the namespace
            class_name = parts[-1]
            namespace = ".".join(parts[:-1])

            # Convert namespace to module path
            module_path = namespace.replace(".", "_")

            # Try to import the module
            try:
                module = importlib.import_module(
                    f"main.EAS.generated.{module_path}_pb2"
                )
            except ImportError:
                raise ImportError(
                    f"Protobuf module not found: main.EAS.generated.{module_path}_pb2"
                )

            # Get the message class
            try:
                message_class = getattr(module, class_name)
            except AttributeError:
                raise AttributeError(
                    f"Message class '{class_name}' not found in module '{module_path}'"
                )
        else:
            # Use namespace and schema_uid to resolve type
            message_class = resolve_protobuf_type(schema_uid, namespace or "vendor.v1")

        return encode_data_protobuf(data, message_class, output_format)

    elif format_type == "json":
        return encode_data_json(data, output_format)

    elif format_type == "yaml":
        return encode_data_yaml(data, output_format)

    else:
        raise ValueError(f"Unsupported format type: {format_type}")


def decode_schema_data(
    encoded_data: Union[bytes, str], message_class: type, input_format: str = "binary"
) -> Dict[str, Any]:
    """
    Decode data using a protobuf message class.

    Args:
        encoded_data: Encoded data to decode
        message_class: The protobuf message class to use
        input_format: Input format ('binary', 'base64', 'hex')

    Returns:
        Dictionary containing field values
    """
    # Parse input format
    if input_format == "binary":
        if isinstance(encoded_data, str):
            serialized = encoded_data.encode("latin-1")
        else:
            serialized = encoded_data
    elif input_format == "base64":
        if isinstance(encoded_data, str):
            serialized = base64.b64decode(encoded_data)
        else:
            serialized = base64.b64decode(encoded_data.decode("utf-8"))
    elif input_format == "hex":
        if isinstance(encoded_data, str):
            serialized = bytes.fromhex(encoded_data)
        else:
            serialized = bytes.fromhex(encoded_data.decode("utf-8"))
    else:
        raise ValueError(f"Unsupported input format: {input_format}")

    # Parse protobuf message
    message = message_class()
    message.ParseFromString(serialized)

    # Convert to dictionary
    result = {}
    for field_name in message.DESCRIPTOR.fields_by_name:
        value = getattr(message, field_name)
        if hasattr(value, "__iter__") and not isinstance(value, (str, bytes)):
            # Convert repeated fields to list
            result[field_name] = list(value)
        else:
            result[field_name] = value

    return result
