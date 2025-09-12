#!/usr/bin/env python3
"""
EAS SDK Command Line Interface

Provides CLI tools for interacting with Ethereum Attestation Service.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Union, cast

import click
import requests
import yaml
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table
from web3 import Web3

from .core import EAS
from .exceptions import EASError, EASTransactionError, EASValidationError
from .query import (
    AttestationFilter,
    AttestationSortBy,
    EASQueryClient,
    SchemaFilter,
    SchemaSortBy,
    SortOrder,
)
from .schema_encoder import encode_schema_data
from .schema_generator import generate_schema_code
from .types import Address, SchemaUID

# Initialize Rich console
console = Console()


# EAS Contract Error Mappings - based on the EAS ABI error definitions
def get_eas_error_message(error_str: str) -> str:
    """Convert EAS contract error codes to user-friendly messages."""
    # Extract error code if it's in the format "('0x905e7107', '0x905e7107')"
    if "'0x" in error_str and "'" in error_str:
        # Extract the hex error code from the string
        start = error_str.find("'0x") + 1
        end = error_str.find("'", start)
        if start > 0 and end > start:
            error_code = error_str[start:end]
        else:
            error_code = error_str
    else:
        error_code = error_str

    # Remove 0x prefix for comparison
    if error_code.startswith("0x"):
        error_code = error_code[2:]

    # Map of EAS error selectors to user-friendly messages
    # Calculated using Web3.keccak(text='ErrorName()').hex()[:10]
    error_mappings = {
        "905e7107": "The attestation has already been revoked",
        "4ca88867": "Access denied - you don't have permission to revoke this attestation",
        "bd8ba84d": "Invalid attestation - the attestation UID doesn't exist or is malformed",
        "1a18c5fc": "This attestation is not revocable",
        "09bde339": "Invalid revocation request",
        "86834db8": "Not found - the attestation doesn't exist",
        "6d87b7b1": "Wrong schema - revocation request doesn't match the attestation's schema",
    }

    # Look for matching error code (first 8 characters)
    error_key = error_code[:8].lower()

    if error_key in error_mappings:
        return error_mappings[error_key]
    else:
        return f"Contract error: {error_code}"


# EAS GraphQL endpoints for different networks
EAS_GRAPHQL_ENDPOINTS = {
    "mainnet": "https://easscan.org/graphql",
    "sepolia": "https://sepolia.easscan.org/graphql",
    "base-sepolia": "https://base-sepolia.easscan.org/graphql",
    "optimism": "https://optimism.easscan.org/graphql",
    "arbitrum": "https://arbitrum.easscan.org/graphql",
    "base": "https://base.easscan.org/graphql",
    "polygon": "https://polygon.easscan.org/graphql",
}


def format_schema_eas(schema_data: Dict[str, Any]) -> None:
    """Format schema in EAS default format using Rich."""
    # Create a table for the schema data
    table = Table(
        title="[bold blue]EAS Schema Information[/bold blue]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    # Add rows to the table
    table.add_row("Schema ID", f"[green]{schema_data.get('id', 'Unknown')}[/green]")
    table.add_row("Creator", schema_data.get("creator", "Unknown"))
    table.add_row("Resolver", schema_data.get("resolver", "Unknown"))
    table.add_row(
        "Revocable",
        "[green]Yes[/green]" if schema_data.get("revocable") else "[red]No[/red]",
    )
    table.add_row(
        "Schema Definition", f"[yellow]{schema_data.get('schema', 'Unknown')}[/yellow]"
    )
    table.add_row("Index", str(schema_data.get("index", "Unknown")))
    table.add_row(
        "Transaction ID", f"[blue]{schema_data.get('txid', 'Unknown')}[/blue]"
    )
    table.add_row("Time", str(schema_data.get("time", "Unknown")))

    console.print(table)


def format_schema_json(schema_data: Dict[str, Any]) -> None:
    """Format schema as JSON using Rich syntax highlighting."""
    json_str = json.dumps(schema_data, indent=2)
    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
    console.print(syntax)


def format_schema_yaml(schema_data: Dict[str, Any]) -> None:
    """Format schema as YAML using Rich syntax highlighting."""
    yaml_str = yaml.dump(schema_data, default_flow_style=False, sort_keys=False)
    syntax = Syntax(yaml_str, "yaml", theme="monokai", line_numbers=True)
    console.print(syntax)


def query_eas_graphql(
    endpoint: str, query: str, variables: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Query the EAS GraphQL API.

    Args:
        endpoint: GraphQL endpoint URL
        query: GraphQL query string
        variables: Query variables

    Returns:
        GraphQL response data
    """
    try:
        response = requests.post(
            endpoint,
            json={"query": query, "variables": variables or {}},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        response.raise_for_status()
        return cast(Dict[str, Any], response.json())
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to query EAS GraphQL API: {e}")


def show_schema_impl(
    schema_uid: str, output_format: str = "eas", network: str = "mainnet"
) -> None:
    """
    Display schema information from EAS GraphQL API.

    Args:
        schema_uid: The schema UID to display
        output_format: Output format (eas, json, yaml)
        network: Network to query (mainnet, sepolia, optimism, etc.)
    """
    try:
        # Get GraphQL endpoint
        endpoint = EAS_GRAPHQL_ENDPOINTS.get(network)
        if not endpoint:
            raise ValueError(f"Unsupported network: {network}")

        # GraphQL query for schema
        query = """
        query GetSchema($uid: String!) {
            schema(where: { id: $uid }) {
                id
                schema
                creator
                resolver
                revocable
                index
                txid
                time
            }
        }
        """

        # Query the API
        result = query_eas_graphql(endpoint, query, {"uid": schema_uid})

        # Check for errors
        if "errors" in result:
            error_msg = result["errors"][0].get("message", "Unknown GraphQL error")
            raise Exception(f"GraphQL error: {error_msg}")

        # Extract schema data
        schema_data = result.get("data", {}).get("schema")
        if not schema_data:
            raise Exception(f"Schema not found: {schema_uid}")

        # Use schema data directly
        parsed_data = schema_data

        # Format and display
        if output_format == "eas":
            format_schema_eas(parsed_data)
        elif output_format == "json":
            format_schema_json(parsed_data)
        elif output_format == "yaml":
            format_schema_yaml(parsed_data)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


def format_attestation_eas(attestation_data: Dict[str, Any]) -> None:
    """Format attestation in EAS default format using Rich."""
    # Create a table for the attestation data
    table = Table(
        title="[bold blue]EAS Attestation Information[/bold blue]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Field", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")

    # Add rows to the table
    table.add_row(
        "Attestation ID", f"[green]{attestation_data.get('id', 'Unknown')}[/green]"
    )
    table.add_row(
        "Schema ID", f"[blue]{attestation_data.get('schemaId', 'Unknown')}[/blue]"
    )
    table.add_row("Attester", attestation_data.get("attester", "Unknown"))
    table.add_row("Recipient", attestation_data.get("recipient", "Unknown"))
    table.add_row("Time", str(attestation_data.get("time", "Unknown")))
    table.add_row("Time Created", str(attestation_data.get("timeCreated", "Unknown")))
    table.add_row(
        "Expiration Time", str(attestation_data.get("expirationTime", "Unknown"))
    )
    table.add_row(
        "Revocation Time", str(attestation_data.get("revocationTime", "Unknown"))
    )
    table.add_row(
        "Reference UID", f"[blue]{attestation_data.get('refUID', 'Unknown')}[/blue]"
    )
    table.add_row(
        "Revocable",
        "[green]Yes[/green]" if attestation_data.get("revocable") else "[red]No[/red]",
    )
    table.add_row(
        "Revoked",
        "[red]Yes[/red]" if attestation_data.get("revoked") else "[green]No[/green]",
    )
    table.add_row(
        "Data",
        f"[yellow]{attestation_data.get('data', 'Unknown')[:100]}"
        f"{'...' if len(str(attestation_data.get('data', ''))) > 100 else ''}[/yellow]",
    )
    table.add_row("IPFS Hash", attestation_data.get("ipfsHash", "Unknown") or "N/A")
    table.add_row(
        "Is Offchain",
        "[green]Yes[/green]" if attestation_data.get("isOffchain") else "[red]No[/red]",
    )
    table.add_row(
        "Transaction ID", f"[blue]{attestation_data.get('txid', 'Unknown')}[/blue]"
    )

    console.print(table)


def format_attestation_json(attestation_data: Dict[str, Any]) -> None:
    """Format attestation as JSON using Rich syntax highlighting."""
    json_str = json.dumps(attestation_data, indent=2)
    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
    console.print(syntax)


def format_attestation_yaml(attestation_data: Dict[str, Any]) -> None:
    """Format attestation as YAML using Rich syntax highlighting."""
    yaml_str = yaml.dump(attestation_data, default_flow_style=False, sort_keys=False)
    syntax = Syntax(yaml_str, "yaml", theme="monokai", line_numbers=True)
    console.print(syntax)


def show_attestation_impl(
    attestation_uid: str, output_format: str = "eas", network: str = "mainnet"
) -> None:
    """
    Display attestation information from EAS GraphQL API.

    Args:
        attestation_uid: The attestation UID to display
        output_format: Output format (eas, json, yaml)
        network: Network to query (mainnet, sepolia, optimism, etc.)
    """
    try:
        # Get GraphQL endpoint
        endpoint = EAS_GRAPHQL_ENDPOINTS.get(network)
        if not endpoint:
            raise ValueError(f"Unsupported network: {network}")

        # GraphQL query for attestation
        query = """
        query GetAttestation($uid: String!) {
            attestation(where: { id: $uid }) {
                id
                schemaId
                attester
                recipient
                time
                expirationTime
                revocable
                revoked
                data
                txid
                timeCreated
                revocationTime
                refUID
                ipfsHash
                isOffchain
            }
        }
        """

        # Query the API
        result = query_eas_graphql(endpoint, query, {"uid": attestation_uid})

        # Check for errors
        if "errors" in result:
            error_msg = result["errors"][0].get("message", "Unknown GraphQL error")
            raise Exception(f"GraphQL error: {error_msg}")

        # Extract attestation data
        attestation_data = result.get("data", {}).get("attestation")
        if not attestation_data:
            raise Exception(f"Attestation not found: {attestation_uid}")

        # Use attestation data directly
        parsed_data = attestation_data

        # Format and display
        if output_format == "eas":
            format_attestation_eas(parsed_data)
        elif output_format == "json":
            format_attestation_json(parsed_data)
        elif output_format == "yaml":
            format_attestation_yaml(parsed_data)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


def _get_endpoint_for_network(network: str) -> str:
    """Get GraphQL endpoint for the given network."""
    endpoint = EAS_GRAPHQL_ENDPOINTS.get(network)
    if not endpoint:
        raise ValueError(f"Unsupported network: {network}")
    return endpoint


def _fetch_attestation_data(endpoint: str, attestation_uid: str) -> Dict[str, Any]:
    """Fetch and validate attestation data from GraphQL endpoint."""
    query = """
    query GetAttestation($uid: String!) {
        attestation(where: { id: $uid }) {
            id
            schemaId
            attester
            recipient
            time
            expirationTime
            revocable
            revoked
            data
            txid
            timeCreated
            revocationTime
            refUID
            ipfsHash
            isOffchain
        }
    }
    """

    result = query_eas_graphql(endpoint, query, {"uid": attestation_uid})

    if "errors" in result:
        error_msg = result["errors"][0].get("message", "Unknown GraphQL error")
        raise Exception(f"GraphQL error: {error_msg}")

    attestation_data = result.get("data", {}).get("attestation")
    if not attestation_data:
        raise Exception(f"Attestation not found: {attestation_uid}")

    return attestation_data  # type: ignore[no-any-return]


def _fetch_schema_data(endpoint: str, schema_uid: str) -> Dict[str, Any]:
    """Fetch and validate schema data from GraphQL endpoint."""
    schema_query = """
    query GetSchema($uid: String!) {
        schema(where: { id: $uid }) {
            id
            schema
            creator
            resolver
            revocable
            index
            txid
            time
        }
    }
    """

    schema_result = query_eas_graphql(endpoint, schema_query, {"uid": schema_uid})

    if "errors" in schema_result:
        error_msg = schema_result["errors"][0].get("message", "Unknown GraphQL error")
        raise Exception(f"GraphQL error fetching schema: {error_msg}")

    schema_data = schema_result.get("data", {}).get("schema")
    if not schema_data:
        raise Exception(f"Schema not found: {schema_uid}")

    return schema_data  # type: ignore[no-any-return]


def _output_encoded_data(
    parsed_data: dict,
    format: str,
    schema_uid: str,
    namespace: Optional[str],
    message_type: Optional[str],
    encoding: str,
) -> None:
    """Output the parsed data in the requested format."""
    if format == "json":
        console.print(json.dumps(parsed_data, indent=2))
    elif format == "yaml":
        console.print(yaml.dump(parsed_data, default_flow_style=False, sort_keys=False))
    elif format == "proto":
        encoded_result: Union[bytes, str] = encode_schema_data(
            schema_uid,
            parsed_data,
            "protobuf",
            namespace or "",
            message_type or "",
            encoding,
        )

        if isinstance(encoded_result, str):
            console.print(encoded_result)
        elif isinstance(encoded_result, bytes):
            console.print(f"[green]Encoded data (hex):[/green] {encoded_result.hex()}")
    else:
        raise ValueError(f"Unsupported format: {format}")


def encode_schema_impl(
    attestation_uid: str,
    format: str = "json",
    encoding: str = "json",
    namespace: Optional[str] = None,
    message_type: Optional[str] = None,
    network: str = "mainnet",
) -> None:
    """
    Retrieve attestation data and encode it using schema-based encoding.

    Args:
        attestation_uid: The attestation UID to retrieve data from
        format: Output format ('json', 'yaml', 'proto')
        encoding: Encoding format ('binary', 'base64', 'hex', 'json') - only relevant for proto
        namespace: The protobuf namespace (e.g., "vendor.v1") - only for proto
        message_type: Full message type name (e.g., "vendor.v1.message_0x1234") - only for proto
        network: Network to query (mainnet, sepolia, etc.)
    """
    try:
        endpoint = _get_endpoint_for_network(network)

        # Fetch and parse attestation data
        parsed_data = _fetch_attestation_data(endpoint, attestation_uid)

        schema_uid = parsed_data.get("schemaId")
        if not schema_uid:
            raise Exception(f"No schema ID found in attestation: {attestation_uid}")

        # Fetch and parse schema data
        parsed_schema = _fetch_schema_data(endpoint, schema_uid)

        schema_definition = parsed_schema.get("schema", "")
        if not schema_definition:
            raise Exception(f"No schema definition found for: {schema_uid}")

        # Get and validate attestation data
        attestation_data_hex = parsed_data.get("data", "")
        if not attestation_data_hex:
            raise Exception(f"No data field found in attestation: {attestation_uid}")

        # Check if data is empty or just zeros
        if (
            not attestation_data_hex
            or attestation_data_hex == "0x"
            or all(c in "0x" for c in attestation_data_hex)
        ):
            console.print(
                "[yellow]⚠️  This attestation contains empty or zero data.[/yellow]"
            )
            console.print(f"[dim]Schema: {schema_definition}[/dim]")
            console.print(
                "[dim]This is common for structural/reference attestations.[/dim]"
            )
            return

        # Parse the attestation data using new converter system
        from .attestation_converter import parse_hex_attestation_data

        try:
            parsed_attestation_data = parse_hex_attestation_data(
                attestation_data_hex, schema_definition
            )
        except Exception as parse_error:
            console.print(
                f"[red]❌ Failed to parse attestation data: {parse_error}[/red]"
            )
            console.print(f"[dim]Data: {attestation_data_hex}[/dim]")
            console.print(f"[dim]Schema: {schema_definition}[/dim]")
            console.print(
                "[dim]This may indicate a parsing bug or malformed data.[/dim]"
            )
            return

        # Output the parsed data in the requested format
        _output_encoded_data(
            parsed_attestation_data,
            format,
            schema_uid,
            namespace,
            message_type,
            encoding,
        )

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


def _display_generated_code(generated_code: str, output_format: str) -> None:
    """Display the generated code with appropriate syntax highlighting."""
    if output_format == "eas":
        console.print(generated_code)
    elif output_format == "json":
        syntax = Syntax(generated_code, "json", theme="monokai", line_numbers=True)
        console.print(syntax)
    elif output_format == "yaml":
        syntax = Syntax(generated_code, "yaml", theme="monokai", line_numbers=True)
        console.print(syntax)
    elif output_format == "proto":
        syntax = Syntax(generated_code, "protobuf", theme="monokai", line_numbers=True)
        console.print(syntax)
    else:
        raise ValueError(f"Unsupported format: {output_format}")


def generate_schema_impl(
    schema_uid: str, output_format: str = "eas", network: str = "mainnet"
) -> None:
    """
    Generate code from EAS schema definition.

    Args:
        schema_uid: The schema UID to generate code from
        output_format: Output format (eas, json, yaml, proto)
        network: Network to query (mainnet, sepolia, optimism, etc.)
    """
    try:
        endpoint = _get_endpoint_for_network(network)

        # Fetch and parse schema data
        parsed_data = _fetch_schema_data(endpoint, schema_uid)

        # Get the schema definition
        schema_definition = parsed_data.get("schema", "")
        if not schema_definition:
            raise Exception(f"No schema definition found for: {schema_uid}")

        # Generate and display code
        generated_code = generate_schema_code(
            schema_definition, output_format, schema_uid
        )

        _display_generated_code(generated_code, output_format)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


def extract_proto_impl(
    schema_uid: str,
    data_json: str,
    namespace: Optional[str] = None,
    message_type: Optional[str] = None,
    output_format: str = "binary",
) -> None:
    """
    Extract and encode EAS data using protobuf.

    Args:
        schema_uid: The schema UID
        data_json: JSON string containing field values
        namespace: The protobuf namespace (e.g., "vendor.v1")
        message_type: Full message type name (e.g., "vendor.v1.message_0x1234")
        output_format: Output format ('binary', 'base64', 'hex', 'json')
    """
    try:
        # Parse JSON data
        try:
            data = json.loads(data_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON data: {e}")

        # Extract and encode data
        result = encode_schema_data(
            schema_uid,
            data,
            "protobuf",
            namespace or "",
            message_type or "",
            output_format,
        )

        # Display result
        if output_format == "json":
            # JSON format returns a JSON string, so just print it
            console.print(result)
        else:
            # For binary formats, display as hex for readability
            if isinstance(result, bytes):
                console.print(f"[green]Encoded data (hex):[/green] {result.hex()}")
            else:
                console.print(f"[green]Encoded data:[/green] {result}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@click.group()
@click.option(
    "--network",
    "-n",
    type=click.Choice(
        [
            "mainnet",
            "sepolia",
            "base-sepolia",
            "optimism",
            "arbitrum",
            "base",
            "polygon",
        ],
        case_sensitive=False,
    ),
    default="mainnet",
    help="Network to query (default: mainnet)",
)
@click.version_option(version="0.1.4", prog_name="EAS Tools")
@click.pass_context
def main(ctx: click.Context, network: str) -> None:
    """🛠️  EAS Tools - Ethereum Attestation Service CLI

    Query and interact with EAS data across multiple networks.
    The --network flag applies to all subcommands.

    \b
    Examples:
      eas-tools -n base-sepolia attestation show 0xceff...
      eas-tools -n mainnet schema show 0x86ad...
      eas-tools dev chains
    """
    ctx.ensure_object(dict)
    ctx.obj["network"] = network


# Schema commands group
@main.group()
def schema() -> None:
    """📋 Schema operations

    View and generate code from EAS schema definitions.
    """
    pass


@schema.command()
@click.argument("schema_uid", type=str)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["eas", "json", "yaml"], case_sensitive=False),
    default="eas",
    help="Output format (default: eas)",
)
@click.pass_context
def show(ctx: click.Context, schema_uid: str, output_format: str) -> None:
    """Display schema information.

    \b
    Example:
      eas-tools -n base-sepolia schema show 0x86ad448d1844cd6d7c13cf5d8effbc70a596af78bd0a01b747e2acb5f74c6d9b
    """
    network = ctx.obj["network"]
    show_schema_impl(schema_uid, output_format, network)


# Attestation commands group
@main.group()
def attestation() -> None:
    """🔏 Attestation operations

    View and decode EAS attestations.
    """
    pass


@attestation.command("show")
@click.argument("attestation_uid", type=str)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["eas", "json", "yaml"], case_sensitive=False),
    default="eas",
    help="Output format (default: eas)",
)
@click.pass_context
def show_attestation(
    ctx: click.Context, attestation_uid: str, output_format: str
) -> None:
    """Display attestation information.

    \b
    Example:
      eas-tools -n base-sepolia attestation show 0xceffa19c412727fa6ea41ce8f685a397d93d744c5314f19c39fa7b007a985c41
    """
    network = ctx.obj["network"]
    show_attestation_impl(attestation_uid, output_format, network)


@attestation.command()
@click.argument("attestation_uid", type=str)
@click.option(
    "--format",
    "-f",
    "format",
    type=click.Choice(["json", "yaml", "proto"], case_sensitive=False),
    default="json",
    help="Output format (default: json)",
)
@click.option(
    "--encoding",
    "-e",
    "encoding",
    type=click.Choice(["binary", "base64", "hex", "json"], case_sensitive=False),
    default="json",
    help="Encoding format (default: json, only relevant for proto)",
)
@click.option(
    "--namespace",
    "namespace",
    type=str,
    help='Protobuf namespace (e.g., "vendor.v1") - only for protobuf',
)
@click.option(
    "--message-type",
    "-m",
    "message_type",
    type=str,
    help='Full message type name (e.g., "vendor.v1.message_0x1234") - only for protobuf',
)
@click.pass_context
def decode(
    ctx: click.Context,
    attestation_uid: str,
    format: str,
    encoding: str,
    namespace: Optional[str],
    message_type: Optional[str],
) -> None:
    """Decode attestation data using its schema.

    Retrieves the attestation and its schema, then parses the attestation
    data according to the schema structure.

    \b
    Example:
      eas-tools -n base-sepolia attestation decode 0xceff...
    """
    network = ctx.obj["network"]
    encode_schema_impl(
        attestation_uid, format, encoding, namespace, message_type, network
    )


@schema.command()
@click.argument("schema_uid", type=str)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["eas", "json", "yaml", "proto"], case_sensitive=False),
    default="eas",
    help="Output format (default: eas)",
)
@click.pass_context
def generate(ctx: click.Context, schema_uid: str, output_format: str) -> None:
    """Generate code from schema definition.

    \b
    Example:
      eas-tools -n base-sepolia schema generate 0x86ad... --format proto
    """
    network = ctx.obj["network"]
    generate_schema_impl(schema_uid, output_format, network)


# Query commands group
@main.group()
def query() -> None:
    """🔍 Bulk query operations

    Search for multiple attestations and schemas with comprehensive filtering.
    """
    pass


def format_attestation_results(
    attestations: list, output_format: str = "table"
) -> None:
    """Format attestation query results using Rich."""
    if not attestations:
        console.print("🔍 No attestations found matching the specified criteria.")
        return

    if output_format == "json":
        # Convert to JSON serializable format
        results = []
        for att in attestations:
            result = {
                "uid": att.uid,
                "schema_uid": att.schema_uid,
                "attester": att.attester,
                "recipient": att.recipient,
                "time": att.time,
                "expiration_time": att.expiration_time,
                "revocable": att.revocable,
                "revoked": att.revoked,
            }
            if att.ref_uid:
                result["ref_uid"] = att.ref_uid
            if att.data:
                result["data"] = att.data
            results.append(result)

        json_str = json.dumps(results, indent=2)
        syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
        console.print(syntax)
        return

    # Table format (default)
    table = Table(
        title=f"[bold blue]Found {len(attestations)} Attestation(s)[/bold blue]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("UID", style="cyan", no_wrap=True, max_width=20)
    table.add_column("Schema", style="yellow", no_wrap=True, max_width=20)
    table.add_column("Attester", style="green", no_wrap=True, max_width=20)
    table.add_column("Recipient", style="blue", no_wrap=True, max_width=20)
    table.add_column("Revoked", style="white", no_wrap=True)
    table.add_column("Time", style="white", no_wrap=True)

    for att in attestations[:50]:  # Limit display to first 50 for readability
        uid_short = f"{att.uid[:6]}...{att.uid[-6:]}" if len(att.uid) > 16 else att.uid
        schema_short = (
            f"{att.schema_uid[:6]}...{att.schema_uid[-6:]}"
            if len(att.schema_uid) > 16
            else att.schema_uid
        )
        attester_short = (
            f"{att.attester[:6]}...{att.attester[-6:]}"
            if len(att.attester) > 16
            else att.attester
        )
        recipient_short = (
            f"{att.recipient[:6]}...{att.recipient[-6:]}"
            if len(att.recipient) > 16
            else att.recipient
        )

        revoked_status = "[red]Yes[/red]" if att.revoked else "[green]No[/green]"
        time_display = str(att.time) if att.time else "Unknown"

        table.add_row(
            uid_short,
            schema_short,
            attester_short,
            recipient_short,
            revoked_status,
            time_display,
        )

    if len(attestations) > 50:
        console.print(
            f"\n⚠️  Showing first 50 results. Total found: {len(attestations)}"
        )
        console.print(
            "Use --limit and --offset parameters or --format json to see all results."
        )

    console.print(table)


def format_schema_results(schemas: list, output_format: str = "table") -> None:
    """Format schema query results using Rich."""
    if not schemas:
        console.print("🔍 No schemas found matching the specified criteria.")
        return

    if output_format == "json":
        # Convert to JSON serializable format
        results = []
        for schema in schemas:
            result = {
                "uid": schema.uid,
                "schema": schema.schema_definition,
                "creator": schema.creator,
                "resolver": schema.resolver,
                "revocable": schema.revocable,
            }
            if schema.time:
                result["time"] = schema.time
            if schema.txid:
                result["txid"] = schema.txid
            results.append(result)

        json_str = json.dumps(results, indent=2)
        syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
        console.print(syntax)
        return

    # Table format (default)
    table = Table(
        title=f"[bold blue]Found {len(schemas)} Schema(s)[/bold blue]",
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("UID", style="cyan", no_wrap=True, max_width=20)
    table.add_column("Creator", style="green", no_wrap=True, max_width=20)
    table.add_column("Resolver", style="blue", no_wrap=True, max_width=20)
    table.add_column("Revocable", style="white", no_wrap=True)
    table.add_column("Schema", style="yellow", max_width=40)

    for schema in schemas[:50]:  # Limit display to first 50 for readability
        uid_short = (
            f"{schema.uid[:6]}...{schema.uid[-6:]}"
            if len(schema.uid) > 16
            else schema.uid
        )
        creator_short = (
            f"{schema.creator[:6]}...{schema.creator[-6:]}"
            if len(schema.creator) > 16
            else schema.creator
        )
        resolver_short = (
            f"{schema.resolver[:6]}...{schema.resolver[-6:]}"
            if len(schema.resolver) > 16
            else schema.resolver
        )

        revocable_status = "[green]Yes[/green]" if schema.revocable else "[red]No[/red]"
        schema_display = (
            (schema.schema_definition[:37] + "...")
            if len(schema.schema_definition) > 40
            else schema.schema_definition
        )

        table.add_row(
            uid_short, creator_short, resolver_short, revocable_status, schema_display
        )

    if len(schemas) > 50:
        console.print(f"\n⚠️  Showing first 50 results. Total found: {len(schemas)}")
        console.print(
            "Use --limit and --offset parameters or --format json to see all results."
        )

    console.print(table)


@query.command()
@click.option("--schema", help="Filter by schema UID")
@click.option("--attester", "--sender", help="Filter by attester/sender address")
@click.option("--recipient", help="Filter by recipient address")
@click.option(
    "--revocable/--non-revocable", default=None, help="Filter by revocable status"
)
@click.option("--revoked/--active", default=None, help="Filter by revoked status")
@click.option(
    "--expirable/--non-expirable",
    default=None,
    help="Filter by whether attestation has expiration set",
)
@click.option(
    "--expired/--valid", default=None, help="Filter by whether attestation is expired"
)
@click.option(
    "--expires-before",
    type=int,
    help="Filter attestations that expire before this timestamp",
)
@click.option(
    "--expires-after",
    type=int,
    help="Filter attestations that expire after this timestamp",
)
@click.option(
    "--created-after", type=int, help="Filter attestations created after this timestamp"
)
@click.option(
    "--created-before",
    type=int,
    help="Filter attestations created before this timestamp",
)
@click.option(
    "--limit", type=int, default=100, help="Maximum results (1-1000, default: 100)"
)
@click.option("--offset", type=int, default=0, help="Result offset for pagination")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@click.pass_context
def attestations(
    ctx: click.Context,
    schema: Optional[str],
    attester: Optional[str],
    recipient: Optional[str],
    revocable: Optional[bool],
    revoked: Optional[bool],
    expirable: Optional[bool],
    expired: Optional[bool],
    expires_before: Optional[int],
    expires_after: Optional[int],
    created_after: Optional[int],
    created_before: Optional[int],
    limit: int,
    offset: int,
    format: str,
) -> None:
    """Search for attestations with comprehensive filtering.

    \b
    Examples:
      # Find all attestations for a schema
      eas-tools -n base-sepolia query attestations --schema 0x86ad...

      # Find all attestations by an attester/sender (both options work)
      eas-tools -n base-sepolia query attestations --attester 0x0E9A64...
      eas-tools -n base-sepolia query attestations --sender 0x0E9A64...

      # Find attestations for a recipient
      eas-tools -n base-sepolia query attestations --recipient 0x742D35...

      # Find active (non-revoked) attestations
      eas-tools query attestations --recipient 0x742D35... --active

      # Find expired attestations
      eas-tools query attestations --expired

      # Find attestations that expire before a timestamp (Unix epoch)
      eas-tools query attestations --expires-before 1735689600

      # Find revocable attestations created in the last day
      eas-tools query attestations --revocable --created-after 1726147200

      # Get results as JSON with pagination
      eas-tools query attestations --limit 50 --offset 100 --format json
    """
    try:
        network = ctx.obj["network"]
        client = EASQueryClient(network=network)

        # Build filter
        filters = AttestationFilter(
            schema_uid=SchemaUID(schema) if schema else None,
            attester=Address(attester) if attester else None,
            recipient=Address(recipient) if recipient else None,
            ref_uid=None,
            revocable=revocable,
            revoked=revoked,
            is_offchain=None,
            expirable=expirable,
            expired=expired,
            expires_before=expires_before,
            expires_after=expires_after,
            time_after=created_after,
            time_before=created_before,
            limit=limit,
            offset=offset,
            sort_by=AttestationSortBy.TIME,
            sort_order=SortOrder.DESC,
        )

        console.print(f"🔍 Searching for attestations on {network}...")
        results = client.find_attestations(filters)
        format_attestation_results(results, format)

    except Exception as e:
        console.print(f"❌ Query failed: {e}", style="red")
        sys.exit(1)


@query.command()
@click.option("--creator", help="Filter by schema creator address")
@click.option("--resolver", help="Filter by resolver address")
@click.option(
    "--revocable/--non-revocable", default=None, help="Filter by revocable status"
)
@click.option(
    "--resolvable/--non-resolvable",
    default=None,
    help="Filter by whether schema has a resolver contract",
)
@click.option(
    "--created-after", type=int, help="Filter schemas created after this timestamp"
)
@click.option(
    "--created-before", type=int, help="Filter schemas created before this timestamp"
)
@click.option(
    "--limit", type=int, default=100, help="Maximum results (1-1000, default: 100)"
)
@click.option("--offset", type=int, default=0, help="Result offset for pagination")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
@click.pass_context
def schemas(
    ctx: click.Context,
    creator: Optional[str],
    resolver: Optional[str],
    revocable: Optional[bool],
    resolvable: Optional[bool],
    created_after: Optional[int],
    created_before: Optional[int],
    limit: int,
    offset: int,
    format: str,
) -> None:
    """Search for schemas with comprehensive filtering.

    \b
    Examples:
      # Find all schemas by a creator
      eas-tools -n mainnet query schemas --creator 0x1234...

      # Find revocable schemas
      eas-tools query schemas --revocable

      # Find schemas with resolver contracts (resolvable)
      eas-tools query schemas --resolvable

      # Find schemas created after a timestamp (Unix epoch)
      eas-tools query schemas --created-after 1726147200

      # Get results as JSON with pagination
      eas-tools query schemas --limit 25 --format json
    """
    try:
        network = ctx.obj["network"]
        client = EASQueryClient(network=network)

        # Build filter
        filters = SchemaFilter(
            creator=Address(creator) if creator else None,
            resolver=Address(resolver) if resolver else None,
            revocable=revocable,
            resolvable=resolvable,
            time_after=created_after,
            time_before=created_before,
            limit=limit,
            offset=offset,
            sort_by=SchemaSortBy.TIME,
            sort_order=SortOrder.DESC,
        )

        console.print(f"🔍 Searching for schemas on {network}...")
        results = client.find_schemas(filters)
        format_schema_results(results, format)

    except Exception as e:
        console.print(f"❌ Query failed: {e}", style="red")
        sys.exit(1)


# Revoke command
@main.command()
@click.argument("attestation_uid", type=str)
@click.option(
    "--private-key",
    "-k",
    help="Private key for signing (or use EAS_PRIVATE_KEY env var)",
)
@click.option(
    "--from-account",
    help="From account address (or use EAS_FROM_ACCOUNT env var, or derive from private key)",
)
@click.option(
    "--dry-run", is_flag=True, help="Show transaction details without submitting"
)
@click.option("--gas-limit", type=int, help="Custom gas limit (optional)")
@click.pass_context
def revoke(
    ctx: click.Context,
    attestation_uid: str,
    private_key: Optional[str],
    from_account: Optional[str],
    dry_run: bool,
    gas_limit: Optional[int],
) -> None:
    """Revoke an attestation by UID.

    This command submits a revocation transaction to the blockchain.
    You can provide credentials via command line options or environment variables.

    \b
    Environment Variables:
      EAS_PRIVATE_KEY     - Private key for signing transactions
      EAS_FROM_ACCOUNT    - Account address (optional, derived from private key)
      EAS_CHAIN          - Network name (uses --network flag if not set)

    \b
    Examples:
      # Using environment variables
      export EAS_PRIVATE_KEY=0x1234...
      export EAS_CHAIN=base-sepolia
      eas-tools revoke 0xceff19c412727fa6ea41ce8f685a397d93d744c5314f19c39fa7b007a985c41

      # Using command line options
      eas-tools -n base-sepolia revoke 0xceff... --private-key 0x1234...

      # Dry run to see transaction details
      eas-tools -n base-sepolia revoke 0xceff... --dry-run
    """
    try:
        network = ctx.obj["network"]

        console.print(f"🔐 Preparing to revoke attestation on {network}...")
        console.print(f"    Attestation UID: {attestation_uid}")

        # Get private key from CLI option or environment
        if not private_key:
            private_key = os.environ.get("EAS_PRIVATE_KEY")
            if not private_key:
                console.print(
                    "❌ Private key required. Use --private-key or set EAS_PRIVATE_KEY environment variable.",
                    style="red",
                )
                sys.exit(1)

        # Derive from_account from private key if not provided
        if not from_account:
            from_account = os.environ.get("EAS_FROM_ACCOUNT")
            if not from_account:
                # Derive address from private key
                try:
                    account = Web3().eth.account.from_key(private_key)
                    from_account = account.address
                    console.print(f"    Derived address: {from_account}")
                except Exception as e:
                    console.print(
                        f"❌ Failed to derive address from private key: {e}",
                        style="red",
                    )
                    sys.exit(1)

        console.print(f"    From account: {from_account}")

        if dry_run:
            console.print("\n🔍 DRY RUN - Transaction will not be submitted")
            console.print(f"    Network: {network}")
            console.print(f"    Attestation UID: {attestation_uid}")
            console.print(f"    From account: {from_account}")
            if gas_limit:
                console.print(f"    Gas limit: {gas_limit}")
            console.print("    Operation: revoke_attestation()")
            return

        # Set chain environment variable if not already set
        if not os.environ.get("EAS_CHAIN"):
            os.environ["EAS_CHAIN"] = network
        if not os.environ.get("EAS_PRIVATE_KEY"):
            os.environ["EAS_PRIVATE_KEY"] = private_key
        if not os.environ.get("EAS_FROM_ACCOUNT"):
            os.environ["EAS_FROM_ACCOUNT"] = from_account

        # Create EAS instance
        console.print("    Creating EAS instance...")
        eas = EAS.from_environment()

        # Submit revocation transaction
        console.print("    Submitting revocation transaction...")
        result = eas.revoke_attestation(attestation_uid)

        # Display results
        console.print(
            "✅ Revocation transaction submitted successfully!", style="green"
        )
        console.print(f"    Transaction hash: [blue]{result.tx_hash}[/blue]")

        if hasattr(result, "gas_used") and result.gas_used:
            console.print(f"    Gas used: {result.gas_used}")
        if hasattr(result, "block_number") and result.block_number:
            console.print(f"    Block number: {result.block_number}")

        console.print("\n🔗 View on explorer:")
        if network == "mainnet":
            console.print(f"    https://etherscan.io/tx/{result.tx_hash}")
        elif network == "sepolia":
            console.print(f"    https://sepolia.etherscan.io/tx/{result.tx_hash}")
        elif network == "base":
            console.print(f"    https://basescan.org/tx/{result.tx_hash}")
        elif network == "base-sepolia":
            console.print(f"    https://sepolia.basescan.org/tx/{result.tx_hash}")
        elif network == "optimism":
            console.print(f"    https://optimistic.etherscan.io/tx/{result.tx_hash}")
        elif network == "arbitrum":
            console.print(f"    https://arbiscan.io/tx/{result.tx_hash}")

    except EASValidationError as e:
        console.print(f"❌ Validation error: {e}", style="red")
        sys.exit(1)
    except EASTransactionError as e:
        # Try to extract user-friendly error message from EAS contract errors
        error_msg = str(e)
        if "('0x" in error_msg or "Contract error" in error_msg:
            friendly_msg = get_eas_error_message(error_msg)
            console.print(f"❌ Revocation failed: {friendly_msg}", style="red")
        else:
            console.print(f"❌ Transaction error: {e}", style="red")
        sys.exit(1)
    except EASError as e:
        console.print(f"❌ EAS error: {e}", style="red")
        sys.exit(1)
    except Exception as e:
        # Try to extract user-friendly error message for any other contract errors
        error_msg = str(e)
        if "('0x" in error_msg:
            friendly_msg = get_eas_error_message(error_msg)
            console.print(f"❌ Revocation failed: {friendly_msg}", style="red")
        else:
            console.print(f"❌ Revocation failed: {e}", style="red")
        sys.exit(1)


# Development Commands
def get_venv_python() -> str:
    """Get path to virtual environment Python."""
    venv_path = Path(".venv")
    if os.name == "nt":
        python_path = venv_path / "Scripts" / "python.exe"
    else:
        python_path = venv_path / "bin" / "python"

    if python_path.exists():
        return str(python_path)

    return sys.executable


def run_command(
    cmd: list[str], description: str = "Running command", check: bool = True
) -> bool:
    """Run a command with nice output."""
    console.print(f"🔧 {description}...")
    console.print(f"   Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=check)
        if result.returncode == 0:
            console.print(f"   ✅ {description} completed")
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        console.print(f"   ❌ {description} failed with code {e.returncode}")
        return False
    except FileNotFoundError:
        console.print(f"   ❌ Command not found: {cmd[0]}")
        return False


@main.group()
def dev() -> None:
    """🔧 Development tools

    Commands for EAS SDK development and debugging.
    """
    pass


@dev.command()
def setup() -> None:
    """Set up development environment."""
    console.print("🚀 EAS SDK Development Setup")
    console.print("=" * 30)

    # Check if we're in a virtual environment
    if hasattr(sys, "real_prefix") or (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    ):
        console.print("✅ Virtual environment detected")
    else:
        console.print("⚠️  No virtual environment detected. Consider using:")
        console.print("   python -m venv .venv")
        console.print("   source .venv/bin/activate  # Linux/Mac")
        console.print("   .venv\\Scripts\\activate     # Windows")

    # Install development dependencies
    python = get_venv_python()
    console.print("📦 Installing development dependencies...")
    success = run_command(
        [python, "-m", "pip", "install", "-e", ".[dev]"], "Installing dev dependencies"
    )

    if success:
        console.print("✅ Development environment ready!")
        console.print("\n🎯 Next steps:")
        console.print("   • Copy env.example to .env and configure")
        console.print("   • Run: eas-tools dev test")
        console.print("   • Run: eas-tools dev example quick-start")
    else:
        console.print("❌ Setup failed")
        sys.exit(1)


@dev.command()
@click.argument(
    "test_type", type=click.Choice(["unit", "integration", "all"]), default="unit"
)
def test(test_type: str) -> None:
    """Run tests with smart selection."""
    python = get_venv_python()

    # Check if Task is available
    if Path("Taskfile.yml").exists():
        try:
            if test_type == "unit":
                cmd = ["task", "test:unit"]
            elif test_type == "integration":
                cmd = ["task", "test:integration"]
            elif test_type == "all":
                cmd = ["task", "test:all"]
            else:
                cmd = ["task", "test:unit"]  # Default

            success = run_command(cmd, f"Running {test_type} tests")
            if not success:
                sys.exit(1)
            return
        except Exception:
            pass

    # Fallback to direct pytest
    cmd = [python, "-m", "pytest", "-v"]
    if test_type == "unit":
        cmd.extend(["-m", "not requires_network and not requires_private_key"])
    elif test_type == "integration":
        cmd.extend(["-m", "integration and not requires_private_key"])

    cmd.append("src/test")
    success = run_command(cmd, f"Running {test_type} tests")
    if not success:
        sys.exit(1)


@dev.command()
def format() -> None:
    """Format code."""
    python = get_venv_python()

    if Path("Taskfile.yml").exists():
        success = run_command(["task", "format"], "Formatting code")
        if not success:
            sys.exit(1)
        return

    # Fallback to direct commands
    success = True
    success &= run_command([python, "-m", "black", "src"], "Running black")
    success &= run_command([python, "-m", "isort", "src"], "Running isort")
    if not success:
        sys.exit(1)


@dev.command()
def check() -> None:
    """Run all code quality checks."""
    if Path("Taskfile.yml").exists():
        success = run_command(["task", "check"], "Running all checks")
        if not success:
            sys.exit(1)
        return

    python = get_venv_python()
    success = True
    success &= run_command(
        [python, "-m", "black", "--check", "src"], "Checking formatting"
    )
    success &= run_command([python, "-m", "flake8", "src"], "Running linter")
    success &= run_command([python, "-m", "mypy", "src/main"], "Running type checker")
    if not success:
        sys.exit(1)


@dev.command()
@click.option("--mainnet", is_flag=True, help="Show only mainnet chains")
@click.option("--testnet", is_flag=True, help="Show only testnet chains")
def chains(mainnet: bool, testnet: bool) -> None:
    """List supported chains."""
    python = get_venv_python()

    if testnet:
        filter_cmd = (
            "testnet_chains = get_testnet_chains(); print('\\n'.join(testnet_chains))"
        )
    elif mainnet:
        filter_cmd = (
            "mainnet_chains = get_mainnet_chains(); print('\\n'.join(mainnet_chains))"
        )
    else:
        filter_cmd = (
            "all_chains = list_supported_chains(); print('\\n'.join(all_chains))"
        )

    cmd = [
        python,
        "-c",
        f"from eas import list_supported_chains, get_mainnet_chains, get_testnet_chains; {filter_cmd}",
    ]

    success = run_command(cmd, "Listing supported chains", check=False)
    if not success:
        sys.exit(1)


@dev.command()
@click.argument("name", type=click.Choice(["quick-start", "full", "multi-chain"]))
def example(name: str) -> None:
    """Run example scripts."""
    python = get_venv_python()

    examples = {
        "quick-start": "examples/quick_start.py",
        "full": "examples/full_example.py",
        "multi-chain": "examples/multi_chain_examples.py",
    }

    example_path = examples[name]
    if not Path(example_path).exists():
        console.print(f"❌ Example file not found: {example_path}")
        sys.exit(1)

    cmd = [python, example_path]
    success = run_command(cmd, f"Running {name} example")
    if not success:
        sys.exit(1)


@dev.command()
def clean() -> None:
    """Clean build artifacts."""
    if Path("Taskfile.yml").exists():
        success = run_command(["task", "clean"], "Cleaning artifacts")
        if not success:
            sys.exit(1)
        return

    # Manual cleanup
    import shutil

    patterns = [
        "build",
        "dist",
        "*.egg-info",
        ".pytest_cache",
        "__pycache__",
        ".coverage",
        "htmlcov",
    ]

    for pattern in patterns:
        for path in Path(".").glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
                console.print(f"   🗑️  Removed directory: {path}")
            else:
                path.unlink()
                console.print(f"   🗑️  Removed file: {path}")

    console.print("   ✅ Clean completed")


@dev.command()
def build() -> None:
    """Build the package."""
    if Path("Taskfile.yml").exists():
        success = run_command(["task", "build"], "Building package")
        if not success:
            sys.exit(1)
        return

    python = get_venv_python()
    success = run_command([python, "-m", "build"], "Building package")
    if not success:
        sys.exit(1)


@dev.command()
def shell() -> None:
    """Start interactive shell with EAS imported."""
    python = get_venv_python()

    startup_code = """
import sys
print("🚀 EAS SDK Interactive Shell")
print("="*30)

try:
    from eas import EAS, list_supported_chains, get_network_config
    print("✅ EAS SDK imported successfully")
    print()
    print("Available objects:")
    print("  • EAS - Main EAS class")
    print("  • list_supported_chains() - List all chains")
    print("  • get_network_config(chain) - Get chain config")
    print()
    print("Quick start:")
    print("  chains = list_supported_chains()")
    print("  eas = EAS.from_environment()  # Requires .env setup")
    print()
except ImportError as e:
    print(f"❌ Failed to import EAS SDK: {e}")
    print("   Make sure you've run: eas-tools dev setup")
"""

    # Write startup script to temp file
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(startup_code)
        startup_file = f.name

    try:
        cmd = [python, "-i", startup_file]
        subprocess.run(cmd)
    finally:
        os.unlink(startup_file)


if __name__ == "__main__":
    main()
