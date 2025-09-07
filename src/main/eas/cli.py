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

from .schema_encoder import encode_schema_data
from .schema_generator import generate_schema_code

# Initialize Rich console
console = Console()

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

        # Parse the attestation data using new converter system
        from .attestation_converter import parse_hex_attestation_data

        parsed_attestation_data = parse_hex_attestation_data(
            attestation_data_hex, schema_definition
        )

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
@click.version_option(version="0.1.0", prog_name="EAS SDK")
def main() -> None:
    """EAS SDK Command Line Interface

    Query Ethereum Attestation Service data using GraphQL API.
    """
    pass


@main.command()
@click.argument("schema_uid", type=str)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["eas", "json", "yaml"], case_sensitive=False),
    default="eas",
    help="Output format (default: eas)",
)
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
def show_schema(schema_uid: str, output_format: str, network: str) -> None:
    """Display schema information from EAS GraphQL API."""
    show_schema_impl(schema_uid, output_format, network)


@main.command()
@click.argument("attestation_uid", type=str)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["eas", "json", "yaml"], case_sensitive=False),
    default="eas",
    help="Output format (default: eas)",
)
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
def show_attestation(attestation_uid: str, output_format: str, network: str) -> None:
    """Display attestation information from EAS GraphQL API."""
    show_attestation_impl(attestation_uid, output_format, network)


@main.command()
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
def encode_schema(
    attestation_uid: str,
    format: str,
    encoding: str,
    namespace: Optional[str],
    message_type: Optional[str],
    network: str,
) -> None:
    """Retrieve attestation data and encode it using schema-based encoding."""
    encode_schema_impl(
        attestation_uid, format, encoding, namespace, message_type, network
    )


@main.command()
@click.argument("schema_uid", type=str)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["eas", "json", "yaml", "proto"], case_sensitive=False),
    default="eas",
    help="Output format (default: eas)",
)
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
def generate_schema(schema_uid: str, output_format: str, network: str) -> None:
    """Generate code from EAS schema definition."""
    generate_schema_impl(schema_uid, output_format, network)


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
    """Development commands for EAS SDK."""
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
        f"from EAS import list_supported_chains, get_mainnet_chains, get_testnet_chains; {filter_cmd}",
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
    from EAS import EAS, list_supported_chains, get_network_config
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
