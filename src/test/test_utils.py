"""
Test utilities for EAS SDK tests.

Provides utilities for conditional test skipping based on environment configuration
and helper functions for test setup.
"""

import os

import pytest
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def has_private_key() -> bool:
    """Check if a private key is available in environment variables or .env file."""
    private_key = os.getenv("PRIVATE_KEY", "").strip()
    # Check if it's not empty and not the default example value
    return bool(
        private_key
        and private_key
        != "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    )


def has_network_config() -> bool:
    """Check if network configuration is available for testing."""
    return bool(os.getenv("RPC_URL") or os.getenv("NETWORK"))


def requires_private_key(func):
    """Decorator to skip tests that require a real private key for live write operations."""
    return pytest.mark.skipif(
        not has_private_key(),
        reason="Requires PRIVATE_KEY in environment or .env file for live write operations",
    )(func)


def requires_network(func):
    """Decorator to skip tests that require network connectivity."""
    return pytest.mark.skipif(
        not has_network_config(),
        reason="Requires network configuration (RPC_URL or NETWORK) for integration tests",
    )(func)


# Pytest fixtures for common test setup
@pytest.fixture
def mock_private_key():
    """Provide a mock private key for unit tests."""
    return "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


@pytest.fixture
def mock_address():
    """Provide a mock Ethereum address for unit tests."""
    return "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD"


@pytest.fixture
def mock_tx_hash():
    """Provide a mock transaction hash for unit tests."""
    return "0xb1384f2ce6c62162d880e287fd0452846f7668cad837377c4146f204d3e4d892"


@pytest.fixture
def mock_schema_uid():
    """Provide a mock schema UID for unit tests."""
    return "0x9848ff2e4109233f6eedad4fd2625bb899f124e8e5c195c2180a63366fb9860b"


@pytest.fixture
def mock_attestation_uid():
    """Provide a mock attestation UID for unit tests."""
    return "0xa58dadd91e62f3030573457de6ccd829e8c3805e8696c047318850c3a35c365f"
