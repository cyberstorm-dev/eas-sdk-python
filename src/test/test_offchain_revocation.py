"""
Tests for EAS SDK off-chain revocation operations.

Demonstrates comprehensive testing of off-chain revocation functionality
including EIP-712 signing, validation, and data structures.
"""

import time
from unittest.mock import Mock, patch

import pytest

from main.EAS.core import EAS
from main.EAS.exceptions import EASValidationError

from .test_utils import has_private_key, requires_network, requires_private_key


class TestOffchainRevocation:
    """Unit tests for off-chain revocation functionality."""

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_revoke_offchain_validation(self, mock_open, mock_web3_class):
        """Test off-chain revocation input validation."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS(
            "http://test",
            "0x4200000000000000000000000000000000000021",
            1,
            "0.26",
            "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD",
            "deadbeef" * 8,
        )

        # Test invalid UID format
        with pytest.raises(EASValidationError, match="Invalid attestation UID format"):
            eas.revoke_offchain("")

        with pytest.raises(EASValidationError, match="Invalid attestation UID format"):
            eas.revoke_offchain("invalid-uid")

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_get_offchain_revocation_uid_version_0(self, mock_open, mock_web3_class):
        """Test off-chain revocation UID calculation for version 0."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        mock_w3.keccak.return_value = b"mock_uid"

        eas = EAS(
            "http://test",
            "0x4200000000000000000000000000000000000021",
            1,
            "0.26",
            "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD",
            "deadbeef" * 8,
        )

        message = {
            "version": 0,
            "schema": "0x0000000000000000000000000000000000000000",
            "uid": "0xtest",
            "value": 0,
            "time": 1234567890,
            "salt": "0xsalt",
        }

        uid = eas.get_offchain_revocation_uid(message, version=0)

        assert uid == b"mock_uid"
        mock_w3.keccak.assert_called_once()

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_get_offchain_revocation_uid_version_1(self, mock_open, mock_web3_class):
        """Test off-chain revocation UID calculation for version 1 - now works with EIP-712 implementation."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS(
            "http://test",
            "0x4200000000000000000000000000000000000021",
            1,
            "0.26",
            "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD",
            "deadbeef" * 8,
        )

        message = {
            "version": 1,
            "schema": "0x071de830af40cf7e1035554968b97f9ae2441e8b6a15f02217aa3f46dad85d86",
            "uid": "0xa58dadd91e62f3030573457de6ccd829e8c3805e8696c047318850c3a35c365f",
            "value": 0,
            "time": 1234567890,
            "salt": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        }

        # Version 1 should now work with EIP-712 implementation
        uid = eas.get_offchain_revocation_uid(message, version=1)

        # Should return bytes object
        assert isinstance(uid, bytes)
        assert len(uid) == 32  # 32 bytes

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_get_offchain_revocation_uid_invalid_version(
        self, mock_open, mock_web3_class
    ):
        """Test off-chain revocation UID calculation with invalid version."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS(
            "http://test",
            "0x4200000000000000000000000000000000000021",
            1,
            "0.26",
            "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD",
            "deadbeef" * 8,
        )

        message = {"uid": "0xtest"}

        with pytest.raises(
            ValueError, match="Unsupported off-chain revocation UID version: 99"
        ):
            eas.get_offchain_revocation_uid(message, version=99)

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    @patch("main.EAS.core.os.urandom")
    @patch("main.EAS.core.time.time")
    def test_revoke_offchain_success(
        self, mock_time, mock_urandom, mock_open, mock_web3_class
    ):
        """Test off-chain revocation - currently blocked by EIP-712 implementation issues."""
        # Setup mocks
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        mock_time.return_value = 1234567890
        mock_urandom.return_value = b"salt_bytes_32_length_salt_bytes"

        eas = EAS(
            "http://test",
            "0x4200000000000000000000000000000000000021",
            1,
            "0.26",
            "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD",
            "deadbeef" * 8,
        )

        # Version 1 should now work with EIP-712 implementation
        # Mock the get_offchain_revocation_uid to return a predictable value
        with patch.object(
            eas,
            "get_offchain_revocation_uid",
            return_value=b"mock_uid_32_bytes_long_padded_x",
        ):
            result = eas.revoke_offchain(
                attestation_uid="0xa58dadd91e62f3030573457de6ccd829e8c3805e8696c047318850c3a35c365f",
                schema_uid="0x071de830af40cf7e1035554968b97f9ae2441e8b6a15f02217aa3f46dad85d86",
                value=100,
                reason="Test revocation",
            )

            # Should return a properly structured revocation
            assert isinstance(result, dict)
            assert "revoker" in result
            assert "uid" in result
            assert "data" in result
            assert result["revoker"] == eas.from_account

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_revoke_offchain_default_parameters(self, mock_open, mock_web3_class):
        """Test off-chain revocation with default parameters - currently blocked by EIP-712 issues."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS(
            "http://test",
            "0x4200000000000000000000000000000000000021",
            1,
            "0.26",
            "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD",
            "deadbeef" * 8,
        )

        # Version 1 should now work with EIP-712 implementation
        with patch.object(
            eas,
            "get_offchain_revocation_uid",
            return_value=b"mock_uid_32_bytes_long_padded_x",
        ):
            result = eas.revoke_offchain(
                "0xa58dadd91e62f3030573457de6ccd829e8c3805e8696c047318850c3a35c365f"
            )

            # Should return a properly structured revocation with defaults
            assert isinstance(result, dict)
            assert "revoker" in result
            assert "uid" in result
            assert "data" in result


@pytest.mark.integration
class TestOffchainRevocationIntegration:
    """Integration tests for off-chain revocation with network connectivity."""

    @requires_network
    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_offchain_revocation_structure(self, mock_open, mock_web3_class):
        """Test that off-chain revocation returns proper structure."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS(
            "http://test",
            "0x4200000000000000000000000000000000000021",
            84532,
            "1.3.0",
            "0xcc084F7A8d127C5F56C6293852609c9feE7b27eD",
            "deadbeef" * 8,
        )

        # Mock required methods for integration test
        with patch.object(eas, "get_offchain_revocation_uid", return_value=b"mock_uid"):
            # Mock eth_account functions that are now used for EIP-712
            mock_signable_message = Mock()
            with patch(
                "eth_account.messages.encode_typed_data",
                return_value=mock_signable_message,
            ):
                mock_account = Mock()
                mock_signed_message = Mock()
                mock_signed_message.r = int("0x" + "a" * 64, 16)
                mock_signed_message.s = int("0x" + "b" * 64, 16)
                mock_signed_message.v = 28
                mock_account.sign_message.return_value = mock_signed_message
                with patch("eth_account.Account.from_key", return_value=mock_account):
                    with patch("main.EAS.core.os.urandom", return_value=b"salt" * 8):
                        with patch("main.EAS.core.time.time", return_value=1234567890):

                            result = eas.revoke_offchain(
                                attestation_uid="0x" + "a" * 64,
                                reason="Integration test revocation",
                            )

                            # Verify complete structure
                            assert isinstance(result, dict)
                            assert len(result["uid"]) > 0
                            assert result["revoker"].startswith("0x")

                            # Verify EIP-712 domain
                            domain = result["data"]["domain"]
                            assert domain["name"] == "EAS Attestation"
                            assert domain["version"] == "1.3.0"
                            assert domain["chainId"] == 84532
                            assert (
                                domain["verifyingContract"]
                                == "0x4200000000000000000000000000000000000021"
                            )

                            # Verify types structure
                            types = result["data"]["types"]
                            assert "Revoke" in types
                            revoke_type = types["Revoke"]
                            expected_fields = [
                                "version",
                                "schema",
                                "uid",
                                "value",
                                "time",
                                "salt",
                            ]
                            assert len(revoke_type) == len(expected_fields)
                            for field in revoke_type:
                                assert field["name"] in expected_fields
                                assert "type" in field


@pytest.mark.live_write
class TestLiveOffchainRevocation:
    """Live tests for off-chain revocation (requires real private key)."""

    @requires_private_key
    @requires_network
    def test_real_offchain_revocation(self):
        """Test off-chain revocation with real cryptographic operations."""
        assert has_private_key()

        import os

        rpc_url = os.getenv("RPC_URL", "https://sepolia.base.org")
        contract_address = os.getenv(
            "EAS_CONTRACT_ADDRESS", "0x4200000000000000000000000000000000000021"
        )
        from_account = os.getenv("FROM_ACCOUNT")
        private_key = os.getenv("PRIVATE_KEY")

        # Create real EAS instance
        eas = EAS(rpc_url, contract_address, 84532, "1.3.0", from_account, private_key)

        # Use a mock attestation UID for testing
        test_attestation_uid = "0x" + "1234567890abcdef" * 8  # 64 hex chars

        # This should now work with EIP-712 implementation
        result = eas.revoke_offchain(test_attestation_uid)

        # Should return a properly structured revocation
        assert isinstance(result, dict)
        assert "revoker" in result
        assert "uid" in result
        assert "data" in result


# Helper function to create mock file content for ABI loading
def mock_file_content(content="[]"):
    """Create mock file content for testing."""
    from unittest.mock import mock_open

    return mock_open(read_data=content)


if __name__ == "__main__":
    # Run unit tests by default
    pytest.main([__file__ + "::TestOffchainRevocation", "-v"])
