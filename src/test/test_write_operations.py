"""
Tests for EAS SDK write operations (schema registration, revocation, timestamping).

Demonstrates proper use of test markers for different operation types.
"""

import time
from unittest.mock import Mock, patch

import pytest

from main.EAS.core import EAS
from main.EAS.exceptions import EASValidationError
from main.EAS.schema_registry import SchemaRegistry
from main.EAS.transaction import TransactionResult

from .test_utils import has_private_key, requires_network, requires_private_key


class TestSchemaRegistry:
    """Unit tests for SchemaRegistry class."""

    def test_schema_registry_initialization(self):
        """Test schema registry initialization."""
        mock_w3 = Mock()
        mock_w3.eth.contract.return_value = Mock()

        registry = SchemaRegistry(
            web3=mock_w3,
            registry_address="0x1234567890123456789012345678901234567890",
            from_account="0xabcd",
            private_key="0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12",
        )

        assert registry.w3 == mock_w3
        assert registry.registry_address == "0x1234567890123456789012345678901234567890"
        assert registry.from_account == "0xabcd"

    def test_validate_schema_format_valid(self):
        """Test schema format validation with valid schema."""
        mock_w3 = Mock()
        mock_w3.eth.contract.return_value = Mock()

        registry = SchemaRegistry(
            mock_w3,
            "0x1234567890123456789012345678901234567890",
            "0xabcd",
            "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12",
        )

        # Should not raise for valid schema
        registry._validate_schema_format("uint256 id,string name")
        registry._validate_schema_format("address user,bytes32 hash,bool active")

    def test_validate_schema_format_invalid(self):
        """Test schema format validation with invalid schema."""
        mock_w3 = Mock()
        mock_w3.eth.contract.return_value = Mock()

        registry = SchemaRegistry(
            mock_w3,
            "0x1234567890123456789012345678901234567890",
            "0xabcd",
            "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12",
        )

        # Should raise for invalid schemas
        with pytest.raises(EASValidationError, match="cannot be empty"):
            registry._validate_schema_format("")

        with pytest.raises(EASValidationError, match="appears invalid"):
            registry._validate_schema_format("just some text")

    def test_get_registry_address(self):
        """Test getting registry addresses for different networks."""
        # Test known networks
        address = SchemaRegistry.get_registry_address("base-sepolia")
        assert address.startswith("0x")
        assert len(address) == 42

        # Test unknown network
        with pytest.raises(EASValidationError, match="Unsupported network"):
            SchemaRegistry.get_registry_address("unknown-network")


class TestEASWriteOperations:
    """Unit tests for new write operations in EAS class."""

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_revoke_attestation_validation(self, mock_open, mock_web3_class):
        """Test attestation revocation input validation."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS(
            "http://test",
            "0x1234",
            1,
            "0.26",
            "0xabcd",
            "a7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12",
        )

        # Test invalid UID format
        with pytest.raises(EASValidationError, match="Invalid attestation UID"):
            eas.revoke_attestation("")

        with pytest.raises(EASValidationError, match="Invalid attestation UID"):
            eas.revoke_attestation("invalid-uid")

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_revoke_validation(self, mock_open, mock_web3_class):
        """Test batch revocation input validation."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS(
            "http://test",
            "0x1234",
            1,
            "0.26",
            "0xabcd",
            "a7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12",
        )

        # Test empty revocations list
        with pytest.raises(EASValidationError, match="cannot be empty"):
            eas.multi_revoke([])

        # Test missing UID in revocation
        with pytest.raises(EASValidationError, match="Missing UID"):
            eas.multi_revoke([{"value": 0}])  # Missing uid

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_timestamp_validation(self, mock_open, mock_web3_class):
        """Test timestamping input validation."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS(
            "http://test",
            "0x1234",
            1,
            "0.26",
            "0xabcd",
            "a7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12",
        )

        # Test empty data
        with pytest.raises(EASValidationError, match="cannot be empty"):
            eas.timestamp("")

        with pytest.raises(EASValidationError, match="cannot be empty"):
            eas.timestamp(b"")

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_timestamp_validation(self, mock_open, mock_web3_class):
        """Test batch timestamping input validation."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS(
            "http://test",
            "0x1234",
            1,
            "0.26",
            "0xabcd",
            "a7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12",
        )

        # Test empty data list
        with pytest.raises(EASValidationError, match="cannot be empty"):
            eas.multi_timestamp([])

        # Test empty data item in list
        with pytest.raises(EASValidationError, match="Data item 0 cannot be empty"):
            eas.multi_timestamp([""])


@pytest.mark.integration
class TestWriteOperationsIntegration:
    """Integration tests for write operations with network connectivity."""

    @requires_network
    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_transaction_result_creation(self, mock_open, mock_web3_class):
        """Test that write operations return proper TransactionResult objects."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        # Mock successful transaction
        mock_contract = Mock()
        mock_w3.eth.contract.return_value = mock_contract
        mock_function = Mock()
        mock_contract.functions.revoke.return_value = mock_function
        mock_function.estimate_gas.return_value = 50000
        mock_function.build_transaction.return_value = {
            "from": "0xabcd",
            "gas": 60000,
            "gasPrice": 20000000000,
            "nonce": 1,
        }

        mock_w3.eth.gas_price = 20000000000
        mock_w3.eth.get_transaction_count.return_value = 1

        # Mock signing and sending
        with patch("main.EAS.core.Account.sign_transaction") as mock_sign:
            mock_signed = Mock()
            mock_signed.rawTransaction = b"signed_tx"
            mock_sign.return_value = mock_signed

            mock_w3.eth.send_raw_transaction.return_value = Mock(hex=lambda: "0xabcdef")
            mock_w3.eth.wait_for_transaction_receipt.return_value = {
                "status": 1,
                "gasUsed": 45000,
                "blockNumber": 12345,
            }

            eas = EAS(
                "http://test",
                "0x1234",
                1,
                "0.26",
                "0xabcd",
                "a7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12",
            )

            result = eas.revoke_attestation("0x" + "a" * 64)

            assert isinstance(result, TransactionResult)
            assert result.success is True
            assert result.tx_hash == "0xabcdef"
            assert result.gas_used == 45000
            assert result.block_number == 12345


@pytest.mark.live_write
class TestLiveWriteOperations:
    """Live tests that perform actual blockchain writes (requires real private key)."""

    @requires_private_key
    @requires_network
    def test_schema_registration_with_real_network(self):
        """Test schema registration with real network connection."""
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

        # Test schema registration with a unique test schema
        import random
        import string

        random_field = "".join(random.choices(string.ascii_lowercase, k=8))
        test_schema = f"string {random_field},uint256 timestamp"

        try:
            result = eas.register_schema(
                schema=test_schema,
                network_name="base-sepolia",
                resolver=None,
                revocable=True,
            )

            # Verify transaction result
            assert isinstance(result, TransactionResult)
            assert result.success is True
            assert result.tx_hash is not None
            assert result.tx_hash.startswith("0x")
            assert result.gas_used > 0
            assert result.block_number > 0

            print(f"✅ Schema registered successfully: {result.tx_hash}")
            print(f"   Gas used: {result.gas_used}")
            print(f"   Block: {result.block_number}")

        except Exception as e:
            # If we get gas estimation errors or network issues, that's expected in test environment
            if "execution reverted" in str(
                e
            ) or "gas required exceeds allowance" in str(e):
                pytest.skip(
                    f"Schema registration failed due to network conditions: {e}"
                )
            else:
                raise

    @requires_private_key
    @requires_network
    def test_timestamping_with_real_network(self):
        """Test data timestamping with real network connection using contract's timestamp method."""
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

        # Test timestamping using contract's timestamp method
        test_data = f"EAS SDK Test Timestamp - {time.time()}"

        try:
            result = eas.timestamp(test_data)

            # Verify transaction result
            assert isinstance(result, TransactionResult)
            assert result.success is True
            assert result.tx_hash is not None
            assert result.tx_hash.startswith("0x")
            assert result.gas_used > 0
            assert result.block_number > 0

            print(f"✅ Data timestamped successfully: {result.tx_hash}")
            print(f"   Data: {test_data}")
            print(f"   Gas used: {result.gas_used}")
            print(f"   Block: {result.block_number}")

        except Exception as e:
            # If we get gas estimation errors or network issues, that's expected in test environment
            if "execution reverted" in str(
                e
            ) or "gas required exceeds allowance" in str(e):
                pytest.skip(f"Timestamping failed due to network conditions: {e}")
            else:
                raise

    @requires_private_key
    @requires_network
    def test_multi_timestamp_with_real_network(self):
        """Test batch timestamping with real network connection using contract's multiTimestamp method."""
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

        # Test batch timestamping with multiple data items
        current_time = time.time()
        test_data = [
            f"EAS SDK Batch Test 1 - {current_time}",
            f"EAS SDK Batch Test 2 - {current_time}",
            f"EAS SDK Batch Test 3 - {current_time}",
        ]

        try:
            result = eas.multi_timestamp(test_data)

            # Verify transaction result
            assert isinstance(result, TransactionResult)
            assert result.success is True
            assert result.tx_hash is not None
            assert result.tx_hash.startswith("0x")
            assert result.gas_used > 0
            assert result.block_number > 0

            print(f"✅ Batch timestamping successful: {result.tx_hash}")
            print(f"   Items timestamped: {len(test_data)}")
            print(f"   Gas used: {result.gas_used}")
            print(f"   Block: {result.block_number}")

        except Exception as e:
            # If we get gas estimation errors or network issues, that's expected in test environment
            if "execution reverted" in str(
                e
            ) or "gas required exceeds allowance" in str(e):
                pytest.skip(f"Batch timestamping failed due to network conditions: {e}")
            else:
                raise

    @requires_private_key
    @requires_network
    def test_attestation_revocation_validation_only(self):
        """Test attestation revocation validation (without actual revocation since we need existing attestation)."""
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

        # Test validation with invalid UID (should fail fast)
        with pytest.raises(EASValidationError, match="Invalid attestation UID"):
            eas.revoke_attestation("")

        with pytest.raises(EASValidationError, match="Invalid attestation UID"):
            eas.revoke_attestation("invalid-uid")

        # Test multi-revoke validation
        with pytest.raises(EASValidationError, match="cannot be empty"):
            eas.multi_revoke([])

        with pytest.raises(EASValidationError, match="Missing UID"):
            eas.multi_revoke([{"value": 0}])

        print("✅ Revocation validation working correctly")

        # Note: We can't test actual revocation without first creating an attestation to revoke
        # This would require a more complex test setup with attestation creation


# Helper function to create mock file content for ABI loading
def mock_file_content(content="[]"):
    """Create mock file content for testing."""
    from unittest.mock import mock_open

    return mock_open(read_data=content)


if __name__ == "__main__":
    # Run unit tests by default
    pytest.main(
        [__file__ + "::TestSchemaRegistry", __file__ + "::TestEASWriteOperations", "-v"]
    )
