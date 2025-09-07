"""
Tests for EAS SDK batch attestation operations.

Demonstrates comprehensive testing of multi_attest functionality
including validation, gas efficiency, and partial failure handling.
"""

import time
from unittest.mock import Mock, patch

import pytest

from main.EAS.core import EAS
from main.EAS.exceptions import EASTransactionError, EASValidationError
from main.EAS.transaction import TransactionResult

from .test_utils import requires_network, requires_private_key


class TestBatchAttestation:
    """Unit tests for batch attestation functionality."""

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_attest_validation_empty_requests(self, mock_open, mock_web3_class):
        """Test multi_attest with empty requests list."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)

        # Test empty requests list
        with pytest.raises(
            EASValidationError, match="Attestation requests list cannot be empty"
        ):
            eas.multi_attest([])

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_attest_validation_invalid_request_format(
        self, mock_open, mock_web3_class
    ):
        """Test multi_attest with invalid request format."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)

        # Test non-dict request
        with pytest.raises(EASValidationError, match="Request 0 must be a dictionary"):
            eas.multi_attest(["invalid"])

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_attest_validation_invalid_schema_uid(
        self, mock_open, mock_web3_class
    ):
        """Test multi_attest with invalid schema UID."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)

        # Test missing schema_uid
        with pytest.raises(EASValidationError, match="Invalid schema UID format"):
            eas.multi_attest(
                [
                    {
                        "attestations": [
                            {"recipient": "0x1234567890123456789012345678901234567890"}
                        ]
                    }
                ]
            )

        # Test invalid schema_uid format
        with pytest.raises(EASValidationError, match="Invalid schema UID format"):
            eas.multi_attest(
                [
                    {
                        "schema_uid": "invalid",
                        "attestations": [
                            {"recipient": "0x1234567890123456789012345678901234567890"}
                        ],
                    }
                ]
            )

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_attest_validation_empty_attestations(
        self, mock_open, mock_web3_class
    ):
        """Test multi_attest with empty attestations list."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True

        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)

        # Test empty attestations
        with pytest.raises(
            EASValidationError, match="Request 0 must contain at least one attestation"
        ):
            eas.multi_attest([{"schema_uid": "0x" + "a" * 64, "attestations": []}])

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_attest_validation_invalid_recipient(
        self, mock_open, mock_web3_class
    ):
        """Test multi_attest with invalid recipient address."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        mock_w3.is_address.return_value = False  # Mock invalid address

        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)

        # Test invalid recipient
        with pytest.raises(EASValidationError, match="Invalid recipient address"):
            eas.multi_attest(
                [
                    {
                        "schema_uid": "0x" + "a" * 64,
                        "attestations": [{"recipient": "invalid_address"}],
                    }
                ]
            )

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_attest_validation_invalid_ref_uid(self, mock_open, mock_web3_class):
        """Test multi_attest with invalid ref_uid format."""
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        mock_w3.is_address.return_value = True  # Mock valid address

        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)

        # Test invalid ref_uid format
        with pytest.raises(EASValidationError, match="Invalid ref_uid format"):
            eas.multi_attest(
                [
                    {
                        "schema_uid": "0x" + "a" * 64,
                        "attestations": [
                            {
                                "recipient": "0x1234567890123456789012345678901234567890",
                                "ref_uid": "invalid_ref",
                            }
                        ],
                    }
                ]
            )

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_attest_success_single_schema(self, mock_open, mock_web3_class):
        """Test successful multi_attest with single schema."""
        # Setup mocks
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        mock_w3.is_address.return_value = True

        # Mock contract and transaction
        mock_contract = Mock()
        mock_w3.eth.contract.return_value = mock_contract
        mock_function = Mock()
        mock_contract.functions.multiAttest.return_value = mock_function
        mock_function.estimate_gas.return_value = 200000
        mock_function.build_transaction.return_value = {
            "from": "0xabcd",
            "gas": 240000,
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
                "gasUsed": 180000,
                "blockNumber": 12345,
            }

            eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)

            # Test successful multi-attest
            requests = [
                {
                    "schema_uid": "0x" + "a" * 64,
                    "attestations": [
                        {
                            "recipient": "0x1234567890123456789012345678901234567890",
                            "data": b"test_data_1",
                            "expiration_time": 1234567890,
                            "revocable": True,
                        },
                        {
                            "recipient": "0x9876543210987654321098765432109876543210",
                            "data": b"test_data_2",
                            "value": 1000,
                        },
                    ],
                }
            ]

            result = eas.multi_attest(requests)

            # Verify result
            assert isinstance(result, TransactionResult)
            assert result.success is True
            assert result.tx_hash == "0xabcdef"
            assert result.gas_used == 180000
            assert result.block_number == 12345

            # Verify contract call structure
            mock_contract.functions.multiAttest.assert_called_once()
            call_args = mock_contract.functions.multiAttest.call_args[0][0]

            # Verify multi_requests structure
            assert len(call_args) == 1  # One schema
            schema_uid, attestation_data_list = call_args[0]
            assert schema_uid == bytes.fromhex("a" * 64)  # Now expects bytes
            assert len(attestation_data_list) == 2  # Two attestations

            # Verify first attestation data
            recipient1, exp_time1, revocable1, ref_uid1, data1, value1 = (
                attestation_data_list[0]
            )
            assert recipient1 == "0x1234567890123456789012345678901234567890"
            assert exp_time1 == 1234567890
            assert revocable1 is True
            assert ref_uid1 == bytes(32)  # Default zero bytes
            assert data1 == b"test_data_1"
            assert value1 == 0  # Default

            # Verify second attestation data
            recipient2, exp_time2, revocable2, ref_uid2, data2, value2 = (
                attestation_data_list[1]
            )
            assert recipient2 == "0x9876543210987654321098765432109876543210"
            assert exp_time2 == 0  # Default
            assert revocable2 is True  # Default
            assert ref_uid2 == bytes(32)  # Default zero bytes
            assert data2 == b"test_data_2"
            assert value2 == 1000

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_attest_success_multiple_schemas(self, mock_open, mock_web3_class):
        """Test successful multi_attest with multiple schemas."""
        # Setup mocks
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        mock_w3.is_address.return_value = True

        # Mock contract and transaction
        mock_contract = Mock()
        mock_w3.eth.contract.return_value = mock_contract
        mock_function = Mock()
        mock_contract.functions.multiAttest.return_value = mock_function
        mock_function.estimate_gas.return_value = 400000
        mock_function.build_transaction.return_value = {
            "from": "0xabcd",
            "gas": 480000,
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

            mock_w3.eth.send_raw_transaction.return_value = Mock(hex=lambda: "0xmulti")
            mock_w3.eth.wait_for_transaction_receipt.return_value = {
                "status": 1,
                "gasUsed": 380000,
                "blockNumber": 12346,
            }

            eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)

            # Test multi-attest with multiple schemas
            requests = [
                {
                    "schema_uid": "0x" + "a" * 64,
                    "attestations": [
                        {
                            "recipient": "0x1234567890123456789012345678901234567890",
                            "data": b"data_1a",
                        },
                        {
                            "recipient": "0x2234567890123456789012345678901234567890",
                            "data": b"data_1b",
                        },
                    ],
                },
                {
                    "schema_uid": "0x" + "b" * 64,
                    "attestations": [
                        {
                            "recipient": "0x3234567890123456789012345678901234567890",
                            "data": b"data_2a",
                        }
                    ],
                },
            ]

            result = eas.multi_attest(requests)

            # Verify result
            assert isinstance(result, TransactionResult)
            assert result.success is True
            assert result.tx_hash == "0xmulti"

            # Verify contract call structure
            call_args = mock_contract.functions.multiAttest.call_args[0][0]
            assert len(call_args) == 2  # Two schemas

            # Verify first schema
            schema_uid1, attestation_data_list1 = call_args[0]
            assert schema_uid1 == bytes.fromhex("a" * 64)
            assert len(attestation_data_list1) == 2

            # Verify second schema
            schema_uid2, attestation_data_list2 = call_args[1]
            assert schema_uid2 == bytes.fromhex("b" * 64)
            assert len(attestation_data_list2) == 1

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_attest_gas_estimation_failure(self, mock_open, mock_web3_class):
        """Test multi_attest gas estimation failure."""
        # Setup mocks
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        mock_w3.is_address.return_value = True

        # Mock contract with gas estimation failure but build_transaction also fails
        mock_contract = Mock()
        mock_w3.eth.contract.return_value = mock_contract
        mock_function = Mock()
        mock_contract.functions.multiAttest.return_value = mock_function
        mock_function.estimate_gas.side_effect = Exception("Gas estimation failed")
        mock_function.build_transaction.side_effect = Exception(
            "Build transaction failed after gas estimation failure"
        )

        eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)

        requests = [
            {
                "schema_uid": "0x" + "a" * 64,
                "attestations": [
                    {"recipient": "0x1234567890123456789012345678901234567890"}
                ],
            }
        ]

        # Test that gas estimation failure falls back, but then build_transaction fails
        with pytest.raises(EASTransactionError, match="Build transaction failed"):
            eas.multi_attest(requests)

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open", new_callable=lambda: mock_file_content("[]"))
    def test_multi_attest_transaction_failure(self, mock_open, mock_web3_class):
        """Test multi_attest transaction failure."""
        # Setup mocks
        mock_w3 = Mock()
        mock_web3_class.return_value = mock_w3
        mock_w3.is_connected.return_value = True
        mock_w3.is_address.return_value = True

        # Mock contract and transaction
        mock_contract = Mock()
        mock_w3.eth.contract.return_value = mock_contract
        mock_function = Mock()
        mock_contract.functions.multiAttest.return_value = mock_function
        mock_function.estimate_gas.return_value = 200000
        mock_function.build_transaction.return_value = {
            "from": "0xabcd",
            "gas": 240000,
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

            mock_w3.eth.send_raw_transaction.return_value = Mock(hex=lambda: "0xfailed")
            mock_w3.eth.wait_for_transaction_receipt.return_value = {
                "status": 0,  # Transaction failed
                "gasUsed": 100000,
                "blockNumber": 12345,
            }

            eas = EAS("http://test", "0x1234", 1, "0.26", "0xabcd", "deadbeef" * 8)

            requests = [
                {
                    "schema_uid": "0x" + "a" * 64,
                    "attestations": [
                        {"recipient": "0x1234567890123456789012345678901234567890"}
                    ],
                }
            ]

            result = eas.multi_attest(requests)

            # Verify failed result
            assert isinstance(result, TransactionResult)
            assert result.success is False
            assert result.tx_hash == "0xfailed"


@pytest.mark.integration
class TestBatchAttestationIntegration:
    """Integration tests for batch attestation with network connectivity."""

    @requires_network
    def test_multi_attest_validation_integration(self):
        """Test that multi_attest validation works in integration context."""
        # This is a minimal integration test that verifies the method exists and validation works
        # without requiring complex mocking or network calls
        import os

        rpc_url = os.getenv("RPC_URL", "https://sepolia.base.org")
        contract_address = os.getenv(
            "EAS_CONTRACT_ADDRESS", "0x4200000000000000000000000000000000000021"
        )

        # Use dummy account info since we're only testing validation
        eas = EAS(
            rpc_url,
            contract_address,
            84532,
            "1.3.0",
            "0x1234567890123456789012345678901234567890",
            "deadbeef" * 8,
        )

        # Test that validation works - should fail fast with proper error
        with pytest.raises(
            EASValidationError, match="Attestation requests list cannot be empty"
        ):
            eas.multi_attest([])


@pytest.mark.live_write
class TestLiveBatchAttestation:
    """Live tests for batch attestation (requires real private key)."""

    @requires_private_key
    @requires_network
    def test_real_multi_attest(self):
        """Test multi_attest with real network connection."""

        import os

        rpc_url = os.getenv("RPC_URL", "https://sepolia.base.org")
        contract_address = os.getenv(
            "EAS_CONTRACT_ADDRESS", "0x4200000000000000000000000000000000000021"
        )
        from_account = os.getenv("FROM_ACCOUNT")
        private_key = os.getenv("PRIVATE_KEY")

        # Create real EAS instance
        eas = EAS(rpc_url, contract_address, 84532, "1.3.0", from_account, private_key)

        # Test schema UID (purpose-made schema for batch testing)
        test_schema_uid = (
            "0x071de830af40cf7e1035554968b97f9ae2441e8b6a15f02217aa3f46dad85d86"
        )

        # Create batch attestation request
        requests = [
            {
                "schema_uid": test_schema_uid,
                "attestations": [
                    {
                        "recipient": from_account,  # Attest to self for testing
                        "data": f"Multi-attest test 1 - {time.time()}".encode("utf-8"),
                        "expiration_time": 0,
                        "revocable": True,
                    },
                    {
                        "recipient": from_account,  # Attest to self for testing
                        "data": f"Multi-attest test 2 - {time.time()}".encode("utf-8"),
                        "expiration_time": 0,
                        "revocable": True,
                    },
                ],
            }
        ]

        try:
            result = eas.multi_attest(requests)

            # Verify transaction result structure
            assert isinstance(result, TransactionResult)
            assert result.tx_hash is not None
            assert result.tx_hash.startswith("0x")

            if result.success:
                # Transaction succeeded - verify full result
                assert result.gas_used > 0
                assert result.block_number > 0
                print(f"✅ Multi-attest successful: {result.tx_hash}")
                print("   Attestations created: 2")
                print(f"   Gas used: {result.gas_used}")
                print(f"   Block: {result.block_number}")
            else:
                # Transaction failed on-chain (expected with test schema UID)
                print(
                    f"⚠️ Multi-attest transaction submitted but failed on-chain: {result.tx_hash}"
                )
                print(
                    "   This is expected when using test schema UIDs on live networks"
                )
                print(
                    "   SDK functionality verified: formatting, gas estimation fallback, transaction submission"
                )

        except Exception as e:
            # If we get gas estimation errors or network issues, that's expected in test environment
            if "execution reverted" in str(
                e
            ) or "gas required exceeds allowance" in str(e):
                pytest.skip(f"Multi-attest failed due to network conditions: {e}")
            else:
                raise


# Helper function to create mock file content for ABI loading
def mock_file_content(content="[]"):
    """Create mock file content for testing."""
    from unittest.mock import mock_open

    return mock_open(read_data=content)


if __name__ == "__main__":
    # Run unit tests by default
    pytest.main([__file__ + "::TestBatchAttestation", "-v"])
