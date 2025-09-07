import os
import sys
from unittest.mock import Mock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from main.EAS.core import EAS


class TestEAS:
    """Test cases for the EAS class"""

    @pytest.fixture
    def mock_web3(self):
        """Mock web3 instance"""
        mock_w3 = Mock()
        mock_w3.is_connected.return_value = True
        mock_w3.eth.get_transaction_count.return_value = 0
        mock_w3.eth.send_raw_transaction.return_value = b"tx_hash"
        mock_w3.eth.wait_for_transaction_receipt.return_value = {"status": 1}
        mock_w3.to_hex.side_effect = lambda x: f"0x{x.hex()}"
        mock_w3.keccak.return_value = b"keccak_hash"
        return mock_w3

    @pytest.fixture
    def mock_contract(self):
        """Mock contract instance"""
        mock_contract = Mock()
        mock_contract.address = "0x1234567890123456789012345678901234567890"
        mock_contract.functions.attest.return_value.estimate_gas.return_value = 100000
        mock_contract.functions.attest.return_value.build_transaction.return_value = {
            "from": "0x1234567890123456789012345678901234567890",
            "gas": 100000,
            "nonce": 0,
        }
        return mock_contract

    @patch("main.EAS.core.web3.Web3")
    @patch("builtins.open")
    @patch("json.load")
    def test_init_success(
        self, mock_json_load, mock_open, mock_web3_class, mock_web3, mock_contract
    ):
        """Test successful initialization of EAS class"""
        # Setup mocks
        mock_web3_class.HTTPProvider.return_value = Mock()
        mock_web3_class.return_value = mock_web3
        mock_web3.eth.contract.return_value = mock_contract
        mock_json_load.return_value = [{"type": "function"}]

        # Test initialization
        eas = EAS(
            rpc_url="https://test.com",
            contract_address="0x1234567890123456789012345678901234567890",
            chain_id=1,
            contract_version="0.26",
            from_account="0x1234567890123456789012345678901234567890",
            private_key="0x1234567890123456789012345678901234567890123456789012345678901234",
        )

        assert eas.from_account == "0x1234567890123456789012345678901234567890"
        assert eas.chain_id == 1
        assert eas.contract_version == "0.26"

    @patch("main.EAS.core.web3.Web3")
    def test_init_connection_failure(self, mock_web3_class):
        """Test initialization failure when web3 connection fails"""
        # Setup mock to return False for is_connected
        mock_w3 = Mock()
        mock_w3.is_connected.return_value = False
        mock_web3_class.return_value = mock_w3

        # Test that exception is raised
        with pytest.raises(Exception, match="Failed to connect to Ethereum network"):
            EAS(
                rpc_url="https://test.com",
                contract_address="0x1234567890123456789012345678901234567890",
                chain_id=1,
                contract_version="0.26",
                from_account="0x1234567890123456789012345678901234567890",
                private_key="0x1234567890123456789012345678901234567890123456789012345678901234",
            )

    def test_get_offchain_uid_version_0(self, mock_web3, mock_contract):
        """Test get_offchain_uid with version 0"""
        with (
            patch("main.EAS.core.web3.Web3") as mock_web3_class,
            patch("builtins.open"),
            patch("json.load") as mock_json_load,
        ):

            mock_web3_class.return_value = mock_web3
            mock_web3.eth.contract.return_value = mock_contract
            mock_json_load.return_value = [{"type": "function"}]

            eas = EAS(
                rpc_url="https://test.com",
                contract_address="0x1234567890123456789012345678901234567890",
                chain_id=1,
                contract_version="0.26",
                from_account="0x1234567890123456789012345678901234567890",
                private_key="0x1234567890123456789012345678901234567890123456789012345678901234",
            )

            uid = eas.get_offchain_uid(
                version=0,
                schema="test_schema",
                recipient="0x1234567890123456789012345678901234567890",
                time=1234567890,
                expiration_time=1234567899,
                revocable=True,
                ref_uid="0x0000000000000000000000000000000000000000000000000000000000000000",
                data=b"test_data",
            )

            assert uid == "6b656363616b5f68617368"  # hex of b'keccak_hash'

    def test_get_offchain_uid_version_1(self, mock_web3, mock_contract):
        """Test get_offchain_uid with version 1"""
        with (
            patch("main.EAS.core.web3.Web3") as mock_web3_class,
            patch("builtins.open"),
            patch("json.load") as mock_json_load,
        ):

            mock_web3_class.return_value = mock_web3
            mock_web3.eth.contract.return_value = mock_contract
            mock_json_load.return_value = [{"type": "function"}]

            eas = EAS(
                rpc_url="https://test.com",
                contract_address="0x1234567890123456789012345678901234567890",
                chain_id=1,
                contract_version="0.26",
                from_account="0x1234567890123456789012345678901234567890",
                private_key="0x1234567890123456789012345678901234567890123456789012345678901234",
            )

            # Version 1 should now work with EIP-712 implementation
            uid_v1 = eas.get_offchain_uid(
                version=1,
                schema="0x1234567890123456789012345678901234567890123456789012345678901234",
                recipient="0x1234567890123456789012345678901234567890",
                time=1234567890,
                expiration_time=1234567899,
                revocable=True,
                ref_uid="0x0000000000000000000000000000000000000000000000000000000000000000",
                data=b"test_data",
            )

            # Should return a valid hex string UID
            assert uid_v1.startswith("0x")
            assert len(uid_v1) == 66  # 0x + 64 hex characters = 32 bytes

            # Should be deterministic - same inputs should produce same UID
            uid_v1_repeat = eas.get_offchain_uid(
                version=1,
                schema="0x1234567890123456789012345678901234567890123456789012345678901234",
                recipient="0x1234567890123456789012345678901234567890",
                time=1234567890,
                expiration_time=1234567899,
                revocable=True,
                ref_uid="0x0000000000000000000000000000000000000000000000000000000000000000",
                data=b"test_data",
            )
            assert uid_v1 == uid_v1_repeat

    def test_get_offchain_uid_unsupported_version(self, mock_web3, mock_contract):
        """Test get_offchain_uid with unsupported version"""
        with (
            patch("main.EAS.core.web3.Web3") as mock_web3_class,
            patch("builtins.open"),
            patch("json.load") as mock_json_load,
        ):

            mock_web3_class.return_value = mock_web3
            mock_web3.eth.contract.return_value = mock_contract
            mock_json_load.return_value = [{"type": "function"}]

            eas = EAS(
                rpc_url="https://test.com",
                contract_address="0x1234567890123456789012345678901234567890",
                chain_id=1,
                contract_version="0.26",
                from_account="0x1234567890123456789012345678901234567890",
                private_key="0x1234567890123456789012345678901234567890123456789012345678901234",
            )

            with pytest.raises(ValueError, match="Unsupported version"):
                eas.get_offchain_uid(
                    version=2,
                    schema="test_schema",
                    recipient="0x1234567890123456789012345678901234567890",
                    time=1234567890,
                    expiration_time=1234567899,
                    revocable=True,
                    ref_uid="0x0000000000000000000000000000000000000000000000000000000000000000",
                    data=b"test_data",
                )
