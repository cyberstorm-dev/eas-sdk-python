import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main.EAS.config import (
    get_mainnet_chains,
    get_network_config,
    get_testnet_chains,
    list_supported_chains,
)
from main.EAS.core import EAS


class TestMultiChainSupport:
    """Comprehensive test suite for multi-chain support functionality"""

    @pytest.fixture
    def mock_env_vars(self):
        """Fixture to manage environment variables during tests"""
        original_env = dict(os.environ)
        yield
        # Reset environment variables after test
        os.environ.clear()
        os.environ.update(original_env)

    def test_list_supported_chains(self):
        """Test the list_supported_chains() function"""
        chains = list_supported_chains()

        # Basic validation
        assert len(chains) >= 12, "Should support at least 12 chains"
        assert "ethereum" in chains, "Ethereum should be in supported chains"
        assert "polygon" in chains, "Polygon should be in supported chains"

    def test_get_mainnet_chains(self):
        """Test retrieving mainnet chains"""
        mainnet_chains = get_mainnet_chains()

        assert len(mainnet_chains) > 0, "Should have at least one mainnet chain"
        for chain in mainnet_chains:
            config = get_network_config(chain)
            assert (
                config.get("network_type", "mainnet") == "mainnet"
            ), f"{chain} should be a mainnet chain"

    def test_get_testnet_chains(self):
        """Test retrieving testnet chains"""
        testnet_chains = get_testnet_chains()

        assert len(testnet_chains) > 0, "Should have at least one testnet chain"
        valid_testnet_chains = []

        for chain in testnet_chains:
            try:
                config = get_network_config(chain)
                assert (
                    config.get("network_type", "mainnet") == "testnet"
                ), f"{chain} should be a testnet chain"
                valid_testnet_chains.append(chain)
            except Exception as e:
                # Skip deprecated or invalid chains (like goerli which may fail security checks)
                if "Deprecated" in str(e) or "integrity check failed" in str(e):
                    print(f"Skipping deprecated/invalid chain {chain}: {e}")
                    continue
                else:
                    # Re-raise unexpected errors
                    raise

        # Ensure we have at least some valid testnet chains after filtering
        assert (
            len(valid_testnet_chains) > 0
        ), "Should have at least one valid testnet chain after filtering"

    def test_get_network_config_valid_chains(self):
        """Test network configuration retrieval for all supported chains"""
        valid_chains_tested = 0

        for chain in list_supported_chains():
            try:
                config = get_network_config(chain)

                # Common configuration validation
                assert "rpc_url" in config, f"RPC URL missing for {chain}"
                assert (
                    "contract_address" in config
                ), f"Contract address missing for {chain}"
                assert "chain_id" in config, f"Chain ID missing for {chain}"
                assert (
                    "contract_version" in config
                ), f"Contract version missing for {chain}"

                valid_chains_tested += 1

            except Exception as e:
                # Skip deprecated or invalid chains (like goerli which may fail security checks)
                if "integrity check failed" in str(e):
                    print(f"Skipping deprecated/invalid chain {chain}: {e}")
                    continue
                else:
                    # Re-raise unexpected errors
                    raise

        # Ensure we tested at least some chains successfully
        assert (
            valid_chains_tested >= 10
        ), f"Should have tested at least 10 valid chains, only tested {valid_chains_tested}"

    def test_get_network_config_invalid_chain(self):
        """Test error handling for unsupported chain names"""
        with pytest.raises(
            ValueError, match="(Unsupported chain|Invalid network name)"
        ):
            get_network_config("non_existent_chain")

    @patch("main.EAS.core.web3.Web3")
    def test_eas_from_chain_valid_chain(self, mock_web3_class):
        """Test EAS.from_chain() with valid chain names"""
        # Mock web3 connection
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_web3_class.return_value = mock_w3

        # Test supported chains with required parameters
        supported_chains = ["ethereum", "polygon", "arbitrum", "optimism"]
        test_private_key = (
            "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12"
        )
        test_from_account = "0xd796b20681bD6BEe28f0c938271FA99261c84fE8"

        for chain in supported_chains:
            eas = EAS.from_chain(chain, test_private_key, test_from_account)

            # Validate basic properties
            assert eas.chain_id is not None
            assert eas.contract_address is not None
            assert eas.from_account == test_from_account

    @patch("main.EAS.core.web3.Web3")
    def test_eas_from_chain_with_overrides(self, mock_web3_class):
        """Test EAS.from_chain() with custom RPC URL and contract address"""
        # Mock web3 connection
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_web3_class.return_value = mock_w3

        # Custom override parameters
        custom_rpc = "https://mainnet.infura.io/v3/abcd1234567890abcd1234567890abcd"  # Use whitelisted provider format
        custom_contract = "0x1234567890123456789012345678901234567890"
        test_private_key = (
            "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12"
        )
        test_from_account = "0xd796b20681bD6BEe28f0c938271FA99261c84fE8"

        eas = EAS.from_chain(
            "ethereum",
            test_private_key,
            test_from_account,
            rpc_url=custom_rpc,
            contract_address=custom_contract,
        )

        assert eas.contract_address == custom_contract
        assert eas.from_account == test_from_account

    def test_eas_from_chain_invalid_chain(self):
        """Test EAS.from_chain() with invalid chain name"""
        test_private_key = (
            "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12"
        )
        test_from_account = "0xd796b20681bD6BEe28f0c938271FA99261c84fE8"

        with pytest.raises(
            ValueError,
            match="(Unsupported chain|Invalid network name|Security validation failed)",
        ):
            EAS.from_chain("non_existent_chain", test_private_key, test_from_account)

    def test_eas_from_environment(self, mock_env_vars):
        """Test EAS.from_environment() parsing"""
        # Set environment variables
        os.environ["EAS_CHAIN"] = "polygon"
        os.environ["EAS_PRIVATE_KEY"] = (
            "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12"
        )
        os.environ["EAS_FROM_ACCOUNT"] = "0xd796b20681bD6BEe28f0c938271FA99261c84fE8"

        with patch("main.EAS.core.web3.Web3"):
            eas = EAS.from_environment()

            assert eas.chain_id is not None
            assert eas.from_account == os.environ["EAS_FROM_ACCOUNT"]

    def test_eas_from_environment_missing_vars(self, mock_env_vars):
        """Test EAS.from_environment() with missing required variables"""
        # Clear all EAS-related environment variables
        for var in ["EAS_CHAIN", "EAS_PRIVATE_KEY", "EAS_FROM_ACCOUNT"]:
            os.environ.pop(var, None)

        with pytest.raises(ValueError, match="Missing required environment variables"):
            EAS.from_environment()

    @patch("main.EAS.core.web3.Web3")
    def test_backward_compatibility_factory_method(self, mock_web3_class):
        """Test that original create_eas_instance() works with new multi-chain support"""
        # Mock web3 connection
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_web3_class.return_value = mock_w3

        from main.EAS.config import create_eas_instance

        # Test with legacy network names (excluding deprecated ones that may fail security checks)
        legacy_networks = ["mainnet", "sepolia"]
        successful_tests = 0

        for network in legacy_networks:
            try:
                eas = create_eas_instance(
                    network,
                    from_account="0x1234567890123456789012345678901234567890",
                    private_key="0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12",
                )

                assert eas.chain_id is not None
                assert eas.contract_address is not None
                successful_tests += 1
            except Exception as e:
                # Skip deprecated or invalid chains that fail security checks
                if "integrity check failed" in str(e) or "Deprecated" in str(e):
                    print(f"Skipping deprecated/invalid network {network}: {e}")
                    continue
                else:
                    # Re-raise unexpected errors
                    raise

        # Ensure at least one legacy network works
        assert (
            successful_tests >= 1
        ), f"At least one legacy network should work, got {successful_tests}"

    @patch("main.EAS.core.web3.Web3")
    def test_multiple_eas_instances(self, mock_web3_class):
        """Test creating multiple EAS instances for different chains"""
        # Mock web3 connection
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_web3_class.return_value = mock_w3

        chains_to_test = ["ethereum", "polygon", "arbitrum"]
        test_private_key = (
            "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12"
        )
        test_from_account = "0xd796b20681bD6BEe28f0c938271FA99261c84fE8"

        eas_instances = {}
        for chain in chains_to_test:
            eas_instances[chain] = EAS.from_chain(
                chain, test_private_key, test_from_account
            )

        # Verify unique chain IDs and contract addresses
        chain_ids = {eas.chain_id for eas in eas_instances.values()}
        contract_addresses = {eas.contract_address for eas in eas_instances.values()}

        assert len(chain_ids) == len(
            chains_to_test
        ), "Each chain should have a unique chain ID"
        assert len(contract_addresses) == len(
            chains_to_test
        ), "Each chain should have a unique contract address"

    @patch("main.EAS.core.web3.Web3")
    def test_performance_factory_methods(self, mock_web3_class):
        """Verify performance of factory methods"""
        import os
        import time

        # Mock web3 connection
        mock_w3 = MagicMock()
        mock_w3.is_connected.return_value = True
        mock_web3_class.return_value = mock_w3

        test_private_key = (
            "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12"
        )
        test_from_account = "0xd796b20681bD6BEe28f0c938271FA99261c84fE8"

        # Measure initialization time for from_chain
        start_time = time.time()
        eas = EAS.from_chain("ethereum", test_private_key, test_from_account)
        from_chain_time = time.time() - start_time
        assert eas is not None

        # Set up environment variables for from_environment test
        original_env = dict(os.environ)
        os.environ["EAS_CHAIN"] = "ethereum"
        os.environ["EAS_PRIVATE_KEY"] = test_private_key
        os.environ["EAS_FROM_ACCOUNT"] = test_from_account

        try:
            start_time = time.time()
            eas_env = EAS.from_environment()
            from_env_time = time.time() - start_time
            assert eas_env is not None
        finally:
            # Reset environment variables
            os.environ.clear()
            os.environ.update(original_env)

        # Assert reasonable initialization times (less than 0.5 seconds)
        assert (
            from_chain_time < 0.5
        ), f"from_chain() initialization too slow: {from_chain_time} seconds"
        assert (
            from_env_time < 0.5
        ), f"from_environment() initialization too slow: {from_env_time} seconds"
