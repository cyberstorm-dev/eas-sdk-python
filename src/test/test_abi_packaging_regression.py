"""
Regression test for ABI packaging issue.

This test ensures that the EAS ABI JSON file is properly included in the package
and can be loaded by the EAS core module.

Background: In version 0.1.3, there was a bug where the eas-abi.json file was
not included in the built wheel package, causing web3.exceptions.NoABIFunctionsFound
errors when trying to create attestations.
"""

import json
import os

import pytest


class TestABIPackagingRegression:
    """Regression tests for ABI file packaging."""

    def test_abi_file_exists_in_package(self):
        """Test that the eas-abi.json file exists in the installed package."""
        from eas import core

        # Get the path that core.py uses to load the ABI
        eas_abi_path = os.path.join(
            os.path.dirname(core.__file__), "contracts", "eas-abi.json"
        )

        assert os.path.exists(eas_abi_path), (
            f"ABI file not found at {eas_abi_path}. "
            "This indicates the package-data configuration in pyproject.toml is not working."
        )

    def test_abi_file_is_valid_json(self):
        """Test that the ABI file contains valid JSON."""
        from eas import core

        eas_abi_path = os.path.join(
            os.path.dirname(core.__file__), "contracts", "eas-abi.json"
        )

        with open(eas_abi_path, "r") as f:
            abi_data = json.load(f)

        assert isinstance(
            abi_data, list
        ), "ABI should be a list of function/event definitions"
        assert len(abi_data) > 0, "ABI should contain function definitions"

    def test_abi_contains_required_functions(self):
        """Test that the ABI contains the essential EAS contract functions."""
        from eas import core

        eas_abi_path = os.path.join(
            os.path.dirname(core.__file__), "contracts", "eas-abi.json"
        )

        with open(eas_abi_path, "r") as f:
            abi_data = json.load(f)

        # Extract function names from the ABI
        function_names = set()
        for item in abi_data:
            if item.get("type") == "function":
                function_names.add(item.get("name"))

        # Check that essential EAS functions are present
        required_functions = {
            "attest",
            "attestByDelegation",
            "getAttestation",
            "multiAttest",
            "revoke",
            "revokeOffchain",
            "getSchemaRegistry",
        }

        missing_functions = required_functions - function_names
        assert not missing_functions, (
            f"ABI is missing required functions: {missing_functions}. "
            f"Available functions: {sorted(function_names)}"
        )

    @pytest.mark.requires_private_key
    def test_eas_contract_initialization_with_abi(self):
        """Test that EAS contract can be initialized with the packaged ABI."""
        pytest.skip("Test requires network connectivity and private key")
        from eas.core import EAS

        # Mock minimal parameters for EAS initialization
        # We're not testing actual blockchain interaction, just ABI loading

        try:
            # This should not raise NoABIFunctionsFound if ABI is properly loaded
            eas = EAS(
                rpc_url="https://sepolia.base.org",
                contract_address="0x4200000000000000000000000000000000000021",
                chain_id=84532,
                contract_version="0.26",
                from_account="0x0000000000000000000000000000000000000000",
                private_key="0x" + "0" * 64,
            )

            # Check that contract has functions (ABI was loaded successfully)
            contract_functions = eas.easContract.all_functions()
            assert (
                len(contract_functions) > 0
            ), "Contract should have functions if ABI is loaded correctly"

            # Check that essential functions are accessible
            attest_function = eas.easContract.get_function_by_name("attest")
            assert attest_function is not None, "attest function should be accessible"

        except Exception as e:
            if "NoABIFunctionsFound" in str(e) or "no function definitions" in str(e):
                pytest.fail(
                    f"ABI loading failed: {e}. This indicates the ABI file is not "
                    "properly included in the package or contains no function definitions."
                )
            else:
                # Other errors are acceptable (network issues, invalid private key, etc.)
                pass

    def test_package_includes_json_files_in_wheel(self):
        """
        Test that verifies JSON files are included when building the wheel.

        This test can be run after building to ensure the packaging configuration works.
        """
        # This is more of a build-time check, but we can verify the current installation
        import importlib.util

        # Get the path to the eas package
        spec = importlib.util.find_spec("eas")
        if spec is None:
            pytest.skip("EAS package not found")

        package_path = os.path.dirname(spec.origin)
        contracts_path = os.path.join(package_path, "contracts")

        assert os.path.exists(
            contracts_path
        ), "contracts directory should exist in package"

        json_files = [f for f in os.listdir(contracts_path) if f.endswith(".json")]
        assert len(json_files) > 0, (
            f"No JSON files found in {contracts_path}. "
            "Check the [tool.setuptools.package-data] configuration in pyproject.toml"
        )

        assert (
            "eas-abi.json" in json_files
        ), f"eas-abi.json not found in contracts directory. Found: {json_files}"
