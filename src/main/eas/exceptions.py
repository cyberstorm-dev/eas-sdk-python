"""
Secure exception handling for EAS SDK operations.

Provides a clean error hierarchy for different types of failures,
enabling proper error handling and debugging context while preventing
information disclosure through sanitized error messages.
"""

import re
from typing import Any, Dict, Optional

# Import strong types from our types module
# Note: Type imports removed as they were unused - add back as needed


class EASError(Exception):
    """Base exception for all EAS SDK operations with secure message handling."""

    def __init__(self, message: str, context: Optional[Dict[str, Any]] = None):
        # Sanitize message to prevent information disclosure
        sanitized_message = self._sanitize_error_message(message)
        super().__init__(sanitized_message)

        # Sanitize context to prevent sensitive data leakage
        self.context = self._sanitize_context(context or {})

    @staticmethod
    def _sanitize_error_message(message: str) -> str:
        """Sanitize error messages to prevent sensitive data disclosure"""
        if not message:
            return "Unknown error occurred"

        # Remove private keys (0x followed by 64 hex chars)
        message = re.sub(r"0x[a-fA-F0-9]{64}", "[PRIVATE_KEY_REDACTED]", message)

        # Sanitize addresses (keep first 6 and last 4 chars)
        def sanitize_address(match: re.Match[str]) -> str:
            addr = match.group(0)
            if len(addr) >= 10:
                return f"{addr[:6]}...{addr[-4:]}"
            return "[ADDRESS_REDACTED]"

        message = re.sub(r"0x[a-fA-F0-9]{40}", sanitize_address, message)

        # Remove URLs but keep domain info
        def sanitize_url(match: re.Match[str]) -> str:
            url = match.group(0)
            try:
                from urllib.parse import urlparse

                parsed = urlparse(url)
                return f"{parsed.scheme}://{parsed.netloc}/..."
            except Exception:
                return "[URL_REDACTED]"

        message = re.sub(r'https?://[^\s<>"\']+', sanitize_url, message)

        # Remove file paths
        message = re.sub(r'/[^\s<>"\']*', "[PATH_REDACTED]", message)

        return message

    @staticmethod
    def _sanitize_context(context: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize context dictionary to prevent sensitive data leakage"""
        if not context:
            return {}

        from .security import SecureEnvironmentValidator

        sanitized_context = {}
        sensitive_fields = {
            "private_key": "private_key",
            "tx_hash": "transaction_hash",
            "from_account": "address",
            "to_account": "address",
            "recipient": "address",
            "contract_address": "address",
            "rpc_url": "url",
            "attestation_uid": "uid",
            "schema_uid": "uid",
        }

        for key, value in context.items():
            if key in sensitive_fields and value:
                sanitized_context[key] = (
                    SecureEnvironmentValidator.sanitize_for_logging(
                        str(value), sensitive_fields[key]
                    )
                )
            else:
                sanitized_context[key] = value

        return sanitized_context


class EASValidationError(EASError):
    """Input validation failures before blockchain operations with secure field handling."""

    def __init__(
        self, message: str, field_name: Optional[str] = None, field_value: Any = None
    ):
        context = {}
        if field_name:
            context["field_name"] = field_name
        if field_value is not None:
            # Sanitize field value to prevent information disclosure
            if isinstance(field_value, str):
                # Never log private keys or other sensitive values
                if field_name in ["private_key", "secret", "password", "token"]:
                    context["field_value"] = "[REDACTED]"
                elif field_name in [
                    "address",
                    "from_account",
                    "to_account",
                    "recipient",
                ]:
                    from .security import SecureEnvironmentValidator

                    context["field_value"] = (
                        SecureEnvironmentValidator.sanitize_for_logging(
                            field_value, "address"
                        )
                    )
                elif len(str(field_value)) > 50:  # Truncate very long values
                    context["field_value"] = str(field_value)[:47] + "..."
                else:
                    context["field_value"] = field_value
            else:
                context["field_value"] = field_value
        super().__init__(message, context)


class EASTransactionError(EASError):
    """Blockchain transaction failures with secure transaction context."""

    def __init__(
        self,
        message: str,
        tx_hash: Optional[str] = None,
        receipt: Optional[Dict[str, Any]] = None,
    ):
        context = {}
        if tx_hash:
            # Sanitize transaction hash for logging
            from .security import SecureEnvironmentValidator

            context["tx_hash"] = SecureEnvironmentValidator.sanitize_for_logging(
                tx_hash, "transaction_hash"
            )
        if receipt:
            # Include only non-sensitive receipt information
            context["gas_used"] = receipt.get("gasUsed", 0)
            context["block_number"] = receipt.get("blockNumber", 0)
            context["transaction_status"] = receipt.get("status", 0)
            # Don't include full receipt to avoid potential information disclosure
        super().__init__(message, context)


class EASNetworkError(EASError):
    """RPC/network connectivity issues with secure context."""

    def __init__(
        self,
        message: str,
        rpc_url: Optional[str] = None,
        network_name: Optional[str] = None,
    ):
        context = {}
        if rpc_url:
            # Sanitize RPC URL to prevent disclosure of API keys or sensitive endpoints
            from .security import SecureEnvironmentValidator

            context["rpc_url"] = SecureEnvironmentValidator.sanitize_for_logging(
                rpc_url, "url"
            )
        if network_name:
            context["network_name"] = network_name
        super().__init__(message, context)


class EASContractError(EASError):
    """Smart contract interaction failures with secure context."""

    def __init__(
        self,
        message: str,
        contract_address: Optional[str] = None,
        method_name: Optional[str] = None,
    ):
        context = {}
        if contract_address:
            # Sanitize contract address for logging
            from .security import SecureEnvironmentValidator

            context["contract_address"] = (
                SecureEnvironmentValidator.sanitize_for_logging(
                    contract_address, "address"
                )
            )
        if method_name:
            context["method_name"] = method_name
        super().__init__(message, context)


class EASSecurityError(EASError):
    """Security validation and threat detection failures."""

    def __init__(
        self, message: str, threat_type: Optional[str] = None, severity: str = "high"
    ):
        context = {"security_event": True, "severity": severity}
        if threat_type:
            context["threat_type"] = threat_type
        super().__init__(message, context)
