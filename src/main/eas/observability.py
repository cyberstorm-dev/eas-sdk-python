"""
Security-aware observability utilities for EAS SDK operations.

Provides structured logging with security sanitization, operation timing,
and monitoring without exposing sensitive data.
"""

import functools
import re
import time
from typing import Any, Callable, Dict, Mapping, MutableMapping, Optional, Union

import structlog


def _security_sanitizer_processor(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> Union[Mapping[str, Any], str, bytes, bytearray, tuple[Any, ...]]:
    """Processor to sanitize sensitive data in all log entries."""
    from .security import SecureEnvironmentValidator

    # Fields that should always be sanitized
    sensitive_field_mapping = {
        "from_account": "address",
        "to_account": "address",
        "recipient": "address",
        "contract_address": "address",
        "private_key": "private_key",
        "rpc_url": "url",
        "tx_hash": "transaction_hash",
        "transaction_hash": "transaction_hash",
        "attestation_uid": "uid",
        "schema_uid": "uid",
        "uid": "uid",
        "revocation_uid": "uid",
    }

    # Sanitize known sensitive fields
    for field, field_type in sensitive_field_mapping.items():
        if field in event_dict and event_dict[field]:
            event_dict[field] = SecureEnvironmentValidator.sanitize_for_logging(
                str(event_dict[field]), field_type
            )

    # Sanitize the main message if it contains sensitive patterns
    if "event" in event_dict and isinstance(event_dict["event"], str):
        msg = event_dict["event"]

        # Sanitize private keys (0x followed by 64 hex chars)
        msg = re.sub(r"0x[a-fA-F0-9]{64}", "[PRIVATE_KEY_REDACTED]", msg)

        # Sanitize addresses (0x followed by 40 hex chars)
        msg = re.sub(
            r"0x[a-fA-F0-9]{40}",
            lambda m: SecureEnvironmentValidator.sanitize_for_logging(
                m.group(0), "address"
            ),
            msg,
        )

        # Sanitize transaction hashes and UIDs (0x followed by 64 hex chars that aren't private keys)
        msg = re.sub(
            r"(?<!private_key:\s)0x[a-fA-F0-9]{64}",
            lambda m: SecureEnvironmentValidator.sanitize_for_logging(
                m.group(0), "uid"
            ),
            msg,
        )

        event_dict["event"] = msg

    return event_dict


# Configure structlog for EAS SDK with security-aware processing
structlog.configure(
    processors=[
        _security_sanitizer_processor,  # Security sanitization first
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("eas_sdk")


def log_operation(operation_name: str) -> Callable[..., Any]:
    """Decorator to log operation start, completion, and errors with timing."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start_time = time.time()
            operation_id = f"{operation_name}_{int(start_time)}"

            # Log operation start
            logger.info(
                "operation_started", operation=operation_name, operation_id=operation_id
            )

            try:
                result = func(*args, **kwargs)
                duration = time.time() - start_time

                # Log successful completion
                log_data = {
                    "operation": operation_name,
                    "operation_id": operation_id,
                    "duration_seconds": round(duration, 3),
                    "success": True,
                }

                # Add transaction details if result has them
                if hasattr(result, "tx_hash"):
                    log_data["tx_hash"] = result.tx_hash
                if hasattr(result, "gas_used") and result.gas_used:
                    log_data["gas_used"] = result.gas_used
                if hasattr(result, "block_number") and result.block_number:
                    log_data["block_number"] = result.block_number

                logger.info("operation_completed", **log_data)
                return result

            except Exception as e:
                duration = time.time() - start_time

                # Log operation failure
                log_data = {
                    "operation": operation_name,
                    "operation_id": operation_id,
                    "duration_seconds": round(duration, 3),
                    "success": False,
                    "error": str(e),
                    "error_type": type(e).__name__,
                }

                # Add error context if available
                if hasattr(e, "context") and e.context:
                    log_data.update(e.context)

                logger.error("operation_failed", **log_data)
                raise

        return wrapper

    return decorator


def log_transaction_metrics(
    tx_result: Any, operation: str, context: Optional[Dict[str, Any]] = None
) -> None:
    """Log transaction metrics for monitoring and analysis with security sanitization."""

    log_data = {
        "operation": operation,
        "tx_hash": tx_result.tx_hash,  # Will be sanitized by processor
        "success": tx_result.success,
    }

    if tx_result.gas_used:
        log_data["gas_used"] = tx_result.gas_used

    if tx_result.block_number:
        log_data["block_number"] = tx_result.block_number

    # Sanitize context data before adding to log
    if context:
        sanitized_context = {}
        for key, value in context.items():
            if key in ["from_account", "recipient", "contract_address"]:
                sanitized_context[key] = value  # Will be sanitized by processor
            elif key in ["private_key"]:
                sanitized_context[key] = "[REDACTED]"  # Never log private keys
            elif isinstance(value, str) and len(value) > 100:
                # Truncate very long values to prevent log pollution
                sanitized_context[key] = value[:97] + "..."
            else:
                sanitized_context[key] = value
        log_data.update(sanitized_context)

    if tx_result.error:
        # Sanitize error messages to prevent information disclosure
        error_msg = str(tx_result.error)
        # Remove sensitive patterns from error messages
        error_msg = re.sub(r"0x[a-fA-F0-9]{64}", "[KEY_REDACTED]", error_msg)
        error_msg = re.sub(r"0x[a-fA-F0-9]{40}", "[ADDRESS_REDACTED]", error_msg)
        log_data["error"] = error_msg
        log_data["error_type"] = type(tx_result.error).__name__

    if tx_result.success:
        logger.info("transaction_success", **log_data)
    else:
        logger.error("transaction_failure", **log_data)


def get_logger(name: str = "eas_sdk") -> Any:
    """Get a configured structlog logger for EAS SDK operations with security sanitization."""
    return structlog.get_logger(name)


def log_security_event(
    event_type: str, details: Dict[str, Any], severity: str = "info"
) -> None:
    """
    Log security-related events with appropriate sanitization.

    Args:
        event_type: Type of security event (e.g., "validation_failed", "suspicious_activity")
        details: Event details dictionary
        severity: Log severity level ("info", "warning", "error", "critical")
    """
    from .security import SecureEnvironmentValidator  # noqa: F401

    # Sanitize all details before logging
    sanitized_details = {}
    for key, value in details.items():
        if isinstance(value, str):
            if key in ["private_key", "secret", "password", "token"]:
                sanitized_details[key] = "[REDACTED]"
            elif key in ["address", "from_account", "to_account", "recipient"]:
                sanitized_details[key] = (
                    SecureEnvironmentValidator.sanitize_for_logging(value, "address")
                )
            elif key in ["tx_hash", "uid", "attestation_uid"]:
                sanitized_details[key] = (
                    SecureEnvironmentValidator.sanitize_for_logging(value, "uid")
                )
            elif key == "rpc_url":
                sanitized_details[key] = (
                    SecureEnvironmentValidator.sanitize_for_logging(value, "url")
                )
            else:
                # Generic sanitization for other string values
                sanitized_details[key] = (
                    SecureEnvironmentValidator.sanitize_for_logging(value, "general")
                )
        else:
            sanitized_details[key] = value

    log_data = {"event_type": event_type, "security_event": True, **sanitized_details}

    security_logger = get_logger("eas_security")

    if severity == "critical":
        security_logger.critical("security_event", **log_data)
    elif severity == "error":
        security_logger.error("security_event", **log_data)
    elif severity == "warning":
        security_logger.warning("security_event", **log_data)
    else:
        security_logger.info("security_event", **log_data)
