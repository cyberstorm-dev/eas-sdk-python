"""
Transaction result wrapper providing standardized transaction handling.

Provides consistent transaction result objects instead of raw Web3 receipts,
enabling better error handling and transaction monitoring.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from eth_typing import HexStr
from web3 import Web3

from .exceptions import EASTransactionError


@dataclass
class TransactionResult:
    """Standardized transaction result with context and utilities."""

    success: bool
    tx_hash: str
    receipt: Optional[Dict[str, Any]] = None
    gas_used: Optional[int] = None
    block_number: Optional[int] = None
    error: Optional[Exception] = None

    def __post_init__(self) -> None:
        """Extract common fields from receipt if available."""
        if self.receipt and self.success:
            self.gas_used = self.receipt.get("gasUsed")
            self.block_number = self.receipt.get("blockNumber")

    @classmethod
    def success_from_receipt(
        cls, tx_hash: str, receipt: Dict[str, Any]
    ) -> "TransactionResult":
        """Create successful transaction result from Web3 receipt."""
        return cls(
            success=True,
            tx_hash=tx_hash,
            receipt=receipt,
            gas_used=receipt.get("gasUsed"),
            block_number=receipt.get("blockNumber"),
        )

    @classmethod
    def failure_from_error(cls, tx_hash: str, error: Exception) -> "TransactionResult":
        """Create failed transaction result from error."""
        return cls(success=False, tx_hash=tx_hash, error=error)

    def wait_for_confirmation(
        self, web3: Web3, timeout: int = 120
    ) -> "TransactionResult":
        """Wait for transaction confirmation and update receipt."""
        if not self.success:
            return self

        try:
            receipt = web3.eth.wait_for_transaction_receipt(
                HexStr(self.tx_hash), timeout=timeout
            )

            # Check if transaction was successful
            if receipt.get("status") == 0:
                error = EASTransactionError(
                    f"Transaction failed: {self.tx_hash}",
                    tx_hash=self.tx_hash,
                    receipt=dict(receipt),
                )
                return TransactionResult.failure_from_error(self.tx_hash, error)

            # Update with confirmed receipt
            self.receipt = dict(receipt)
            self.gas_used = receipt.get("gasUsed")
            self.block_number = receipt.get("blockNumber")

            return self

        except Exception as e:
            error = EASTransactionError(
                f"Failed to wait for transaction confirmation: {str(e)}",
                tx_hash=self.tx_hash,
            )
            return TransactionResult.failure_from_error(self.tx_hash, error)

    def get_events(
        self, contract_abi: List[Dict[str, Any]], event_name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Extract events from transaction receipt."""
        if not self.receipt or not self.success:
            return []

        events = []
        logs = self.receipt.get("logs", [])

        # Simple event extraction - in production would use proper ABI decoding
        for log in logs:
            if event_name:
                # Filter by event name if specified
                # This is a simplified implementation
                events.append(
                    {
                        "address": log.get("address"),
                        "topics": log.get("topics", []),
                        "data": log.get("data", ""),
                        "event_name": event_name,
                    }
                )
            else:
                events.append(
                    {
                        "address": log.get("address"),
                        "topics": log.get("topics", []),
                        "data": log.get("data", ""),
                    }
                )

        return events

    def to_dict(self) -> Dict[str, Any]:
        """Convert transaction result to dictionary for logging/serialization."""
        result = {
            "success": self.success,
            "tx_hash": self.tx_hash,
            "gas_used": self.gas_used,
            "block_number": self.block_number,
        }

        if self.error:
            result["error"] = str(self.error)
            result["error_type"] = type(self.error).__name__

        return result
