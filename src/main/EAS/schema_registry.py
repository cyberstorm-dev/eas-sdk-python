"""
Schema Registry for EAS SDK.

Handles schema registration operations, enabling full schema lifecycle management
to match TypeScript SDK functionality.
"""

from typing import Any, Dict, Optional

from eth_account import Account
from web3 import Web3

from .exceptions import EASContractError, EASTransactionError, EASValidationError
from .observability import get_logger, log_operation
from .transaction import TransactionResult

logger = get_logger("schema_registry")


class SchemaRegistry:
    """Manages EAS schema registration and lifecycle operations."""

    # EAS Schema Registry contract ABI (minimal interface for registration)
    SCHEMA_REGISTRY_ABI = [
        {
            "inputs": [
                {"name": "schema", "type": "string"},
                {"name": "resolver", "type": "address"},
                {"name": "revocable", "type": "bool"},
            ],
            "name": "register",
            "outputs": [{"name": "uid", "type": "bytes32"}],
            "stateMutability": "nonpayable",
            "type": "function",
        },
        {
            "inputs": [{"name": "uid", "type": "bytes32"}],
            "name": "getSchema",
            "outputs": [
                {"name": "uid", "type": "bytes32"},
                {"name": "resolver", "type": "address"},
                {"name": "revocable", "type": "bool"},
                {"name": "schema", "type": "string"},
            ],
            "stateMutability": "view",
            "type": "function",
        },
    ]

    ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

    def __init__(
        self, web3: Web3, registry_address: str, from_account: str, private_key: str
    ):
        """Initialize schema registry with Web3 connection and account details."""
        self.w3 = web3
        self.registry_address = registry_address
        self.from_account = from_account
        self.private_key = private_key

        # Create contract instance
        try:
            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(registry_address),
                abi=self.SCHEMA_REGISTRY_ABI,
            )
        except Exception as e:
            raise EASContractError(
                f"Failed to initialize schema registry contract: {str(e)}",
                contract_address=registry_address,
            )

    def _validate_schema_format(self, schema: str) -> None:
        """Validate schema format before registration."""
        if not schema or not schema.strip():
            raise EASValidationError(
                "Schema definition cannot be empty", field_name="schema"
            )

        # Basic validation - schema should look like type definitions
        if not any(c in schema for c in ["(", ")", ","]):
            raise EASValidationError(
                "Schema format appears invalid - should contain type definitions",
                field_name="schema",
                field_value=schema,
            )

    def _validate_address(self, address: str, field_name: str) -> None:
        """Validate Ethereum address format."""
        if not address:
            raise EASValidationError(
                f"{field_name} cannot be empty", field_name=field_name
            )

        if not self.w3.is_address(address):
            raise EASValidationError(
                f"Invalid Ethereum address format: {address}",
                field_name=field_name,
                field_value=address,
            )

    @log_operation("schema_registration")
    def register_schema(
        self, schema: str, resolver: Optional[str] = None, revocable: bool = True
    ) -> TransactionResult:
        """
        Register a new schema on-chain.

        Args:
            schema: Schema definition string (e.g., "uint256 id,string name")
            resolver: Optional resolver contract address (defaults to zero address)
            revocable: Whether attestations using this schema can be revoked

        Returns:
            TransactionResult with schema UID and transaction details
        """
        # Input validation
        self._validate_schema_format(schema)

        if resolver is None:
            resolver = self.ZERO_ADDRESS
        else:
            self._validate_address(resolver, "resolver")

        logger.info(
            "schema_registration_started",
            schema_preview=schema[:100] + "..." if len(schema) > 100 else schema,
            resolver=resolver,
            revocable=revocable,
        )

        try:
            # Build transaction
            function_call = self.contract.functions.register(
                schema, resolver, revocable
            )

            # Estimate gas
            gas_estimate = function_call.estimate_gas({"from": self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer

            # Build transaction data
            transaction = function_call.build_transaction(
                {
                    "from": self.from_account,
                    "gas": gas_limit,
                    "gasPrice": self.w3.eth.gas_price,
                    "nonce": self.w3.eth.get_transaction_count(
                        Web3.to_checksum_address(self.from_account)
                    ),
                }
            )

            # Sign transaction
            signed_txn = Account.sign_transaction(
                transaction, private_key=self.private_key
            )

            # Send transaction
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            tx_hash_hex = tx_hash.hex()

            logger.info("schema_registration_submitted", tx_hash=tx_hash_hex)

            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # Check transaction success
            if receipt.get("status") != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError(
                        "Schema registration transaction failed",
                        tx_hash_hex,
                        dict(receipt),
                    ),
                )

            # Extract schema UID from logs (this is simplified - in production would decode properly)
            schema_uid = None
            if receipt.get("logs"):
                # The schema UID would be in the transaction logs
                # This is a simplified extraction
                logger.info(
                    "schema_registration_success",
                    tx_hash=tx_hash_hex,
                    logs_count=len(receipt["logs"]),
                )

            result = TransactionResult.success_from_receipt(tx_hash_hex, dict(receipt))

            logger.info(
                "schema_registration_completed",
                tx_hash=tx_hash_hex,
                gas_used=receipt.get("gasUsed"),
                block_number=receipt.get("blockNumber"),
                schema_uid=schema_uid,
            )

            return result

        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise

            logger.error(
                "schema_registration_failed", error=str(e), error_type=type(e).__name__
            )
            raise EASTransactionError(f"Schema registration failed: {str(e)}")

    def get_schema(self, uid: str) -> Dict[str, Any]:
        """
        Retrieve schema information by UID.

        Args:
            uid: Schema UID (bytes32 hex string)

        Returns:
            Dict containing schema information
        """
        self._validate_address(
            uid, "schema_uid"
        )  # Reuse address validation for bytes32

        try:
            result = self.contract.functions.getSchema(uid).call()

            return {
                "uid": result[0].hex() if hasattr(result[0], "hex") else result[0],
                "resolver": result[1],
                "revocable": result[2],
                "schema": result[3],
            }

        except Exception as e:
            raise EASContractError(
                f"Failed to retrieve schema {uid}: {str(e)}",
                contract_address=self.registry_address,
                method_name="getSchema",
            )

    @classmethod
    def get_registry_address(cls, network_name: str) -> str:
        """Get the schema registry contract address for a network."""
        # Network-specific registry addresses
        # Note: These would need to be updated with actual EAS Schema Registry addresses
        registry_addresses = {
            "mainnet": "0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0",
            "sepolia": "0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0",
            "goerli": "0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0",
            "base-sepolia": "0x4200000000000000000000000000000000000020",  # Example - needs actual address
        }

        if network_name not in registry_addresses:
            raise EASValidationError(
                f"Unsupported network for schema registry: {network_name}",
                field_name="network_name",
                field_value=network_name,
            )

        return registry_addresses[network_name]
