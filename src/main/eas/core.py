import json
import os
import time
from typing import Any, Dict, List, Optional, Union, cast

import web3
from eth_account import Account

try:
    from eth_abi import encode
except ImportError:
    encode = None  # type: ignore[assignment]

from .exceptions import EASError, EASTransactionError, EASValidationError
from .observability import get_logger, log_operation
from .schema_registry import SchemaRegistry
from .security import (
    ContractAddressValidator,
    SecureEnvironmentValidator,
    SecurityError,
)
from .transaction import TransactionResult

logger = get_logger("eas_core")


class EAS:

    ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

    def __init__(
        self,
        rpc_url: str,
        contract_address: str,
        chain_id: int,
        contract_version: str,
        from_account: str,
        private_key: str,
    ) -> None:
        self.w3 = web3.Web3(web3.HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise Exception("Failed to connect to Ethereum network")

        self.contract_address = contract_address
        self.chain_id = chain_id
        self.contract_version = contract_version
        self.from_account = from_account
        self.private_key = private_key

        # Load the ABI files
        eas_abi_path = os.path.join(
            os.path.dirname(__file__), "contracts", "eas-abi.json"
        )
        try:
            with open(eas_abi_path, "r") as eas_abi_file:
                eas_abi = json.load(eas_abi_file)
        except FileNotFoundError:
            eas_abi = []

        # Create contract instances
        self.easContract = self.w3.eth.contract(
            address=self.w3.to_checksum_address(contract_address), abi=eas_abi
        )

    @classmethod
    def from_chain(
        cls,
        chain_name: str,
        private_key: str,
        from_account: str,
        rpc_url: Optional[str] = None,
        contract_address: Optional[str] = None,
        **kwargs: Any,
    ) -> "EAS":
        """
        Create an EAS instance from a chain name with automatic configuration resolution.

        Args:
            chain_name: Name of the blockchain network (e.g., 'ethereum', 'base', 'sepolia')
            private_key: Private key for transaction signing
            from_account: Account address for transactions
            rpc_url: Optional custom RPC URL (overrides chain default)
            contract_address: Optional custom contract address (overrides chain default)
            **kwargs: Additional arguments passed to EAS constructor

        Returns:
            EAS instance configured for the specified chain

        Raises:
            ValueError: If chain name is invalid or required parameters are missing
            TypeError: If parameters have incorrect types
            ConnectionError: If unable to connect to the network

        Example:
            # Using chain defaults
            eas = EAS.from_chain('ethereum', private_key, from_account)

            # With custom RPC
            eas = EAS.from_chain('base', private_key, from_account,
                               rpc_url='https://my-custom-base-rpc.com')
        """
        from .config import get_network_config, validate_chain_config

        # Enhanced security validation using SecureEnvironmentValidator
        try:
            # Validate all inputs with comprehensive security checks
            chain_name = SecureEnvironmentValidator.validate_chain_name(chain_name)
            private_key = SecureEnvironmentValidator.validate_private_key(private_key)
            from_account = SecureEnvironmentValidator.validate_address(from_account)
        except SecurityError as e:
            logger.error("security_validation_failed", error=str(e), field=e.field_name)
            raise ValueError(f"Security validation failed: {str(e)}")

        try:
            # Get chain configuration
            config = get_network_config(chain_name)
            validate_chain_config(config, chain_name)

            # Override with provided parameters
            final_rpc_url = rpc_url if rpc_url is not None else config["rpc_url"]
            final_contract_address = (
                contract_address
                if contract_address is not None
                else config["contract_address"]
            )

            # Validate custom parameters with security checks
            if rpc_url is not None:
                try:
                    final_rpc_url = SecureEnvironmentValidator.validate_rpc_url(rpc_url)
                except SecurityError as e:
                    logger.error("rpc_url_validation_failed", error=str(e))
                    raise ValueError(f"RPC URL validation failed: {str(e)}")

            if contract_address is not None:
                try:
                    final_contract_address = (
                        SecureEnvironmentValidator.validate_address(contract_address)
                    )

                    # Verify against known EAS contracts
                    if not ContractAddressValidator.is_valid_eas_contract(
                        final_contract_address, config["chain_id"]
                    ):
                        logger.warning(
                            "unknown_contract_address",
                            address=SecureEnvironmentValidator.sanitize_for_logging(
                                final_contract_address, "address"
                            ),
                            chain_id=config["chain_id"],
                        )
                        # Allow but warn - don't fail for flexibility

                except SecurityError as e:
                    logger.error("contract_address_validation_failed", error=str(e))
                    raise ValueError(f"Contract address validation failed: {str(e)}")

            # Secure logging with sanitized sensitive information
            logger.info(
                "creating_eas_from_chain",
                chain_name=chain_name,
                chain_id=config["chain_id"],
                contract_address=SecureEnvironmentValidator.sanitize_for_logging(
                    final_contract_address, "address"
                ),
                from_account=SecureEnvironmentValidator.sanitize_for_logging(
                    from_account, "address"
                ),
                rpc_url=(
                    SecureEnvironmentValidator.sanitize_for_logging(
                        final_rpc_url, "url"
                    )
                    if final_rpc_url
                    else None
                ),
                custom_rpc=rpc_url is not None,
                custom_contract=contract_address is not None,
            )

            # Create EAS instance
            return cls(
                rpc_url=final_rpc_url,
                contract_address=final_contract_address,
                chain_id=config["chain_id"],
                contract_version=config["contract_version"],
                from_account=from_account,
                private_key=private_key,
                **kwargs,
            )

        except (ValueError, TypeError) as e:
            logger.error("eas_from_chain_failed", chain_name=chain_name, error=str(e))
            raise
        except Exception as e:
            logger.error(
                "eas_from_chain_unexpected_error", chain_name=chain_name, error=str(e)
            )
            raise EASError(
                f"Failed to create EAS instance for chain '{chain_name}': {str(e)}"
            )

    @classmethod
    def from_environment(cls, **kwargs: Any) -> "EAS":
        """
        Create an EAS instance from environment variables with comprehensive configuration support.

        Environment Variables:
            EAS_CHAIN: Chain name (required, e.g., 'ethereum', 'base', 'sepolia')
            EAS_PRIVATE_KEY: Private key for signing (required)
            EAS_FROM_ACCOUNT: Account address for transactions (required)
            EAS_RPC_URL: Custom RPC URL (optional, overrides chain default)
            EAS_CONTRACT_ADDRESS: Custom contract address (optional, overrides chain default)

        Args:
            **kwargs: Additional arguments passed to EAS constructor

        Returns:
            EAS instance configured from environment variables

        Raises:
            ValueError: If required environment variables are missing or invalid
            TypeError: If environment variables have incorrect format
            ConnectionError: If unable to connect to the network

        Example:
            # Set environment variables
            export EAS_CHAIN=ethereum
            export EAS_PRIVATE_KEY=0x1234...
            export EAS_FROM_ACCOUNT=0xabcd...

            # Create EAS instance
            eas = EAS.from_environment()
        """
        # Required environment variables
        # required_env_vars = {
        #     "EAS_CHAIN": "chain name",
        #     "EAS_PRIVATE_KEY": "private key",
        #     "EAS_FROM_ACCOUNT": "from account address",
        # }

        # Use comprehensive batch environment variable validation
        required_env_types = {
            "EAS_CHAIN": "chain_name",
            "EAS_PRIVATE_KEY": "private_key",
            "EAS_FROM_ACCOUNT": "address",
        }

        optional_env_types = {
            "EAS_RPC_URL": "rpc_url",
            "EAS_CONTRACT_ADDRESS": "address",
        }

        try:
            env_values = SecureEnvironmentValidator.validate_all_environment_variables(
                required_vars=required_env_types, optional_vars=optional_env_types
            )
        except (SecurityError, ValueError) as e:
            logger.error("environment_validation_failed", error=str(e))
            raise ValueError(f"Environment variable validation failed: {str(e)}")

        chain_name = env_values["EAS_CHAIN"]
        private_key = env_values["EAS_PRIVATE_KEY"]
        from_account = env_values["EAS_FROM_ACCOUNT"]
        rpc_url = env_values.get("EAS_RPC_URL")
        contract_address = env_values.get("EAS_CONTRACT_ADDRESS")

        # Secure logging for environment-based creation
        logger.info(
            "creating_eas_from_environment",
            chain_name=chain_name,
            from_account=SecureEnvironmentValidator.sanitize_for_logging(
                from_account, "address"
            ),
            rpc_url=(
                SecureEnvironmentValidator.sanitize_for_logging(rpc_url, "url")
                if rpc_url
                else None
            ),
            has_custom_rpc=rpc_url is not None,
            has_custom_contract=contract_address is not None,
        )

        try:
            # Use from_chain method with environment variable values
            return cls.from_chain(
                chain_name=chain_name,
                private_key=private_key,
                from_account=from_account,
                rpc_url=rpc_url,
                contract_address=contract_address,
                **kwargs,
            )

        except Exception as e:
            logger.error(
                "eas_from_environment_failed",
                chain_name=chain_name,
                from_account=(
                    SecureEnvironmentValidator.sanitize_for_logging(
                        from_account, "address"
                    )
                    if from_account
                    else None
                ),
                error=str(e),
            )
            raise EASError(f"Failed to create EAS instance from environment: {str(e)}")

    def get_attestation(self, uid: str) -> Any:
        """Get an attestation by UID."""
        try:
            attestation = self.easContract.functions.getAttestation(uid).call()
            return attestation
        except Exception as e:
            raise Exception(f"Failed to get attestation: {str(e)}")

    def get_schema(self, schema_uid: str) -> Any:
        """Get a schema by its UID."""
        try:
            schema = self.easContract.functions.getSchema(schema_uid).call()
            return schema
        except Exception as e:
            raise Exception(f"Failed to get schema: {str(e)}")

    def get_offchain_uid(
        self,
        version: int = 1,
        schema: Optional[str] = None,
        recipient: Optional[str] = None,
        time: Optional[int] = None,
        expiration_time: int = 0,
        revocable: bool = True,
        ref_uid: Optional[str] = None,
        data: bytes = b"",
        **kwargs: Any,
    ) -> str:
        """Calculate the UID for an off-chain attestation message."""
        # Build message from parameters
        message = {
            "version": version,
            "schema": schema,
            "recipient": recipient,
            "time": time,
            "expirationTime": expiration_time,
            "revocable": revocable,
            "refUID": ref_uid or "0x" + "0" * 64,
            "data": data.hex() if isinstance(data, bytes) else data,
        }
        message.update(kwargs)  # Allow additional parameters

        if version == 0:
            # Version 0 uses direct keccak
            message_bytes = json.dumps(message, sort_keys=True).encode("utf-8")
            return self.w3.keccak(message_bytes).hex()
        elif version == 1:
            # Version 1 uses EIP-712 structured data hashing
            # Create EIP-712 domain
            domain = {
                "name": "EAS Attestation",
                "version": self.contract_version,
                "chainId": self.chain_id,
                "verifyingContract": self.contract_address,
            }

            # Define EIP-712 types for attestation
            types = {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "Attest": [
                    {"name": "version", "type": "uint16"},
                    {"name": "schema", "type": "bytes32"},
                    {"name": "recipient", "type": "address"},
                    {"name": "time", "type": "uint64"},
                    {"name": "expirationTime", "type": "uint64"},
                    {"name": "revocable", "type": "bool"},
                    {"name": "refUID", "type": "bytes32"},
                    {"name": "data", "type": "bytes"},
                ],
            }

            # Ensure ref_uid is properly formatted as bytes32 - convert to bytes
            ref_uid_str = ref_uid or "0x" + "0" * 64
            if not ref_uid_str.startswith("0x"):
                ref_uid_str = "0x" + ref_uid_str
            # Ensure exactly 64 hex characters (32 bytes) and convert to bytes
            ref_uid_hex = ref_uid_str[2:].ljust(64, "0")[:64]
            formatted_ref_uid = bytes.fromhex(ref_uid_hex)

            # Format schema as bytes32 - convert hex string to bytes
            if isinstance(schema, str):
                if schema.startswith("0x"):
                    schema_hex = schema[2:]
                else:
                    schema_hex = schema
                # Ensure exactly 64 hex characters (32 bytes)
                schema_hex = schema_hex.ljust(64, "0")[:64]
                formatted_schema = bytes.fromhex(schema_hex)
            else:
                # Default to empty bytes32 if schema is None or invalid
                formatted_schema = bytes(32)  # 32 zero bytes

            # Convert data to bytes for EIP-712 encoding
            if isinstance(data, bytes):
                formatted_data = data
            elif isinstance(data, str):  # type: ignore[unreachable]
                if data.startswith("0x"):
                    formatted_data = bytes.fromhex(data[2:])
                else:
                    formatted_data = data.encode("utf-8")
            else:
                formatted_data = str(data).encode("utf-8")

            # Prepare message for EIP-712 encoding
            eip712_message = {
                "version": version,
                "schema": formatted_schema,
                "recipient": recipient,
                "time": time,
                "expirationTime": expiration_time,
                "revocable": revocable,
                "refUID": formatted_ref_uid,
                "data": formatted_data,
            }

            # Create the complete EIP-712 typed data structure
            typed_data = {
                "types": types,
                "primaryType": "Attest",
                "domain": domain,
                "message": eip712_message,
            }

            # Encode and hash the structured data using eth_account
            from eth_account.messages import _hash_eip191_message, encode_typed_data

            encoded_message = encode_typed_data(full_message=typed_data)
            # Get the signable hash for the structured data
            message_hash = _hash_eip191_message(encoded_message)
            return "0x" + message_hash.hex()
        else:
            raise ValueError(f"Unsupported version: {version}")

    def attest_offchain(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Create an off-chain attestation."""
        # Calculate UID for the message using the message contents
        uid = self.get_offchain_uid(
            version=message.get("version", 1),
            schema=message.get("schema"),
            recipient=message.get("recipient"),
            time=message.get("time"),
            expiration_time=message.get("expirationTime", 0),
            revocable=message.get("revocable", True),
            ref_uid=message.get("refUID"),
            data=message.get("data", b""),
        )
        message["uid"] = uid  # uid is already a hex string

        # Sign the message
        signature = self.w3.eth.account.sign_message(
            text=json.dumps(message, sort_keys=True), private_key=self.private_key
        )

        # Create the final attestation with signature
        offchain_attestation = {
            "message": message,
            "signature": {"r": signature.r, "s": signature.s, "v": signature.v},
        }

        return offchain_attestation

    def attest(
        self,
        schema_uid: str,
        recipient: str,
        data_values: Optional[Dict[str, Any]] = None,
        expiration: int = 0,
        revocable: bool = True,
        ref_uid: Optional[str] = None,
    ) -> TransactionResult:
        """Create an on-chain attestation."""
        # Encode the data
        encoded_data = b""
        if data_values:
            try:
                encoded_data = encode(data_values["types"], data_values["values"])
            except Exception as e:
                raise Exception(f"Failed to encode attestation data: {str(e)}")

        # Convert types to match contract ABI expectations
        from web3 import Web3

        # Convert schema_uid to bytes32
        if schema_uid.startswith("0x"):
            schema_uid_bytes32 = bytes.fromhex(schema_uid[2:].ljust(64, "0"))
        else:
            schema_uid_bytes32 = bytes.fromhex(schema_uid.ljust(64, "0"))

        # Convert ref_uid to bytes32
        ref_uid_value = ref_uid or self.ZERO_ADDRESS
        if ref_uid_value.startswith("0x"):
            ref_uid_bytes32 = bytes.fromhex(ref_uid_value[2:].ljust(64, "0"))
        else:
            ref_uid_bytes32 = bytes.fromhex(ref_uid_value.ljust(64, "0"))

        # Prepare attestation request with proper types
        attestation_request_data = (
            Web3.to_checksum_address(recipient),  # address
            int(expiration),  # uint64 (Web3 will handle conversion)
            bool(revocable),  # bool
            ref_uid_bytes32,  # bytes32
            encoded_data,  # bytes
            int(0),  # uint256 (value)
        )
        attestation_request = (schema_uid_bytes32, attestation_request_data)

        # Gas estimation
        gas_estimate = self.easContract.functions.attest(
            attestation_request
        ).estimate_gas()

        # Create a transaction dictionary
        transaction = self.easContract.functions.attest(
            attestation_request
        ).build_transaction(
            {
                "from": self.from_account,
                "gas": gas_estimate,
                "nonce": self.w3.eth.get_transaction_count(
                    self.w3.to_checksum_address(self.from_account)
                ),
            }
        )
        # Sign the transaction
        signed_transaction = self.w3.eth.account.sign_transaction(
            transaction, self.private_key
        )
        # Send the transaction
        tx_hash = self.w3.eth.send_raw_transaction(signed_transaction.raw_transaction)
        # Get the transaction receipt
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        # Extract attestation UID from logs using the same pattern as TypeScript SDK
        attestation_uid = None

        # Get the Attested event topic (first topic is the event signature hash)
        attested_event = self.easContract.events.Attested()
        event_topic = attested_event.build_filter().topics[0]
        for log in receipt.get("logs", []):
            # Filter logs by EAS contract address and Attested event topic
            # Convert both to hex strings for comparison
            log_topics = getattr(log, "topics", [])
            log_address = getattr(log, "address", "")
            if len(log_topics) > 0:
                if isinstance(log_topics[0], bytes):
                    log_topic = "0x" + log_topics[0].hex()
                else:
                    log_topic = (
                        log_topics[0]
                        if log_topics[0].startswith("0x")
                        else "0x" + log_topics[0]
                    )

                if (
                    log_address.lower() == self.easContract.address.lower()
                    and log_topic == event_topic
                ):
                    try:
                        # Decode the event log (matches TypeScript: eas.decodeEventLog(event, log.data, log.topics))
                        decoded_log = attested_event.process_log(log)
                        # Extract UID from decoded args (matches TypeScript: [attribute])
                        uid_value = decoded_log["args"]["uid"]
                        if isinstance(uid_value, bytes):
                            attestation_uid = "0x" + uid_value.hex()
                        elif isinstance(uid_value, str):
                            attestation_uid = (
                                uid_value
                                if uid_value.startswith("0x")
                                else "0x" + uid_value
                            )
                        else:
                            attestation_uid = "0x" + str(uid_value)
                        break
                    except Exception:
                        # Continue to next log if this one fails to decode
                        continue

        result = TransactionResult.success_from_receipt(tx_hash.hex(), dict(receipt))
        # Add UID and explorer URL to result for easy access
        if attestation_uid:
            # Use setattr to add dynamic attributes
            setattr(result, "attestation_uid", attestation_uid)
            setattr(result, "explorer_url", self.get_attestation_url(attestation_uid))
        return result

    def get_attestation_url(self, attestation_uid: str) -> str:
        """Get the explorer URL for an attestation UID using the network config."""
        from .config import SUPPORTED_CHAINS

        # Find network by chain_id
        network_config = None
        for network_name, config in SUPPORTED_CHAINS.items():
            if config.get("chain_id") == self.chain_id:
                network_config = config
                break

        if network_config:
            base_url = network_config.get("explorer_url", "https://easscan.org")
        else:
            base_url = "https://easscan.org"  # fallback

        return f"{base_url}/attestation/view/{attestation_uid}"

    def __init_schema_registry(self, network_name: str) -> SchemaRegistry:
        """Initialize schema registry for the current network."""
        try:
            registry_address = SchemaRegistry.get_registry_address(network_name)
            return SchemaRegistry(
                web3=self.w3,
                registry_address=registry_address,
                from_account=self.from_account,
                private_key=self.private_key,
            )
        except Exception as e:
            raise EASTransactionError(f"Failed to initialize schema registry: {str(e)}")

    @log_operation("schema_registration")
    def register_schema(
        self,
        schema: str,
        network_name: str = "base-sepolia",
        resolver: Optional[str] = None,
        revocable: bool = True,
    ) -> TransactionResult:
        """
        Register a new schema on-chain.

        Args:
            schema: Schema definition string (e.g., "uint256 id,string name")
            network_name: Network to register on (default: base-sepolia)
            resolver: Optional resolver contract address
            revocable: Whether attestations using this schema can be revoked

        Returns:
            TransactionResult with schema UID and transaction details
        """
        registry = self.__init_schema_registry(network_name)
        result = registry.register_schema(schema, resolver, revocable)
        return cast(TransactionResult, result)

    @log_operation("attestation_revocation")
    def revoke_attestation(self, uid: str) -> TransactionResult:
        """
        Revoke a single attestation by UID.

        Args:
            uid: Attestation UID to revoke

        Returns:
            TransactionResult with revocation transaction details
        """
        # Validate UID format securely
        try:
            uid = SecureEnvironmentValidator.validate_schema_uid(uid)
        except SecurityError as e:
            raise EASValidationError(
                f"Invalid attestation UID: {str(e)}", field_name="uid", field_value=uid
            )

        logger.info(
            "attestation_revocation_started",
            attestation_uid=SecureEnvironmentValidator.sanitize_for_logging(uid, "uid"),
        )

        try:
            # Build revocation request
            revocation_request_data = (uid, 0)  # (uid, value)
            revocation_request = (
                bytes.fromhex(self.ZERO_ADDRESS[2:]),
                revocation_request_data,
            )  # (schema, data)

            # Estimate gas
            gas_estimate = self.easContract.functions.revoke(
                revocation_request
            ).estimate_gas({"from": self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer

            # Build transaction
            transaction = self.easContract.functions.revoke(
                revocation_request
            ).build_transaction(
                {
                    "from": self.from_account,
                    "gas": gas_limit,
                    "gasPrice": self.w3.eth.gas_price,
                    "nonce": self.w3.eth.get_transaction_count(
                        self.w3.to_checksum_address(self.from_account)
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

            logger.info(
                "attestation_revocation_submitted",
                tx_hash=SecureEnvironmentValidator.sanitize_for_logging(
                    tx_hash_hex, "transaction_hash"
                ),
                attestation_uid=SecureEnvironmentValidator.sanitize_for_logging(
                    uid, "uid"
                ),
            )

            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt.get("status") != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError(
                        f"Revocation transaction failed for UID {uid}",
                        tx_hash_hex,
                        dict(receipt),
                    ),
                )

            result = TransactionResult.success_from_receipt(tx_hash_hex, dict(receipt))

            logger.info(
                "attestation_revocation_completed",
                tx_hash=SecureEnvironmentValidator.sanitize_for_logging(
                    tx_hash_hex, "transaction_hash"
                ),
                attestation_uid=SecureEnvironmentValidator.sanitize_for_logging(
                    uid, "uid"
                ),
                gas_used=receipt.get("gasUsed"),
                block_number=receipt.get("blockNumber"),
            )

            return result

        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise

            logger.error(
                "attestation_revocation_failed",
                attestation_uid=SecureEnvironmentValidator.sanitize_for_logging(
                    uid, "uid"
                ),
                error=str(e),
            )
            raise EASTransactionError(f"Attestation revocation failed: {str(e)}")

    @log_operation("batch_revocation")
    def multi_revoke(self, revocations: List[Dict[str, Any]]) -> TransactionResult:
        """
        Revoke multiple attestations in a single transaction.

        Args:
            revocations: List of revocation requests, each containing 'uid' and optional 'value'

        Returns:
            TransactionResult with batch revocation transaction details
        """
        if not revocations:
            raise EASValidationError(
                "Revocations list cannot be empty", field_name="revocations"
            )

        logger.info("batch_revocation_started", revocation_count=len(revocations))

        try:
            # Build revocation requests
            revocation_requests = []
            for i, revocation in enumerate(revocations):
                uid = revocation.get("uid")
                value = revocation.get("value", 0)

                if not uid:
                    raise EASValidationError(
                        f"Missing UID in revocation {i}",
                        field_name=f"revocations[{i}].uid",
                    )

                # Each revocation needs (schema, RevocationRequestData)
                revocation_data = (uid, value)
                revocation_request = (
                    bytes.fromhex(self.ZERO_ADDRESS[2:]),
                    revocation_data,
                )
                revocation_requests.append(revocation_request)

            # Estimate gas for batch operation
            gas_estimate = self.easContract.functions.multiRevoke(
                revocation_requests
            ).estimate_gas({"from": self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer

            # Build transaction
            transaction = self.easContract.functions.multiRevoke(
                revocation_requests
            ).build_transaction(
                {
                    "from": self.from_account,
                    "gas": gas_limit,
                    "gasPrice": self.w3.eth.gas_price,
                    "nonce": self.w3.eth.get_transaction_count(
                        self.w3.to_checksum_address(self.from_account)
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

            logger.info(
                "batch_revocation_submitted",
                tx_hash=tx_hash_hex,
                revocation_count=len(revocations),
            )

            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt.get("status") != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError(
                        "Batch revocation transaction failed",
                        tx_hash_hex,
                        dict(receipt),
                    ),
                )

            result = TransactionResult.success_from_receipt(tx_hash_hex, dict(receipt))

            logger.info(
                "batch_revocation_completed",
                tx_hash=tx_hash_hex,
                revocation_count=len(revocations),
                gas_used=receipt.get("gasUsed"),
                block_number=receipt.get("blockNumber"),
            )

            return result

        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise

            logger.error(
                "batch_revocation_failed",
                revocation_count=len(revocations),
                error=str(e),
            )
            raise EASTransactionError(f"Batch revocation failed: {str(e)}")

    @log_operation("attestation_creation")
    def create_attestation(
        self,
        schema_uid: str,
        recipient: str,
        encoded_data: bytes,
        expiration: int = 0,
        revocable: bool = True,
        ref_uid: Optional[str] = None,
        value: int = 0,
    ) -> TransactionResult:
        """
        Create a generic attestation with any schema and data.

        Args:
            schema_uid: The schema UID to attest against
            recipient: Address of the attestation recipient
            encoded_data: ABI-encoded data according to the schema
            expiration: Expiration timestamp (0 for no expiration)
            revocable: Whether the attestation can be revoked
            ref_uid: Reference to another attestation (optional)
            value: ETH value to send with attestation

        Returns:
            TransactionResult with attestation transaction details
        """
        # Validate inputs with security checks
        try:
            schema_uid = SecureEnvironmentValidator.validate_schema_uid(schema_uid)
        except SecurityError as e:
            raise EASValidationError(
                f"Invalid schema UID: {str(e)}",
                field_name="schema_uid",
                field_value=schema_uid,
            )

        try:
            recipient = SecureEnvironmentValidator.validate_address(recipient)
        except SecurityError as e:
            raise EASValidationError(
                f"Invalid recipient address: {str(e)}",
                field_name="recipient",
                field_value=recipient,
            )

        if not encoded_data:
            raise EASValidationError(
                "Encoded data cannot be empty", field_name="encoded_data"
            )

        logger.info(
            "attestation_creation_started",
            schema_uid=SecureEnvironmentValidator.sanitize_for_logging(
                schema_uid, "schema_uid"
            ),
            recipient=SecureEnvironmentValidator.sanitize_for_logging(
                recipient, "address"
            ),
        )

        try:
            # Build attestation request
            attestation_request_data = (
                recipient,  # recipient
                expiration,  # expiration
                revocable,  # revocable
                ref_uid or self.ZERO_ADDRESS,  # refUID
                encoded_data,  # data
                value,  # value
            )
            attestation_request = (schema_uid, attestation_request_data)

            # Estimate gas
            gas_estimate = self.easContract.functions.attest(
                attestation_request
            ).estimate_gas({"from": self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer

            # Build transaction
            transaction = self.easContract.functions.attest(
                attestation_request
            ).build_transaction(
                {
                    "from": self.from_account,
                    "gas": gas_limit,
                    "gasPrice": self.w3.eth.gas_price,
                    "nonce": self.w3.eth.get_transaction_count(
                        self.w3.to_checksum_address(self.from_account)
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

            logger.info(
                "attestation_creation_submitted",
                tx_hash=SecureEnvironmentValidator.sanitize_for_logging(
                    tx_hash_hex, "transaction_hash"
                ),
                schema_uid=SecureEnvironmentValidator.sanitize_for_logging(
                    schema_uid, "schema_uid"
                ),
                recipient=SecureEnvironmentValidator.sanitize_for_logging(
                    recipient, "address"
                ),
            )

            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt.get("status") != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError(
                        "Attestation creation transaction failed",
                        tx_hash_hex,
                        dict(receipt),
                    ),
                )

            result = TransactionResult.success_from_receipt(tx_hash_hex, dict(receipt))

            logger.info(
                "attestation_creation_completed",
                tx_hash=SecureEnvironmentValidator.sanitize_for_logging(
                    tx_hash_hex, "transaction_hash"
                ),
                schema_uid=SecureEnvironmentValidator.sanitize_for_logging(
                    schema_uid, "schema_uid"
                ),
                recipient=SecureEnvironmentValidator.sanitize_for_logging(
                    recipient, "address"
                ),
                gas_used=receipt.get("gasUsed"),
                block_number=receipt.get("blockNumber"),
            )

            return result

        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise

            logger.error(
                "attestation_creation_failed",
                schema_uid=SecureEnvironmentValidator.sanitize_for_logging(
                    schema_uid, "schema_uid"
                ),
                recipient=SecureEnvironmentValidator.sanitize_for_logging(
                    recipient, "address"
                ),
                error=str(e),
            )
            raise EASTransactionError(f"Attestation creation failed: {str(e)}")

    @log_operation("timestamping")
    def timestamp(self, data: Union[str, bytes]) -> TransactionResult:
        """
        Create a timestamp attestation using the contract's timestamp method.

        Args:
            data: Data to timestamp

        Returns:
            TransactionResult with timestamp transaction details
        """
        if not data:
            raise EASValidationError("Data cannot be empty", field_name="data")

        # Convert to bytes32 for contract call
        if isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        # Convert to exactly 32 bytes by hashing if needed or padding
        if len(data_bytes) <= 32:
            # Pad with zeros to make exactly 32 bytes
            data_bytes32 = data_bytes.ljust(32, b"\x00")
        else:
            # Hash to get exactly 32 bytes
            data_bytes32 = self.w3.keccak(data_bytes)

        logger.info("timestamping_started", data_length=len(data_bytes))

        try:
            # Call contract's timestamp method directly
            gas_estimate = self.easContract.functions.timestamp(
                data_bytes32
            ).estimate_gas({"from": self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer

            # Build transaction
            transaction = self.easContract.functions.timestamp(
                data_bytes32
            ).build_transaction(
                {
                    "from": self.from_account,
                    "gas": gas_limit,
                    "gasPrice": self.w3.eth.gas_price,
                    "nonce": self.w3.eth.get_transaction_count(
                        self.w3.to_checksum_address(self.from_account)
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

            logger.info(
                "timestamping_submitted",
                tx_hash=tx_hash_hex,
                data_length=len(data_bytes),
            )

            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt.get("status") != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError(
                        "Timestamp transaction failed", tx_hash_hex, dict(receipt)
                    ),
                )

            result = TransactionResult.success_from_receipt(tx_hash_hex, dict(receipt))

            logger.info(
                "timestamping_completed",
                tx_hash=tx_hash_hex,
                data_length=len(data_bytes),
                gas_used=receipt.get("gasUsed"),
                block_number=receipt.get("blockNumber"),
            )

            return result

        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise

            logger.error(
                "timestamping_failed", data_length=len(data_bytes), error=str(e)
            )
            raise EASTransactionError(f"Timestamping failed: {str(e)}")

    @log_operation("batch_timestamping")
    def multi_timestamp(self, data_items: List[Union[str, bytes]]) -> TransactionResult:
        """
        Create multiple timestamp attestations using the contract's multiTimestamp method.

        Args:
            data_items: List of data to timestamp

        Returns:
            TransactionResult with batch timestamp transaction details
        """
        if not data_items:
            raise EASValidationError(
                "Data items list cannot be empty", field_name="data_items"
            )

        for i, item in enumerate(data_items):
            if not item:
                raise EASValidationError(
                    f"Data item {i} cannot be empty", field_name=f"data_items[{i}]"
                )

        # Convert all items to bytes32 (exactly 32 bytes each)
        data_bytes_list = []
        for item in data_items:
            if isinstance(item, str):
                item_bytes = item.encode("utf-8")
            else:
                item_bytes = item

            # Convert to exactly 32 bytes by hashing if needed or padding
            if len(item_bytes) <= 32:
                # Pad with zeros to make exactly 32 bytes
                bytes32_item = item_bytes.ljust(32, b"\x00")
            else:
                # Hash to get exactly 32 bytes
                bytes32_item = self.w3.keccak(item_bytes)

            data_bytes_list.append(bytes32_item)

        logger.info("batch_timestamping_started", item_count=len(data_items))

        try:
            # Call contract's multiTimestamp method directly
            gas_estimate = self.easContract.functions.multiTimestamp(
                data_bytes_list
            ).estimate_gas({"from": self.from_account})
            gas_limit = int(gas_estimate * 1.2)  # 20% buffer

            # Build transaction
            transaction = self.easContract.functions.multiTimestamp(
                data_bytes_list
            ).build_transaction(
                {
                    "from": self.from_account,
                    "gas": gas_limit,
                    "gasPrice": self.w3.eth.gas_price,
                    "nonce": self.w3.eth.get_transaction_count(
                        self.w3.to_checksum_address(self.from_account)
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

            logger.info(
                "batch_timestamping_submitted",
                tx_hash=tx_hash_hex,
                item_count=len(data_items),
            )

            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt.get("status") != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError(
                        "Batch timestamp transaction failed", tx_hash_hex, dict(receipt)
                    ),
                )

            result = TransactionResult.success_from_receipt(tx_hash_hex, dict(receipt))

            logger.info(
                "batch_timestamping_completed",
                tx_hash=tx_hash_hex,
                item_count=len(data_items),
                gas_used=receipt.get("gasUsed"),
                block_number=receipt.get("blockNumber"),
            )

            return result

        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise

            logger.error(
                "batch_timestamping_failed", item_count=len(data_items), error=str(e)
            )
            raise EASTransactionError(f"Batch timestamping failed: {str(e)}")

    def get_offchain_revocation_uid(
        self, message: Dict[str, Any], version: int = 1
    ) -> bytes:
        """
        Calculate the UID for an off-chain revocation message.

        Args:
            message: Revocation message containing uid, time, value, etc.
            version: Off-chain revocation version (0 or 1)

        Returns:
            bytes: The calculated UID for the revocation
        """
        if version == 0:
            # Version 0 uses direct keccak
            message_bytes = json.dumps(message, sort_keys=True).encode("utf-8")
            return self.w3.keccak(message_bytes)
        elif version == 1:
            # Version 1 uses EIP-712 structured data hashing
            # Create EIP-712 domain
            domain = {
                "name": "EAS Attestation",
                "version": self.contract_version,
                "chainId": self.chain_id,
                "verifyingContract": self.contract_address,
            }

            # Define EIP-712 types for revocation
            types = {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "Revoke": [
                    {"name": "version", "type": "uint16"},
                    {"name": "schema", "type": "bytes32"},
                    {"name": "uid", "type": "bytes32"},
                    {"name": "value", "type": "uint256"},
                    {"name": "time", "type": "uint64"},
                    {"name": "salt", "type": "bytes32"},
                ],
            }

            # Format fields properly for EIP-712 - convert to bytes
            schema_str = message.get("schema", "0x" + "0" * 64)
            if not schema_str.startswith("0x"):
                schema_str = "0x" + schema_str
            schema_hex = schema_str[2:].ljust(64, "0")[:64]
            formatted_schema = bytes.fromhex(schema_hex)

            uid_str = message.get("uid", "0x" + "0" * 64)
            if not uid_str.startswith("0x"):
                uid_str = "0x" + uid_str
            uid_hex = uid_str[2:].ljust(64, "0")[:64]
            formatted_uid = bytes.fromhex(uid_hex)

            salt_str = message.get("salt", "0x" + "0" * 64)
            if not salt_str.startswith("0x"):
                salt_str = "0x" + salt_str
            salt_hex = salt_str[2:].ljust(64, "0")[:64]
            formatted_salt = bytes.fromhex(salt_hex)

            # Prepare message for EIP-712 encoding
            eip712_message = {
                "version": message.get("version", 1),
                "schema": formatted_schema,
                "uid": formatted_uid,
                "value": message.get("value", 0),
                "time": message.get("time", 0),
                "salt": formatted_salt,
            }

            # Create the complete EIP-712 typed data structure
            typed_data = {
                "types": types,
                "primaryType": "Revoke",
                "domain": domain,
                "message": eip712_message,
            }

            # Encode and hash the structured data using eth_account
            from eth_account.messages import _hash_eip191_message, encode_typed_data

            encoded_message = encode_typed_data(full_message=typed_data)
            # Get the signable hash for the structured data
            message_hash = _hash_eip191_message(encoded_message)
            return message_hash
        else:
            raise ValueError(f"Unsupported off-chain revocation UID version: {version}")

    @log_operation("offchain_revocation")
    def revoke_offchain(
        self,
        attestation_uid: str,
        schema_uid: Optional[str] = None,
        value: int = 0,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create an off-chain revocation for a previously created attestation.

        Args:
            attestation_uid: UID of the attestation to revoke
            schema_uid: Optional schema UID (uses zero address if not provided)
            value: Optional value associated with revocation
            reason: Optional reason for revocation (stored in metadata)

        Returns:
            Dict containing the signed off-chain revocation
        """
        if not attestation_uid or not attestation_uid.startswith("0x"):
            raise EASValidationError(
                "Invalid attestation UID format",
                field_name="attestation_uid",
                field_value=attestation_uid,
            )

        logger.info("offchain_revocation_started", attestation_uid=attestation_uid)

        try:
            # Use current timestamp
            current_time = int(time.time())

            # Generate salt for uniqueness
            salt = os.urandom(32)

            # Build revocation message
            revocation_message = {
                "version": 1,
                "schema": schema_uid or self.ZERO_ADDRESS,
                "uid": attestation_uid,
                "value": value,
                "time": current_time,
                "salt": "0x" + salt.hex(),
            }

            # Calculate UID for this revocation
            revocation_uid = self.get_offchain_revocation_uid(
                revocation_message, version=1
            )
            revocation_message["revocation_uid"] = revocation_uid.hex()

            # Create EIP-712 domain
            domain = {
                "name": "EAS Attestation",
                "version": self.contract_version,
                "chainId": self.chain_id,
                "verifyingContract": self.contract_address,
            }

            # Define types for EIP-712 signature
            types = {
                "Revoke": [
                    {"name": "version", "type": "uint16"},
                    {"name": "schema", "type": "bytes32"},
                    {"name": "uid", "type": "bytes32"},
                    {"name": "value", "type": "uint256"},
                    {"name": "time", "type": "uint64"},
                    {"name": "salt", "type": "bytes32"},
                ]
            }

            # Prepare message for signing (without revocation_uid) - convert bytes32 fields
            schema_value = revocation_message["schema"]
            schema_str = str(schema_value)
            if not schema_str.startswith("0x"):
                schema_str = "0x" + schema_str
            schema_hex = schema_str[2:].ljust(64, "0")[:64]
            formatted_schema = bytes.fromhex(schema_hex)

            uid_value = revocation_message["uid"]
            uid_str = str(uid_value)
            if not uid_str.startswith("0x"):
                uid_str = "0x" + uid_str
            uid_hex = uid_str[2:].ljust(64, "0")[:64]
            formatted_uid = bytes.fromhex(uid_hex)

            salt_value = revocation_message["salt"]
            salt_str = str(salt_value)
            if not salt_str.startswith("0x"):
                salt_str = "0x" + salt_str
            salt_hex = salt_str[2:].ljust(64, "0")[:64]
            formatted_salt = bytes.fromhex(salt_hex)

            signing_message = {
                "version": revocation_message["version"],
                "schema": formatted_schema,
                "uid": formatted_uid,
                "value": revocation_message["value"],
                "time": revocation_message["time"],
                "salt": formatted_salt,
            }

            # Create typed data structure
            typed_data = {
                "types": types,
                "primaryType": "Revoke",
                "domain": domain,
                "message": signing_message,
            }

            # Add EIP712Domain to types
            types_dict = cast(Dict[str, Any], typed_data["types"])
            types_dict["EIP712Domain"] = [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ]

            # Encode and sign the data using eth_account
            from eth_account.messages import encode_typed_data

            encoded_message = encode_typed_data(full_message=typed_data)

            # Create account from private key and sign the message
            account = Account.from_key(self.private_key)
            signed_message = account.sign_message(encoded_message)

            # Convert signature to r, s, v format
            r = hex(signed_message.r)
            s = hex(signed_message.s)
            v = signed_message.v

            # Build the final revocation object
            offchain_revocation = {
                "revoker": self.from_account,
                "uid": revocation_uid.hex(),
                "data": {
                    "domain": domain,
                    "primaryType": "Revoke",
                    "types": types,
                    "message": revocation_message,
                    "signature": {"r": r, "s": s, "v": v},
                },
            }

            # Add reason if provided
            if reason:
                data_dict = cast(Dict[str, Any], offchain_revocation["data"])
                data_dict["reason"] = reason

            logger.info(
                "offchain_revocation_completed",
                attestation_uid=attestation_uid,
                revocation_uid=revocation_uid.hex(),
                revoker=self.from_account,
            )

            return offchain_revocation

        except Exception as e:
            if isinstance(e, (EASValidationError, NotImplementedError)):
                raise

            logger.error(
                "offchain_revocation_failed",
                attestation_uid=attestation_uid,
                error=str(e),
            )
            raise EASTransactionError(f"Off-chain revocation failed: {str(e)}")

    @log_operation("multi_attest")
    def multi_attest(
        self, attestation_requests: List[Dict[str, Any]]
    ) -> TransactionResult:
        """
        Create multiple attestations in a single transaction for efficient gas usage.

        Args:
            attestation_requests: List of attestation request dictionaries, each containing:
                - schema_uid: Schema UID (bytes32 hex string)
                - attestations: List of attestation data dictionaries with:
                    - recipient: Recipient address
                    - expiration_time: Expiration timestamp (default: 0)
                    - revocable: Whether attestation can be revoked (default: True)
                    - ref_uid: Reference UID (default: zero address)
                    - data: Encoded attestation data (bytes)
                    - value: ETH value to send (default: 0)

        Returns:
            TransactionResult with array of attestation UIDs

        Raises:
            EASValidationError: Invalid input data
            EASTransactionError: Transaction execution failed
        """
        if not attestation_requests:
            raise EASValidationError(
                "Attestation requests list cannot be empty",
                field_name="attestation_requests",
            )

        # Validate and prepare multi-attestation requests
        multi_requests = []
        total_attestations = 0

        for i, request in enumerate(attestation_requests):
            # Validate request structure
            if not isinstance(request, dict):
                raise EASValidationError(
                    f"Request {i} must be a dictionary",
                    field_name=f"attestation_requests[{i}]",
                )

            schema_uid = request.get("schema_uid")
            if not schema_uid or not schema_uid.startswith("0x"):
                raise EASValidationError(
                    f"Invalid schema UID format in request {i}",
                    field_name=f"attestation_requests[{i}].schema_uid",
                    field_value=schema_uid,
                )

            attestations = request.get("attestations", [])
            if not attestations:
                raise EASValidationError(
                    f"Request {i} must contain at least one attestation",
                    field_name=f"attestation_requests[{i}].attestations",
                )

            # Prepare AttestationRequestData array for this schema
            attestation_data_list = []
            for j, attestation in enumerate(attestations):
                if not isinstance(attestation, dict):
                    raise EASValidationError(
                        f"Attestation {j} in request {i} must be a dictionary",
                        field_name=f"attestation_requests[{i}].attestations[{j}]",
                    )

                # Extract and validate fields
                recipient = attestation.get("recipient")
                if not recipient or not self.w3.is_address(recipient):
                    raise EASValidationError(
                        f"Invalid recipient address in request {i}, attestation {j}",
                        field_name=f"attestation_requests[{i}].attestations[{j}].recipient",
                        field_value=recipient,
                    )

                expiration_time = attestation.get("expiration_time", 0)
                revocable = attestation.get("revocable", True)
                ref_uid = attestation.get("ref_uid", self.ZERO_ADDRESS)
                data = attestation.get("data", b"")
                value = attestation.get("value", 0)

                # Validate ref_uid format if provided
                if ref_uid != self.ZERO_ADDRESS and not ref_uid.startswith("0x"):
                    raise EASValidationError(
                        f"Invalid ref_uid format in request {i}, attestation {j}",
                        field_name=f"attestation_requests[{i}].attestations[{j}].ref_uid",
                        field_value=ref_uid,
                    )

                # Build AttestationRequestData tuple with proper type conversions
                # Convert ref_uid to proper bytes32 format (exactly 32 bytes)
                if ref_uid != self.ZERO_ADDRESS:
                    ref_uid_hex = ref_uid[2:] if ref_uid.startswith("0x") else ref_uid
                    # Ensure exactly 32 bytes by padding with zeros or truncating
                    ref_uid_hex = ref_uid_hex.ljust(64, "0")[:64]
                    ref_uid_bytes = bytes.fromhex(ref_uid_hex)
                else:
                    ref_uid_bytes = b"\x00" * 32  # Exactly 32 zero bytes

                # Validate and convert integer types to their proper ranges
                # uint64: 0 to 2^64-1 (18446744073709551615)
                expiration_uint64 = max(
                    0, min(int(expiration_time), 18446744073709551615)
                )

                # uint256: 0 to 2^256-1
                value_uint256 = max(0, min(int(value), 2**256 - 1))

                attestation_data = (
                    recipient,  # address
                    expiration_uint64,  # uint64 - properly constrained
                    bool(revocable),  # bool
                    ref_uid_bytes,  # bytes32 - exactly 32 bytes
                    data if isinstance(data, bytes) else data.encode("utf-8"),  # bytes
                    value_uint256,  # uint256 - properly constrained
                )
                attestation_data_list.append(attestation_data)
                total_attestations += 1

            # Build MultiAttestationRequest tuple (convert schema_uid to exactly 32 bytes)
            # Ensure schema_uid is exactly 32 bytes for proper bytes32 contract type
            schema_uid_hex = (
                schema_uid[2:] if schema_uid.startswith("0x") else schema_uid
            )
            # Ensure exactly 32 bytes by padding with zeros or truncating
            schema_uid_hex = schema_uid_hex.ljust(64, "0")[:64]
            schema_uid_bytes = bytes.fromhex(schema_uid_hex)
            multi_request = (schema_uid_bytes, attestation_data_list)
            multi_requests.append(multi_request)

        logger.info(
            "multi_attest_started",
            request_count=len(attestation_requests),
            total_attestations=total_attestations,
        )

        try:
            # Build contract call
            function_call = self.easContract.functions.multiAttest(multi_requests)

            # Estimate gas with buffer, fallback to reasonable default if estimation fails
            try:
                gas_estimate = function_call.estimate_gas({"from": self.from_account})
                gas_limit = int(gas_estimate * 1.2)  # 20% buffer
                logger.info(
                    "multi_attest_gas_estimated",
                    gas_estimate=gas_estimate,
                    gas_limit=gas_limit,
                )
            except Exception as e:
                # Gas estimation failed - use reasonable default and warn
                gas_limit = 500000  # Conservative default for multi-attest
                logger.warning(
                    "multi_attest_gas_estimation_failed",
                    error=str(e),
                    fallback_gas_limit=gas_limit,
                    message="Using fallback gas limit due to estimation failure",
                )

            # Build transaction
            transaction = function_call.build_transaction(
                {
                    "from": self.from_account,
                    "gas": gas_limit,
                    "gasPrice": self.w3.eth.gas_price,
                    "nonce": self.w3.eth.get_transaction_count(
                        self.w3.to_checksum_address(self.from_account)
                    ),
                }
            )

            # Sign and send transaction
            signed_txn = Account.sign_transaction(
                transaction, private_key=self.private_key
            )
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
            tx_hash_hex = tx_hash.hex()

            logger.info("multi_attest_submitted", tx_hash=tx_hash_hex)

            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

            # Check transaction success
            if receipt.get("status") != 1:
                return TransactionResult.failure_from_error(
                    tx_hash_hex,
                    EASTransactionError(
                        "Multi-attest transaction failed", tx_hash_hex, dict(receipt)
                    ),
                )

            result = TransactionResult.success_from_receipt(tx_hash_hex, dict(receipt))

            logger.info(
                "multi_attest_completed",
                tx_hash=tx_hash_hex,
                request_count=len(attestation_requests),
                total_attestations=total_attestations,
                gas_used=receipt.get("gasUsed"),
                block_number=receipt.get("blockNumber"),
            )

            return result

        except Exception as e:
            if isinstance(e, (EASValidationError, EASTransactionError)):
                raise

            logger.error(
                "multi_attest_failed",
                request_count=len(attestation_requests),
                total_attestations=total_attestations,
                error=str(e),
            )
            raise EASTransactionError(f"Multi-attest failed: {str(e)}")
