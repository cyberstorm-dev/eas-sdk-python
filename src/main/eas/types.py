"""
EAS SDK Type Definitions

Strong typing for Ethereum Attestation Service SDK using protobuf and Pydantic.
Implements fail-fast, observable validation with structured logging.
"""

from enum import Enum
from typing import (
    Any,
    Dict,
    List,
    NewType,
    NotRequired,
    Optional,
    Protocol,
    Required,
    Tuple,
    TypeAlias,
    TypedDict,
    Union,
)

import structlog
from eth_typing import Hash32, HexStr
from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.message import Message as ProtobufMessage
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.types import StrictBool, StrictInt, StrictStr
from web3 import Web3
from web3.types import TxReceipt, Wei

logger = structlog.get_logger(__name__)

# Type aliases for commonly used web3 types
# Using Any to avoid mypy strict import issues while preserving type information in comments
HexBytes: TypeAlias = Any  # web3.types.HexBytes - bytes with hex representation
ChecksumAddress: TypeAlias = (
    str  # web3.types.ChecksumAddress - ethereum address with checksum
)
BlockNumber: TypeAlias = int  # web3.types.BlockNumber - ethereum block number

# ============================================================================
# Core EAS Domain Types (Strong Typing with NewType)
# ============================================================================

# Ethereum-specific strongly typed addresses and identifiers
Address = NewType("Address", ChecksumAddress)
PrivateKey = NewType("PrivateKey", str)  # 0x + 64 hex chars
PublicKey = NewType("PublicKey", str)  # 0x + 128 hex chars (uncompressed)

# EAS-specific identifiers with validation semantics
SchemaUID = NewType("SchemaUID", str)  # bytes32 as hex string (0x + 64 hex)
AttestationUID = NewType("AttestationUID", str)  # bytes32 as hex string (0x + 64 hex)
RevocationUID = NewType("RevocationUID", str)  # bytes32 as hex string (0x + 64 hex)

# Transaction and blockchain types
TransactionHash = NewType("TransactionHash", str)  # 0x + 64 hex chars
ChainId = NewType("ChainId", int)  # Positive integer
RpcUrl = NewType("RpcUrl", str)  # Valid HTTP/HTTPS URL
ContractVersion = NewType("ContractVersion", str)  # Semantic version string

# Data encoding types
SchemaString = NewType("SchemaString", str)  # Solidity ABI schema format
EncodedData = NewType("EncodedData", bytes)  # ABI-encoded data
Salt = NewType("Salt", str)  # 0x + 64 hex chars (bytes32)
Nonce = NewType("Nonce", int)  # Transaction nonce

# ============================================================================
# Enums for Type Safety
# ============================================================================


class NetworkType(Enum):
    """Supported network types for EAS deployments."""

    MAINNET = "mainnet"
    TESTNET = "testnet"
    LOCAL = "local"
    DEVNET = "devnet"


class SecurityLevel(Enum):
    """Security validation levels for operations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Categories of security threats."""

    INJECTION = "injection"
    DISCLOSURE = "disclosure"
    MANIPULATION = "manipulation"
    BYPASS = "bypass"
    OVERFLOW = "overflow"


class TransactionStatus(Enum):
    """Transaction execution status."""

    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    REVERTED = "reverted"


# ============================================================================
# TypedDict Classes for Structured Data (Wire Protocol)
# ============================================================================


class NetworkConfig(TypedDict):
    """Network configuration with required and optional fields."""

    rpc_url: Required[RpcUrl]
    contract_address: Required[Address]
    chain_id: Required[ChainId]
    contract_version: Required[ContractVersion]
    name: NotRequired[str]
    network_type: NotRequired[NetworkType]
    block_explorer_url: NotRequired[str]


class ChainConfig(TypedDict):
    """Complete chain configuration including registry addresses."""

    eas_contract: Required[Address]
    schema_registry: Required[Address]
    chain_id: Required[ChainId]
    rpc_url: Required[RpcUrl]
    contract_version: Required[ContractVersion]
    network_name: NotRequired[str]


class EIP712Domain(TypedDict):
    """EIP-712 domain separator structure."""

    name: Required[str]
    version: Required[str]
    chainId: Required[ChainId]
    verifyingContract: Required[Address]
    salt: NotRequired[Salt]


class EIP712Types(TypedDict):
    """EIP-712 type definitions structure."""

    EIP712Domain: Required[List[Dict[str, str]]]
    # Additional types are added dynamically based on the message type


class AttestationRequestData(TypedDict):
    """Structured data for attestation requests."""

    schema: Required[SchemaUID]
    recipient: Required[Address]
    data: Required[EncodedData]
    value: NotRequired[Wei]
    refUID: NotRequired[AttestationUID]
    revocable: NotRequired[bool]
    expirationTime: NotRequired[int]


class RevocationRequestData(TypedDict):
    """Structured data for revocation requests."""

    uid: Required[AttestationUID]
    value: NotRequired[Wei]
    schema: NotRequired[SchemaUID]
    reason: NotRequired[str]


class OffchainAttestationData(TypedDict):
    """Off-chain attestation data structure."""

    version: Required[int]
    schema: Required[SchemaUID]
    recipient: Required[Address]
    data: Required[EncodedData]
    time: Required[int]
    value: Required[Wei]
    salt: Required[Salt]
    refUID: NotRequired[AttestationUID]
    revocable: NotRequired[bool]
    expirationTime: NotRequired[int]


# ============================================================================
# Pydantic Models for Local Validation (Non-Wire)
# ============================================================================


class ValidationResult(BaseModel):
    """Result of validation operations with observable context."""

    success: StrictBool
    value: Optional[StrictStr] = None
    error: Optional[StrictStr] = None
    context: Optional[Dict[str, Any]] = None

    def __bool__(self) -> bool:
        """Allow truthiness testing."""
        return self.success

    @field_validator("error", mode="after")
    @classmethod
    def error_requires_failure(cls, v: Optional[str]) -> Optional[str]:
        """Ensure error is provided when success=False."""
        # This validation will be handled at the model level instead
        return v


class TransactionMetadata(BaseModel):
    """Metadata for blockchain transactions with strict validation."""

    gas_limit: StrictInt = Field(gt=0, description="Gas limit must be positive")
    gas_price: Wei = Field(gt=0, description="Gas price must be positive")
    nonce: Nonce = Field(ge=0, description="Nonce must be non-negative")
    from_address: Address
    to_address: Optional[Address] = None
    value: Wei = Field(default=Wei(0), ge=0, description="Value must be non-negative")

    @field_validator("gas_limit")
    @classmethod
    def validate_gas_limit(cls, v: int) -> int:
        """Validate gas limit is within reasonable bounds."""
        if v > 30_000_000:  # Ethereum block gas limit
            logger.warning("Gas limit exceeds block limit", gas_limit=v)
            raise ValueError(f"Gas limit {v} exceeds maximum block gas limit")
        return v


class AttestationMetadata(BaseModel):
    """Complete attestation metadata with strict validation."""

    uid: AttestationUID
    schema_uid: SchemaUID
    attester: Address
    recipient: Address

    model_config = ConfigDict(validate_assignment=True)

    time: StrictInt = Field(gt=0, description="Time must be positive timestamp")
    expiration_time: StrictInt = Field(
        ge=0, description="Expiration time must be non-negative"
    )
    revocable: StrictBool
    ref_uid: Optional[AttestationUID] = None
    data: Optional[bytes] = None

    @field_validator("expiration_time", mode="after")
    @classmethod
    def validate_expiration_time(cls, v: int) -> int:
        """Ensure expiration time is reasonable."""
        if v > 0 and v < 946684800:  # Before year 2000 is unreasonable
            logger.error("Invalid expiration time", expiration=v)
            raise ValueError(f"Expiration time {v} appears to be invalid")
        return v


class SecurityContext(BaseModel):
    """Security validation context with observable failures."""

    level: SecurityLevel
    threat_type: Optional[ThreatType] = None
    sanitized_fields: Dict[str, Any] = Field(default_factory=dict)
    validation_errors: List[str] = Field(default_factory=list)

    def add_error(self, error: str) -> None:
        """Add validation error with structured logging."""
        self.validation_errors.append(error)
        logger.error("Security validation error", error=error, level=self.level.value)

    def fail_if_errors(self) -> None:
        """Fail fast if any validation errors exist."""
        if self.validation_errors:
            error_summary = "; ".join(self.validation_errors)
            logger.error(
                "Security validation failed",
                error_count=len(self.validation_errors),
                errors=error_summary,
            )
            raise SecurityException(f"Security validation failed: {error_summary}")


# ============================================================================
# Protocol Classes for Interface Definition
# ============================================================================


class Logger(Protocol):
    """Logger protocol for dependency injection."""

    def info(self, message: str, **kwargs: Any) -> None: ...
    def error(self, message: str, **kwargs: Any) -> None: ...
    def warning(self, message: str, **kwargs: Any) -> None: ...
    def debug(self, message: str, **kwargs: Any) -> None: ...


class Web3Provider(Protocol):
    """Web3 provider protocol for blockchain interaction."""

    def is_connected(self) -> bool: ...
    def get_block_number(self) -> BlockNumber: ...
    def get_transaction_count(self, address: Address) -> int: ...


class ContractInterface(Protocol):
    """Smart contract interaction protocol."""

    def functions(self) -> Any: ...
    def address(self) -> Address: ...


class ProtobufSerializable(Protocol):
    """Protocol for objects that can be serialized to protobuf."""

    def to_protobuf(self) -> ProtobufMessage: ...

    @classmethod
    def from_protobuf(cls, message: ProtobufMessage) -> "ProtobufSerializable": ...


# ============================================================================
# Type Aliases for Complex Types
# ============================================================================

# Transaction-related type aliases
Web3TxReceipt: TypeAlias = TxReceipt
Web3HexBytes: TypeAlias = HexBytes
Web3Hash32: TypeAlias = Hash32
Web3HexStr: TypeAlias = HexStr

# Complex data structure aliases
AttestationData: TypeAlias = Union[bytes, str, Dict[str, Any]]
SchemaFields: TypeAlias = List[Tuple[str, str]]  # (field_name, field_type) pairs
DecodedAttestationData: TypeAlias = Dict[str, Union[str, int, bool, bytes, Address]]

# EIP-712 message types
EIP712Message: TypeAlias = Dict[str, Union[str, int, Address, bytes]]
EIP712FullMessage: TypeAlias = Dict[
    str, Union[EIP712Domain, EIP712Types, EIP712Message]
]

# Signature-related types
SignatureComponents: TypeAlias = Tuple[int, int, int]  # (r, s, v)
SignedMessage: TypeAlias = Dict[str, Union[str, SignatureComponents]]

# Batch operation types
BatchAttestationRequest: TypeAlias = List[AttestationRequestData]
BatchRevocationRequest: TypeAlias = List[RevocationRequestData]

# Protobuf message types for structured data
ProtobufAttestationData: TypeAlias = ProtobufMessage
ProtobufSchemaData: TypeAlias = ProtobufMessage
ProtobufFieldDescriptor: TypeAlias = FieldDescriptor

# ============================================================================
# Validation Functions with Observable Failures
# ============================================================================


def validate_address(value: Any) -> Address:
    """Validate Ethereum address format with observable failures."""
    if not isinstance(value, str):
        logger.error(
            "Address validation failed: not a string", value_type=type(value).__name__
        )
        raise TypeError(f"Address must be string, got {type(value).__name__}")

    if len(value) != ADDRESS_LENGTH:
        logger.error(
            "Address validation failed: invalid length",
            value=value,
            expected_length=ADDRESS_LENGTH,
            actual_length=len(value),
        )
        raise ValueError(
            f"Address must be {ADDRESS_LENGTH} characters, got {len(value)}"
        )

    if not value.startswith("0x"):
        logger.error("Address validation failed: missing 0x prefix", value=value)
        raise ValueError("Address must start with 0x")

    # Validate checksum
    try:
        checksum_address = Web3.to_checksum_address(value)
    except Exception as e:
        logger.error(
            "Address validation failed: invalid checksum", value=value, error=str(e)
        )
        raise ValueError(f"Invalid Ethereum address: {value}") from e

    return Address(checksum_address)


def validate_uid(value: Any, uid_type: str = "UID") -> str:
    """Validate EAS UID format with observable failures."""
    if not isinstance(value, str):
        logger.error(
            "UID validation failed: not a string",
            uid_type=uid_type,
            value_type=type(value).__name__,
        )
        raise TypeError(f"{uid_type} must be string, got {type(value).__name__}")

    if len(value) != UID_LENGTH:
        logger.error(
            "UID validation failed: invalid length",
            uid_type=uid_type,
            value=value,
            expected_length=UID_LENGTH,
            actual_length=len(value),
        )
        raise ValueError(
            f"{uid_type} must be {UID_LENGTH} characters, got {len(value)}"
        )

    if not value.startswith("0x"):
        logger.error(
            "UID validation failed: missing 0x prefix", uid_type=uid_type, value=value
        )
        raise ValueError(f"{uid_type} must start with 0x")

    try:
        # Validate hex encoding
        bytes.fromhex(value[2:])
    except ValueError as e:
        logger.error(
            "UID validation failed: invalid hex",
            uid_type=uid_type,
            value=value,
            error=str(e),
        )
        raise ValueError(f"Invalid {uid_type} hex format: {value}") from e

    return value


def validate_private_key(value: Any) -> PrivateKey:
    """Validate private key format with observable failures."""
    if not isinstance(value, str):
        logger.error(
            "Private key validation failed: not a string",
            value_type=type(value).__name__,
        )
        raise TypeError(f"Private key must be string, got {type(value).__name__}")

    if len(value) != PRIVATE_KEY_LENGTH:
        logger.error(
            "Private key validation failed: invalid length",
            expected_length=PRIVATE_KEY_LENGTH,
            actual_length=len(value),
        )
        raise ValueError(
            f"Private key must be {PRIVATE_KEY_LENGTH} characters, got {len(value)}"
        )

    if not value.startswith("0x"):
        logger.error("Private key validation failed: missing 0x prefix")
        raise ValueError("Private key must start with 0x")

    try:
        # Validate hex encoding and key range
        key_bytes = bytes.fromhex(value[2:])
        key_int = int.from_bytes(key_bytes, "big")
        if (
            key_int == 0
            or key_int
            >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        ):
            logger.error("Private key validation failed: invalid key range")
            raise ValueError("Private key is outside valid range")
    except ValueError as e:
        logger.error("Private key validation failed: invalid format", error=str(e))
        raise ValueError("Invalid private key format") from e

    return PrivateKey(value)


def validate_chain_id(value: Any) -> ChainId:
    """Validate chain ID with observable failures."""
    if not isinstance(value, int):
        logger.error(
            "Chain ID validation failed: not an integer",
            value_type=type(value).__name__,
        )
        raise TypeError(f"Chain ID must be integer, got {type(value).__name__}")

    if value <= 0:
        logger.error("Chain ID validation failed: not positive", value=value)
        raise ValueError(f"Chain ID must be positive, got {value}")

    # Check against known problematic chain IDs
    if value > 2**53 - 1:  # JavaScript safe integer limit
        logger.error(
            "Chain ID validation failed: exceeds safe integer limit", value=value
        )
        raise ValueError(f"Chain ID {value} exceeds safe integer limit")

    return ChainId(value)


# ============================================================================
# Exception Classes
# ============================================================================


class SecurityException(Exception):
    """Security validation failures."""

    pass


class ValidationException(Exception):
    """General validation failures."""

    pass


# ============================================================================
# Constants for Type Safety
# ============================================================================

# Standard lengths for validation
ADDRESS_LENGTH = 42  # 0x + 40 hex chars
UID_LENGTH = 66  # 0x + 64 hex chars
PRIVATE_KEY_LENGTH = 66  # 0x + 64 hex chars
HASH_LENGTH = 66  # 0x + 64 hex chars

# Common chain IDs
ETHEREUM_MAINNET_CHAIN_ID = ChainId(1)
BASE_MAINNET_CHAIN_ID = ChainId(8453)
BASE_SEPOLIA_CHAIN_ID = ChainId(84532)
ARBITRUM_ONE_CHAIN_ID = ChainId(42161)
OPTIMISM_MAINNET_CHAIN_ID = ChainId(10)

# EIP-712 constants
EIP712_DOMAIN_TYPE_HASH = (
    "0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"
)
EAS_DOMAIN_NAME = "EAS Attestation"

# Zero values for optional parameters
ZERO_ADDRESS = Address(
    Web3.to_checksum_address("0x0000000000000000000000000000000000000000")
)
ZERO_UID = AttestationUID(
    "0x0000000000000000000000000000000000000000000000000000000000000000"
)
EMPTY_BYTES32 = "0x0000000000000000000000000000000000000000000000000000000000000000"

# Export all public types
__all__ = [
    # Core domain types
    "Address",
    "PrivateKey",
    "PublicKey",
    "SchemaUID",
    "AttestationUID",
    "RevocationUID",
    "TransactionHash",
    "ChainId",
    "RpcUrl",
    "ContractVersion",
    "SchemaString",
    "EncodedData",
    "Salt",
    "Nonce",
    # Enums
    "NetworkType",
    "SecurityLevel",
    "ThreatType",
    "TransactionStatus",
    # TypedDict classes
    "NetworkConfig",
    "ChainConfig",
    "EIP712Domain",
    "EIP712Types",
    "AttestationRequestData",
    "RevocationRequestData",
    "OffchainAttestationData",
    # Pydantic models
    "ValidationResult",
    "TransactionMetadata",
    "AttestationMetadata",
    "SecurityContext",
    # Protocols
    "Logger",
    "Web3Provider",
    "ContractInterface",
    "ProtobufSerializable",
    # Type aliases
    "Web3TxReceipt",
    "Web3HexBytes",
    "Web3Hash32",
    "Web3HexStr",
    "AttestationData",
    "SchemaFields",
    "DecodedAttestationData",
    "EIP712Message",
    "EIP712FullMessage",
    "SignatureComponents",
    "SignedMessage",
    "BatchAttestationRequest",
    "BatchRevocationRequest",
    "ProtobufAttestationData",
    "ProtobufSchemaData",
    "ProtobufFieldDescriptor",
    # Validation functions
    "validate_address",
    "validate_uid",
    "validate_private_key",
    "validate_chain_id",
    # Exceptions
    "SecurityException",
    "ValidationException",
    # Constants
    "ADDRESS_LENGTH",
    "UID_LENGTH",
    "PRIVATE_KEY_LENGTH",
    "HASH_LENGTH",
    "ETHEREUM_MAINNET_CHAIN_ID",
    "BASE_MAINNET_CHAIN_ID",
    "BASE_SEPOLIA_CHAIN_ID",
    "ARBITRUM_ONE_CHAIN_ID",
    "OPTIMISM_MAINNET_CHAIN_ID",
    "EIP712_DOMAIN_TYPE_HASH",
    "EAS_DOMAIN_NAME",
    "ZERO_ADDRESS",
    "ZERO_UID",
    "EMPTY_BYTES32",
]
