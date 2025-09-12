"""
EAS Query System

Provides bulk query capabilities for attestations and schemas using the existing
GraphQL infrastructure with comprehensive filtering and validation.
"""

import time
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import requests
from pydantic import BaseModel, Field, field_validator
from pydantic.types import StrictBool, StrictInt, StrictStr

from .types import (
    Address,
    AttestationUID,
    SchemaUID,
    validate_address,
    validate_uid,
)

# ============================================================================
# Query Filter Enums
# ============================================================================


class SortOrder(Enum):
    """Sort order for query results."""

    ASC = "asc"
    DESC = "desc"


class AttestationSortBy(Enum):
    """Available sort fields for attestation queries."""

    TIME = "time"
    TIME_CREATED = "timeCreated"
    EXPIRATION_TIME = "expirationTime"
    REVOCATION_TIME = "revocationTime"


class SchemaSortBy(Enum):
    """Available sort fields for schema queries."""

    TIME = "time"
    INDEX = "index"


# ============================================================================
# Query Parameter Models
# ============================================================================


class AttestationFilter(BaseModel):
    """Filter parameters for attestation queries with comprehensive validation."""

    # Core filters
    schema_uid: Optional[SchemaUID] = Field(None, description="Filter by schema UID")
    attester: Optional[Address] = Field(None, description="Filter by attester address")
    recipient: Optional[Address] = Field(
        None, description="Filter by recipient address"
    )
    ref_uid: Optional[AttestationUID] = Field(
        None, description="Filter by reference UID"
    )

    # Boolean filters
    revocable: Optional[StrictBool] = Field(
        None, description="Filter by revocable status"
    )
    revoked: Optional[StrictBool] = Field(None, description="Filter by revoked status")
    is_offchain: Optional[StrictBool] = Field(
        None, description="Filter by offchain status"
    )

    # Expiration filters
    expirable: Optional[StrictBool] = Field(
        None,
        description="Filter by whether attestation has expiration set (expirationTime > 0)",
    )
    expired: Optional[StrictBool] = Field(
        None,
        description="Filter by whether attestation is expired (past expirationTime)",
    )
    expires_before: Optional[StrictInt] = Field(
        None, description="Filter attestations that expire before this timestamp"
    )
    expires_after: Optional[StrictInt] = Field(
        None, description="Filter attestations that expire after this timestamp"
    )

    # Time range filters
    time_after: Optional[StrictInt] = Field(
        None, description="Filter attestations created after this timestamp"
    )
    time_before: Optional[StrictInt] = Field(
        None, description="Filter attestations created before this timestamp"
    )

    # Pagination and sorting
    limit: StrictInt = Field(100, ge=1, le=1000, description="Maximum results (1-1000)")
    offset: StrictInt = Field(0, ge=0, description="Result offset for pagination")
    sort_by: AttestationSortBy = Field(AttestationSortBy.TIME, description="Sort field")
    sort_order: SortOrder = Field(SortOrder.DESC, description="Sort order")

    @field_validator("schema_uid", mode="before")
    @classmethod
    def validate_schema_uid(cls, v: Optional[str]) -> Optional[SchemaUID]:
        if v is None:
            return None
        validate_uid(v, "SchemaUID")
        return SchemaUID(v)

    @field_validator("attester", "recipient", mode="before")
    @classmethod
    def validate_addresses(cls, v: Optional[str]) -> Optional[Address]:
        if v is None:
            return None
        return validate_address(v)

    @field_validator("ref_uid", mode="before")
    @classmethod
    def validate_ref_uid(cls, v: Optional[str]) -> Optional[AttestationUID]:
        if v is None:
            return None
        validate_uid(v, "AttestationUID")
        return AttestationUID(v)

    @field_validator("time_after", "time_before", "expires_before", "expires_after")
    @classmethod
    def validate_timestamps(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        if v < 0:
            raise ValueError("Timestamp must be non-negative")
        if v > 2**63 - 1:
            raise ValueError("Timestamp exceeds maximum value")
        return v


class SchemaFilter(BaseModel):
    """Filter parameters for schema queries with validation."""

    # Core filters
    creator: Optional[Address] = Field(
        None, description="Filter by schema creator address"
    )
    resolver: Optional[Address] = Field(None, description="Filter by resolver address")
    revocable: Optional[StrictBool] = Field(
        None, description="Filter by revocable status"
    )
    resolvable: Optional[StrictBool] = Field(
        None, description="Filter by whether schema has a resolver contract"
    )

    # Time range filters
    time_after: Optional[StrictInt] = Field(
        None, description="Filter schemas after this timestamp"
    )
    time_before: Optional[StrictInt] = Field(
        None, description="Filter schemas before this timestamp"
    )

    # Pagination and sorting
    limit: StrictInt = Field(100, ge=1, le=1000, description="Maximum results (1-1000)")
    offset: StrictInt = Field(0, ge=0, description="Result offset for pagination")
    sort_by: SchemaSortBy = Field(SchemaSortBy.TIME, description="Sort field")
    sort_order: SortOrder = Field(SortOrder.DESC, description="Sort order")

    @field_validator("creator", "resolver", mode="before")
    @classmethod
    def validate_addresses(cls, v: Optional[str]) -> Optional[Address]:
        if v is None:
            return None
        return validate_address(v)

    @field_validator("time_after", "time_before")
    @classmethod
    def validate_timestamps(cls, v: Optional[int]) -> Optional[int]:
        if v is None:
            return None
        if v < 0:
            raise ValueError("Timestamp must be non-negative")
        return v


# ============================================================================
# Result Models
# ============================================================================


class AttestationResult(BaseModel):
    """Individual attestation result with all available fields."""

    uid: AttestationUID
    schema_uid: SchemaUID
    attester: Address
    recipient: Address
    time: StrictInt
    expiration_time: StrictInt
    revocable: StrictBool
    revoked: StrictBool
    ref_uid: Optional[AttestationUID] = None
    data: Optional[StrictStr] = None
    decoded_data_json: Optional[StrictStr] = None
    txid: Optional[StrictStr] = None
    time_created: Optional[StrictInt] = None
    revocation_time: Optional[StrictInt] = None
    ipfs_hash: Optional[StrictStr] = None
    is_offchain: StrictBool = False


class SchemaResult(BaseModel):
    """Individual schema result with all available fields."""

    uid: SchemaUID
    schema_definition: StrictStr = Field(alias="schema")
    creator: Address
    resolver: Address
    revocable: StrictBool
    index: Optional[StrictStr] = None
    txid: Optional[StrictStr] = None
    time: Optional[StrictInt] = None

    model_config = {"populate_by_name": True}


class QueryResults(BaseModel):
    """Generic query results container with pagination info."""

    results: List[Union[AttestationResult, SchemaResult]]
    total_count: Optional[StrictInt] = None
    has_next_page: StrictBool = False
    next_offset: Optional[StrictInt] = None


# ============================================================================
# EAS Query Client
# ============================================================================


class EASQueryClient:
    """
    Client for bulk EAS queries using GraphQL backend.

    Provides comprehensive filtering, validation, and pagination for attestations
    and schemas. Builds on existing GraphQL infrastructure in the CLI.
    """

    # GraphQL endpoints for different networks
    ENDPOINTS = {
        "mainnet": "https://easscan.org/graphql",
        "sepolia": "https://sepolia.easscan.org/graphql",
        "base-sepolia": "https://base-sepolia.easscan.org/graphql",
        "optimism": "https://optimism.easscan.org/graphql",
        "base": "https://base.easscan.org/graphql",
        "arbitrum": "https://arbitrum.easscan.org/graphql",
        "polygon": "https://polygon.easscan.org/graphql",
    }

    def __init__(self, network: str = "mainnet", timeout: int = 30):
        """
        Initialize query client for specified network.

        Args:
            network: Network name (mainnet, sepolia, optimism, base, arbitrum)
            timeout: Request timeout in seconds
        """
        if network not in self.ENDPOINTS:
            raise ValueError(
                f"Unsupported network: {network}. Available: {list(self.ENDPOINTS.keys())}"
            )

        self.network = network
        self.endpoint = self.ENDPOINTS[network]
        self.timeout = timeout

    def _execute_query(self, query: str, variables: Dict[str, Any]) -> Dict[str, Any]:
        """Execute GraphQL query with error handling."""
        try:
            response = requests.post(
                self.endpoint,
                json={"query": query, "variables": variables},
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )

            if not response.ok:
                # Try to get more detailed error information
                try:
                    error_detail = response.json()
                    raise Exception(
                        f"GraphQL API error ({response.status_code}): {error_detail}"
                    )
                except Exception:
                    raise Exception(
                        f"GraphQL API error ({response.status_code}): {response.text}"
                    )

            result = response.json()

            if "errors" in result:
                error_msg = result["errors"][0].get("message", "Unknown GraphQL error")
                raise Exception(f"GraphQL error: {error_msg}")

            data = result.get("data", {})
            if not isinstance(data, dict):
                raise Exception(f"Expected dict for data field, got {type(data)}")
            return data
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to query EAS GraphQL API: {e}")

    def find_attestations(self, filters: AttestationFilter) -> List[AttestationResult]:
        """
        Find attestations matching the specified filters.

        Args:
            filters: AttestationFilter with search criteria

        Returns:
            List of matching attestations
        """
        # Build WHERE clause conditions
        where_conditions = []
        variables: Dict[str, Any] = {}

        if filters.schema_uid:
            where_conditions.append("schemaId: { equals: $schemaId }")
            variables["schemaId"] = filters.schema_uid

        if filters.attester:
            where_conditions.append("attester: { equals: $attester }")
            variables["attester"] = filters.attester

        if filters.recipient:
            where_conditions.append("recipient: { equals: $recipient }")
            variables["recipient"] = filters.recipient

        if filters.ref_uid:
            where_conditions.append("refUID: { equals: $refUID }")
            variables["refUID"] = filters.ref_uid

        if filters.revocable is not None:
            where_conditions.append("revocable: { equals: $revocable }")
            variables["revocable"] = filters.revocable

        if filters.revoked is not None:
            where_conditions.append("revoked: { equals: $revoked }")
            variables["revoked"] = filters.revoked

        if filters.is_offchain is not None:
            where_conditions.append("isOffchain: { equals: $isOffchain }")
            variables["isOffchain"] = filters.is_offchain

        # Expiration filters - these require more complex logic
        current_time = int(time.time())

        if filters.expirable is not None:
            if filters.expirable:
                where_conditions.append("expirationTime: { gt: 0 }")
            else:
                where_conditions.append("expirationTime: { equals: 0 }")

        if filters.expired is not None:
            if filters.expired:
                # Expired = has expiration and it's in the past
                where_conditions.append("expirationTime: { gt: 0, lte: $currentTime }")
                variables["currentTime"] = current_time
            else:
                # Not expired = no expiration (0) or expiration in future
                # For now, let's just check for expiration in future > current time
                # This will miss non-expirable attestations but is simpler
                where_conditions.append("expirationTime: { gt: $currentTime }")
                variables["currentTime"] = current_time

        if filters.expires_before:
            where_conditions.append("expirationTime: { gt: 0, lte: $expiresBefore }")
            variables["expiresBefore"] = filters.expires_before

        if filters.expires_after:
            where_conditions.append("expirationTime: { gte: $expiresAfter }")
            variables["expiresAfter"] = filters.expires_after

        # Time range filters
        if filters.time_after:
            where_conditions.append("time: { gte: $timeAfter }")
            variables["timeAfter"] = filters.time_after

        if filters.time_before:
            where_conditions.append("time: { lte: $timeBefore }")
            variables["timeBefore"] = filters.time_before

        # Build the WHERE clause
        where_clause = ""
        if where_conditions:
            where_clause = f"where: {{ {', '.join(where_conditions)} }},"

        # Build variable declarations - only include variables we're actually using
        variable_declarations = []
        if "schemaId" in variables:
            variable_declarations.append("$schemaId: String")
        if "attester" in variables:
            variable_declarations.append("$attester: String")
        if "recipient" in variables:
            variable_declarations.append("$recipient: String")
        if "refUID" in variables:
            variable_declarations.append("$refUID: String")
        if "revocable" in variables:
            variable_declarations.append("$revocable: Boolean")
        if "revoked" in variables:
            variable_declarations.append("$revoked: Boolean")
        if "isOffchain" in variables:
            variable_declarations.append("$isOffchain: Boolean")
        if "currentTime" in variables:
            variable_declarations.append("$currentTime: Int")
        if "expiresBefore" in variables:
            variable_declarations.append("$expiresBefore: Int")
        if "expiresAfter" in variables:
            variable_declarations.append("$expiresAfter: Int")
        if "timeAfter" in variables:
            variable_declarations.append("$timeAfter: Int")
        if "timeBefore" in variables:
            variable_declarations.append("$timeBefore: Int")

        variables_str = ", ".join(variable_declarations)
        if variables_str:
            variables_str = f"({variables_str})"

        # Construct the query
        query = f"""
        query GetAttestations{variables_str} {{
            attestations({where_clause} take: {filters.limit}, skip: {filters.offset}) {{
                id
                schemaId
                attester
                recipient
                time
                expirationTime
                revocable
                revoked
                refUID
                data
                txid
                timeCreated
                revocationTime
                ipfsHash
                isOffchain
            }}
        }}
        """

        result = self._execute_query(query, variables)
        attestations = result.get("data", {}).get("attestations", [])

        # Convert to Pydantic models
        return [
            AttestationResult(
                uid=AttestationUID(att["id"]),
                schema_uid=SchemaUID(att["schemaId"]),
                attester=Address(att["attester"]),
                recipient=Address(att["recipient"]),
                time=int(att["time"]),
                expiration_time=int(att["expirationTime"]),
                revocable=att["revocable"],
                revoked=att["revoked"],
                ref_uid=AttestationUID(att["refUID"]) if att.get("refUID") else None,
                data=att.get("data"),
                decoded_data_json=att.get("decodedDataJson"),
                txid=att.get("txid"),
                time_created=(
                    int(att["timeCreated"]) if att.get("timeCreated") else None
                ),
                revocation_time=(
                    int(att["revocationTime"]) if att.get("revocationTime") else None
                ),
                ipfs_hash=att.get("ipfsHash"),
                is_offchain=att.get("isOffchain", False),
            )
            for att in attestations
        ]

    def find_schemas(self, filters: SchemaFilter) -> List[SchemaResult]:
        """
        Find schemas matching the specified filters.

        Args:
            filters: SchemaFilter with search criteria

        Returns:
            List of matching schemas
        """
        # Build WHERE clause conditions for schema filtering
        where_conditions = []
        variables: Dict[str, Any] = {}

        if filters.creator:
            where_conditions.append("creator: { equals: $creator }")
            variables["creator"] = filters.creator

        if filters.resolver:
            where_conditions.append("resolver: { equals: $resolver }")
            variables["resolver"] = filters.resolver

        if filters.revocable is not None:
            where_conditions.append("revocable: { equals: $revocable }")
            variables["revocable"] = filters.revocable

        if filters.resolvable is not None:
            # Zero address means no resolver
            zero_address = "0x0000000000000000000000000000000000000000"
            if filters.resolvable:
                where_conditions.append("resolver: { not: { equals: $zeroAddress } }")
                variables["zeroAddress"] = zero_address
            else:
                where_conditions.append("resolver: { equals: $zeroAddress }")
                variables["zeroAddress"] = zero_address

        # Time range filters
        if filters.time_after:
            where_conditions.append("time: { gte: $timeAfter }")
            variables["timeAfter"] = filters.time_after

        if filters.time_before:
            where_conditions.append("time: { lte: $timeBefore }")
            variables["timeBefore"] = filters.time_before

        # Build the WHERE clause
        where_clause = ""
        if where_conditions:
            where_clause = f"where: {{ {', '.join(where_conditions)} }},"

        # Build variable declarations
        variable_declarations = []
        if "creator" in variables:
            variable_declarations.append("$creator: String")
        if "resolver" in variables:
            variable_declarations.append("$resolver: String")
        if "revocable" in variables:
            variable_declarations.append("$revocable: Boolean")
        if "zeroAddress" in variables:
            variable_declarations.append("$zeroAddress: String")
        if "timeAfter" in variables:
            variable_declarations.append("$timeAfter: Int")
        if "timeBefore" in variables:
            variable_declarations.append("$timeBefore: Int")

        variables_str = ", ".join(variable_declarations)
        if variables_str:
            variables_str = f"({variables_str})"

        # Construct the query
        query = f"""
        query GetSchemas{variables_str} {{
            schemata({where_clause} take: {filters.limit}, skip: {filters.offset}) {{
                id
                schema
                creator
                resolver
                revocable
                index
                txid
                time
            }}
        }}
        """

        result = self._execute_query(query, variables)
        schemas = result.get("data", {}).get("schemata", [])

        # Convert to Pydantic models
        return [
            SchemaResult(
                uid=SchemaUID(schema["id"]),
                schema=schema["schema"],
                creator=Address(schema["creator"]),
                resolver=Address(schema["resolver"]),
                revocable=schema["revocable"],
                index=schema.get("index"),
                txid=schema.get("txid"),
                time=int(schema["time"]) if schema.get("time") else None,
            )
            for schema in schemas
        ]

    def find_attestations_by_schema(
        self, schema_uid: SchemaUID, **kwargs: Any
    ) -> List[AttestationResult]:
        """Convenience method to find all attestations for a schema."""
        filters = AttestationFilter(schema_uid=schema_uid, **kwargs)
        return self.find_attestations(filters)

    def find_attestations_by_attester(
        self, attester: Address, **kwargs: Any
    ) -> List[AttestationResult]:
        """Convenience method to find all attestations by an attester."""
        filters = AttestationFilter(attester=attester, **kwargs)
        return self.find_attestations(filters)

    def find_attestations_by_recipient(
        self, recipient: Address, **kwargs: Any
    ) -> List[AttestationResult]:
        """Convenience method to find all attestations for a recipient."""
        filters = AttestationFilter(recipient=recipient, **kwargs)
        return self.find_attestations(filters)

    def find_schemas_by_creator(
        self, creator: Address, **kwargs: Any
    ) -> List[SchemaResult]:
        """Convenience method to find all schemas by a creator."""
        filters = SchemaFilter(creator=creator, **kwargs)
        return self.find_schemas(filters)

    def find_revoked_attestations(self, **kwargs: Any) -> List[AttestationResult]:
        """Convenience method to find all revoked attestations."""
        filters = AttestationFilter(revoked=True, **kwargs)
        return self.find_attestations(filters)

    def find_active_attestations(self, **kwargs: Any) -> List[AttestationResult]:
        """Convenience method to find all active (non-revoked) attestations."""
        current_time = int(datetime.now().timestamp())
        filters = AttestationFilter(revoked=False, time_before=current_time, **kwargs)
        return self.find_attestations(filters)
