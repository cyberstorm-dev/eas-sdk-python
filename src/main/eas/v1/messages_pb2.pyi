from collections.abc import Iterable as _Iterable
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar
from typing import Optional as _Optional
from typing import Union as _Union

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf.internal import containers as _containers

DESCRIPTOR: _descriptor.FileDescriptor

class Schema(_message.Message):
    __slots__ = (
        "id",
        "schema",
        "creator",
        "resolver",
        "revocable",
        "index",
        "txid",
        "time",
    )
    ID_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_FIELD_NUMBER: _ClassVar[int]
    CREATOR_FIELD_NUMBER: _ClassVar[int]
    RESOLVER_FIELD_NUMBER: _ClassVar[int]
    REVOCABLE_FIELD_NUMBER: _ClassVar[int]
    INDEX_FIELD_NUMBER: _ClassVar[int]
    TXID_FIELD_NUMBER: _ClassVar[int]
    TIME_FIELD_NUMBER: _ClassVar[int]
    id: str
    schema: str
    creator: str
    resolver: str
    revocable: bool
    index: str
    txid: str
    time: int
    def __init__(
        self,
        id: _Optional[str] = ...,
        schema: _Optional[str] = ...,
        creator: _Optional[str] = ...,
        resolver: _Optional[str] = ...,
        revocable: _Optional[bool] = ...,
        index: _Optional[str] = ...,
        txid: _Optional[str] = ...,
        time: _Optional[int] = ...,
    ) -> None: ...

class Attestation(_message.Message):
    __slots__ = (
        "id",
        "schema_id",
        "attester",
        "recipient",
        "time",
        "expiration_time",
        "revocable",
        "revoked",
        "data",
        "txid",
        "time_created",
        "revocation_time",
        "ref_uid",
        "ipfs_hash",
        "is_offchain",
    )
    ID_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_ID_FIELD_NUMBER: _ClassVar[int]
    ATTESTER_FIELD_NUMBER: _ClassVar[int]
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    TIME_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_TIME_FIELD_NUMBER: _ClassVar[int]
    REVOCABLE_FIELD_NUMBER: _ClassVar[int]
    REVOKED_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    TXID_FIELD_NUMBER: _ClassVar[int]
    TIME_CREATED_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_TIME_FIELD_NUMBER: _ClassVar[int]
    REF_UID_FIELD_NUMBER: _ClassVar[int]
    IPFS_HASH_FIELD_NUMBER: _ClassVar[int]
    IS_OFFCHAIN_FIELD_NUMBER: _ClassVar[int]
    id: str
    schema_id: str
    attester: str
    recipient: str
    time: int
    expiration_time: int
    revocable: bool
    revoked: bool
    data: str
    txid: str
    time_created: int
    revocation_time: int
    ref_uid: str
    ipfs_hash: str
    is_offchain: bool
    def __init__(
        self,
        id: _Optional[str] = ...,
        schema_id: _Optional[str] = ...,
        attester: _Optional[str] = ...,
        recipient: _Optional[str] = ...,
        time: _Optional[int] = ...,
        expiration_time: _Optional[int] = ...,
        revocable: _Optional[bool] = ...,
        revoked: _Optional[bool] = ...,
        data: _Optional[str] = ...,
        txid: _Optional[str] = ...,
        time_created: _Optional[int] = ...,
        revocation_time: _Optional[int] = ...,
        ref_uid: _Optional[str] = ...,
        ipfs_hash: _Optional[str] = ...,
        is_offchain: _Optional[bool] = ...,
    ) -> None: ...

class SchemaResponse(_message.Message):
    __slots__ = ("schema",)
    SCHEMA_FIELD_NUMBER: _ClassVar[int]
    schema: Schema
    def __init__(self, schema: _Optional[_Union[Schema, _Mapping]] = ...) -> None: ...

class AttestationResponse(_message.Message):
    __slots__ = ("attestation",)
    ATTESTATION_FIELD_NUMBER: _ClassVar[int]
    attestation: Attestation
    def __init__(
        self, attestation: _Optional[_Union[Attestation, _Mapping]] = ...
    ) -> None: ...

class GraphQLError(_message.Message):
    __slots__ = ("message", "locations", "path")
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    LOCATIONS_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    message: str
    locations: _containers.RepeatedScalarFieldContainer[str]
    path: _containers.RepeatedScalarFieldContainer[str]
    def __init__(
        self,
        message: _Optional[str] = ...,
        locations: _Optional[_Iterable[str]] = ...,
        path: _Optional[_Iterable[str]] = ...,
    ) -> None: ...

class GraphQLResponse(_message.Message):
    __slots__ = ("schema_response", "attestation_response", "errors")
    SCHEMA_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    ATTESTATION_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    ERRORS_FIELD_NUMBER: _ClassVar[int]
    schema_response: SchemaResponse
    attestation_response: AttestationResponse
    errors: _containers.RepeatedCompositeFieldContainer[GraphQLError]
    def __init__(
        self,
        schema_response: _Optional[_Union[SchemaResponse, _Mapping]] = ...,
        attestation_response: _Optional[_Union[AttestationResponse, _Mapping]] = ...,
        errors: _Optional[_Iterable[_Union[GraphQLError, _Mapping]]] = ...,
    ) -> None: ...
