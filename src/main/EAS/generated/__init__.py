# Generated protobuf files for EAS SDK
# Type: ignore comments needed for generated protobuf code
from .eas.v1 import messages_pb2, messages_pb2_grpc

# Import the main message classes for easy access
from .eas.v1.messages_pb2 import (  # type: ignore
    Attestation,
    AttestationResponse,
    GraphQLError,
    GraphQLResponse,
    Schema,
    SchemaResponse,
)

__all__ = [
    "eas.v1.messages_pb2",
    "eas.v1.messages_pb2_grpc",
    "Schema",
    "Attestation",
    "SchemaResponse",
    "AttestationResponse",
    "GraphQLError",
    "GraphQLResponse",
]
