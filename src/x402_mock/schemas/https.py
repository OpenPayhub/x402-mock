"""
HTTP Request/Response Schema Models for x402 Payment Protocol

This module defines all Pydantic models used for HTTP communication between
client and server in the x402 payment authentication flow. These models ensure
type-safe, validated serialization/deserialization of all HTTP requests and responses.

The main payment flow consists of:
1. Client retrieves payment requirements from server (402 response)
2. Client authorizes payment using permits
3. Client exchanges permit for access token (POST request)
4. Client accesses resource with access token in Authorization header

All models inherit from BaseModel for automatic validation and serialization.
"""

from typing import Optional, List, Dict, Any

from pydantic import BaseModel, Field, ConfigDict

from ..adapters.unions import (
    PaymentComponentTypes,
    PermitTypes
)
from .versions import ProtocalVersion


# ============================================================================
# Request Headers
# ============================================================================

class ClientRequestHeader(BaseModel):
    """HTTP request headers sent by client.
    
    Attributes:
        content_type: MIME type of request body (default: application/json).
        authorization: Optional bearer token for authenticated requests.
    """
    model_config = ConfigDict(populate_by_name=True)
    content_type: str = Field(default="application/json", alias="Content-Type")
    authorization: Optional[str] = Field(default=None, alias="Authorization")


# ============================================================================
# Step 1: Server's 402 Payment Required Response
# ============================================================================

class ServerPaymentScheme(BaseModel):
    """Payment scheme configuration for client payment authorization.
    
    Describes the specific payment requirements and supported payment methods
    that the client must fulfill to access the protected resource.
    
    Attributes:
        payment_components: List of supported payment options/requirements.
        protocol_version: Version of the payment protocol being used.
    """
    payment_components: List[PaymentComponentTypes] = Field(
        ..., 
        description="List of supported payment options"
    )
    protocol_version: str = Field(
        ..., 
        description="Payment protocol version"
    )


class Server402ResponsePayload(BaseModel):
    """Server response payload for 402 Payment Required status.
    
    This is returned by the server when client attempts to access a protected
    resource without valid authorization. It instructs the client where to submit
    payment and what payment methods are accepted.
    
    Attributes:
        access_token_endpoint: URL endpoint for POST request to obtain access token.
        payment_scheme: Payment requirements and accepted payment methods.
        payment_instruction: Optional instruction explaining payment process and endpoint usage.
    """
    access_token_endpoint: str = Field(
        ..., 
        description="Endpoint where client can request access token via POST"
    )
    payment_scheme: ServerPaymentScheme = Field(
        ..., 
        description="Payment requirements and supported payment methods"
    )
    payment_instruction: Optional[str] = Field(
        None,
        description="Optional instruction for payment submission process"
    )


# ============================================================================
# Step 2: Client's Token Request (POST)
# ============================================================================

class ClientTokenRequest(BaseModel):
    """Client request to exchange permit for access token.
    
    The client sends this request to the server's access token endpoint after
    generating a valid permit that authorizes the payment. The server validates
    the permit and returns an access token if the permit is valid.
    
    This request should be sent as POST with JSON body.
    
    Attributes:
        version: Protocol version of the permit.
        permit: Signed permit authorizing the payment.
    """
    version: ProtocalVersion = Field(
        ..., 
        description="Protocol version"
    )
    permit: PermitTypes = Field(
        ..., 
        description="Signed permit authorizing payment"
    )


# ============================================================================
# Step 3: Server's Token Response
# ============================================================================

class ServerTokenResponse(BaseModel):
    """Server response containing access token and metadata.
    
    Returned when server successfully verifies and accepts a client's permit.
    The access token is used by client to access the protected resource.
    
    Attributes:
        access_token: Bearer token for authenticating subsequent requests.
        token_type: Type of token (typically "Bearer").
        expires_in: Token lifetime in seconds. None means token never expires.
        metadata: Additional metadata about the token or authorization.
    """
    access_token: str = Field(
        ..., 
        description="Bearer token for accessing protected resource"
    )
    token_type: str = Field(
        default="Bearer", 
        description="Token type (typically Bearer)"
    )
    expires_in: Optional[int] = Field(
        None, 
        ge=0,
        description="Token lifetime in seconds"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, 
        description="Additional token metadata"
    )
