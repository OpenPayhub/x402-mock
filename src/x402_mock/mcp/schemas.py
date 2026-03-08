"""
MCP Configuration Schemas

Pydantic models for McpServerConfig and McpClientConfig.  Sensitive fields
use ``SecretStr`` so that plain ``str`` values are automatically wrapped on
assignment and never appear in ``repr()`` / logs.

McpServerConfig env vars:
    EVM_PRIVATE_KEY   - EVM wallet private key for AdapterHub (optional).
    X402_TOKEN_KEY    - HMAC secret for Bearer tokens (required).

McpClientConfig env vars:
    EVM_PRIVATE_KEY   - EVM wallet private key for AdapterHub (optional).

All other fields carry sensible defaults and must be supplied explicitly
(e.g. when calling :func:`~x402_mock.mcp.server.create_server` or
:func:`~x402_mock.mcp.client.create_client`).
"""

import os
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class McpServerConfig(BaseModel):
    """Server configuration. Sensitive fields are stored as SecretStr."""

    model_config = ConfigDict(frozen=True)

    # --- secrets (SecretStr: str input auto-wrapped, value masked in repr) ---
    token_key: SecretStr = Field(
        description="HMAC secret for signing and verifying Bearer access tokens.",
        exclude=True
    )
    evm_private_key: Optional[SecretStr] = Field(
        default=None,
        description="EVM wallet private key used by AdapterHub.",
        exclude=True
    )

    # --- plain configuration (no env-var sourcing) ---
    token_endpoint: str = Field(
        default="/token",
        description="URL path advertised to clients inside Http402PaymentEvent.",
    )
    token_expires_in: int = Field(
        default=3600,
        ge=1,
        description="Bearer token lifetime in seconds.",
    )
    enable_auto_settlement: bool = Field(
        default=True,
        description="Automatically settle on-chain after permit verification.",
    )
    request_timeout: int = Field(
        default=60,
        ge=1,
        description="HTTP request timeout (seconds) for on-chain RPC calls.",
    )
    server_name: str = Field(
        default="x402",
        description="Display name of the FastMCP server instance.",
    )

    @classmethod
    def from_env(cls) -> "McpServerConfig":
        """
        Build a ``McpServerConfig`` reading only the two secret fields from
        environment variables.  All other fields use their defaults.

        Raises:
            KeyError: If ``X402_TOKEN_KEY`` is not set.
        """
        return cls(
            token_key=os.environ.get("X402_TOKEN_KEY"),
            evm_private_key=os.environ.get("EVM_PRIVATE_KEY"),
        )


class McpClientConfig(BaseModel):
    """Client configuration. Sensitive fields are stored as SecretStr."""

    model_config = ConfigDict(frozen=True)

    # --- secrets ---
    evm_private_key: Optional[SecretStr] = Field(
        default=None,
        description="EVM wallet private key used by AdapterHub for signing payment permits.",
        exclude=True,
    )

    # --- plain configuration ---
    request_timeout: int = Field(
        default=60,
        ge=1,
        description="HTTP request timeout (seconds) for on-chain RPC calls.",
    )
    server_name: str = Field(
        default="x402-client",
        description="Display name of the FastMCP server instance.",
    )

    @classmethod
    def from_env(cls) -> "McpClientConfig":
        """
        Build a ``McpClientConfig`` reading the secret field from the
        environment variable.  All other fields use their defaults.
        """
        return cls(
            evm_private_key=os.environ.get("EVM_PRIVATE_KEY"),
        )
