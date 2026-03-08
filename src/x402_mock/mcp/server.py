"""
X402 MCP Server

Assembles all X402 tool providers (EvmTools, AdapterHubTools,
ServerWorkflowTools) onto a single FastMCP instance and exposes a
``main()`` entry point consumed by the ``x402-mcp`` CLI command.

Quick start::

    # Set required env vars (only secrets come from the environment)
    export EVM_PRIVATE_KEY="0x..."
    export X402_TOKEN_KEY="my-secret"

    # Run the MCP server (stdio transport)
    x402-mcp

    # Or drive it from Python — all options explicit
    from x402_mock.mcp import create_server

    mcp = create_server(
        token_key="my-secret",
        evm_private_key="0x...",
        token_expires_in=7200,
    )
    mcp.run()
"""

from typing import Optional, Union

from mcp.server.fastmcp import FastMCP
from pydantic import SecretStr

from ..adapters.adapters_hub import AdapterHub
from .schemas import McpServerConfig
from .tools.raw_tools import AdapterHubTools, EvmTools
from .tools.workflow_tools import ServerWorkflowTools


def create_server(
    token_key: Union[str, SecretStr],
    evm_private_key: Optional[Union[str, SecretStr]] = None,
    token_endpoint: str = "/token",
    token_expires_in: int = 3600,
    enable_auto_settlement: bool = True,
    request_timeout: int = 60,
    server_name: str = "x402",
) -> FastMCP:
    """
    Build and return a fully wired FastMCP server instance.

    All parameters are explicit — nothing is read from environment variables
    here.  Use :func:`main` (or :meth:`McpServerConfig.from_env`) when you
    want env-var-based configuration.

    Args:
        token_key: HMAC secret for signing and verifying Bearer tokens.
            Plain ``str`` is accepted and automatically wrapped as
            ``SecretStr`` by the config model.
        evm_private_key: EVM wallet private key for AdapterHub.  Optional;
            omit when running in client-only or observer roles.
        token_endpoint: URL path returned to clients inside
            Http402PaymentEvent.  Defaults to ``"/token"``.
        token_expires_in: Bearer token lifetime in seconds.  Defaults to 3600.
        enable_auto_settlement: Automatically settle on-chain after permit
            verification.  Defaults to True.
        request_timeout: HTTP timeout for on-chain RPC calls in seconds.
            Defaults to 60.
        server_name: Display name of the FastMCP server.  Defaults to
            ``"x402"``.

    Returns:
        A configured :class:`~mcp.server.fastmcp.FastMCP` instance with
        :class:`~.tools.raw_tools.EvmTools`,
        :class:`~.tools.raw_tools.AdapterHubTools`, and
        :class:`~.tools.workflow_tools.ServerWorkflowTools` registered.

    Example::

        mcp = create_server(token_key="secret", evm_private_key="0x...")
        mcp.run()
    """
    config = McpServerConfig(
        token_key=token_key,
        evm_private_key=evm_private_key,
        token_endpoint=token_endpoint,
        token_expires_in=token_expires_in,
        enable_auto_settlement=enable_auto_settlement,
        request_timeout=request_timeout,
        server_name=server_name,
    )

    mcp = FastMCP(config.server_name)
    hub = AdapterHub(
        evm_private_key=(
            config.evm_private_key.get_secret_value()
            if config.evm_private_key is not None
            else None
        ),
        request_timeout=config.request_timeout,
    )

    # Register tool providers — order determines listing in MCP clients.
    EvmTools(mcp=mcp)
    AdapterHubTools(mcp=mcp, hub=hub)
    ServerWorkflowTools(
        mcp=mcp,
        adapter_hub=hub,
        token_key=config.token_key.get_secret_value(),
        token_endpoint=config.token_endpoint,
        token_expires_in=config.token_expires_in,
        enable_auto_settlement=config.enable_auto_settlement,
    )

    return mcp


def main() -> None:
    """
    CLI entry point — starts the X402 MCP server over stdio transport.

    Called by the ``x402-mcp`` console script.  Only the two secret fields
    are sourced from the environment:

    .. code-block:: bash

        export X402_TOKEN_KEY="my-secret"   # required
        export EVM_PRIVATE_KEY="0x..."       # optional

    All other server options use defaults.  To customise them, call
    :func:`create_server` directly instead.

    Raises:
        KeyError: If ``X402_TOKEN_KEY`` is not set.
    """
    config = McpServerConfig.from_env()
    mcp = create_server(
        token_key=config.token_key,
        evm_private_key=config.evm_private_key,
    )
    mcp.run()


if __name__ == "__main__":
    main()
