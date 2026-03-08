"""
X402 MCP Client

Assembles all X402 client-side tool providers (EvmTools, AdapterHubTools,
ClientWorkflowTools) onto a single FastMCP instance and exposes a
``main()`` entry point consumed by the ``x402-mcp-client`` CLI command.

Quick start::

    # Set optional env var to pre-fund the client with a signing key
    export EVM_PRIVATE_KEY="0x..."

    # Run the MCP client server (stdio transport)
    x402-mcp-client

    # Or drive it from Python — all options explicit
    from x402_mock.mcp import create_client

    mcp = create_client(
        evm_private_key="0x...",
        server_name="my-x402-client",
    )
    mcp.run()
"""

from typing import Optional, Union

from mcp.server.fastmcp import FastMCP
from pydantic import SecretStr

from ..adapters.adapters_hub import AdapterHub
from .schemas import McpClientConfig
from .tools.raw_tools import AdapterHubTools, EvmTools
from .tools.workflow_tools import ClientWorkflowTools


def create_client(
    evm_private_key: Optional[Union[str, SecretStr]] = None,
    request_timeout: int = 60,
    server_name: str = "x402-client",
) -> FastMCP:
    """
    Build and return a fully wired FastMCP client instance.

    All parameters are explicit — nothing is read from environment variables
    here.  Use :func:`main` (or :meth:`McpClientConfig.from_env`) when you
    want env-var-based configuration.

    Args:
        evm_private_key: EVM wallet private key for AdapterHub, used to sign
            payment permits when handling 402 responses.  Optional; if omitted
            payment methods must be registered via the ``add_payment_method``
            MCP tool before making requests.
        request_timeout: HTTP timeout for on-chain RPC calls in seconds.
            Defaults to 60.
        server_name: Display name of the FastMCP server.  Defaults to
            ``"x402-client"``.

    Returns:
        A configured :class:`~mcp.server.fastmcp.FastMCP` instance with
        :class:`~.tools.raw_tools.EvmTools`,
        :class:`~.tools.raw_tools.AdapterHubTools`, and
        :class:`~.tools.workflow_tools.ClientWorkflowTools` registered.

    Example::

        mcp = create_client(evm_private_key="0x...")
        mcp.run()
    """
    config = McpClientConfig(
        evm_private_key=evm_private_key,
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
    ClientWorkflowTools(mcp=mcp, adapter_hub=hub)

    return mcp


def main() -> None:
    """
    CLI entry point — starts the X402 MCP client server over stdio transport.

    Called by the ``x402-mcp-client`` console script.  Only the secret field
    is sourced from the environment:

    .. code-block:: bash

        export EVM_PRIVATE_KEY="0x..."   # optional

    All other client options use defaults.  To customise them, call
    :func:`create_client` directly instead.
    """
    config = McpClientConfig.from_env()
    mcp = create_client(
        evm_private_key=config.evm_private_key,
    )
    mcp.run()


if __name__ == "__main__":
    main()
