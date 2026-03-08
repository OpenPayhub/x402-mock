"""
X402 MCP Server Example
=======================

Starts an MCP server that exposes the X402 *payment-server* role as tools
an AI agent can call over the Model Context Protocol (stdio transport).

Role clarification
------------------
In the x402-mock SDK there are two distinct MCP roles:

* **MCP Server (this file)** -- acts as the *payment-accepting* party.
  Provides tools:
    - ``verify_request``  -- check an Authorization header token; return a
                             402 payment scheme when absent / invalid.
    - ``issue_token``     -- accept a signed payment permit and return a
                             Bearer access token on success.
    - adapter / EVM helper tools.

* **MCP Client** -- acts as the *paying* party (see mcp_client_example.py).
  Provides tools:
    - ``add_payment_method`` -- register a local signing key + payment details.
    - ``make_request``       -- issue HTTP calls with automatic 402 handling.

Usage
-----
1. Set environment variables (or pass them explicitly to create_server()):

    $env:X402_TOKEN_KEY  = "my-hmac-secret"   # required
    $env:EVM_PRIVATE_KEY = "0x..."             # optional (on-chain settlement)

2. Run this file:

    python example/mcp_server_example.py

   The server speaks the MCP stdio protocol -- configure your AI client
   (Claude Desktop, Cursor, etc.) to launch this script as an MCP server:

    {
        "mcpServers": {
            "x402": {
                "command": "python",
                "args": ["example/mcp_server_example.py"],
                "env": {
                    "X402_TOKEN_KEY": "my-hmac-secret",
                    "EVM_PRIVATE_KEY": "0x..."
                }
            }
        }
    }
"""

import os

from mcp.server.fastmcp import FastMCP

from x402_mock.adapters.adapters_hub import AdapterHub
from x402_mock.adapters.evm.schemas import EVMPaymentComponent
from x402_mock.engine.events import SettleFailedEvent, SettleSuccessEvent, TokenIssuedEvent
from x402_mock.mcp.tools.raw_tools import AdapterHubTools, EvmTools
from x402_mock.mcp.tools.workflow_tools import ServerWorkflowTools

# ---------------------------------------------------------------------------
# Configuration -- prefer env vars for secrets in production
# ---------------------------------------------------------------------------
TOKEN_KEY = os.environ.get("X402_TOKEN_KEY", "dev-secret-change-me")
EVM_PRIVATE_KEY = os.environ.get("EVM_PRIVATE_KEY")  # None -> settlement skipped

# ---------------------------------------------------------------------------
# Build the shared AdapterHub and register accepted payment methods
# ---------------------------------------------------------------------------
hub = AdapterHub(evm_private_key=EVM_PRIVATE_KEY)
hub.register_payment_methods(
    EVMPaymentComponent(
        amount=0.5,
        currency="USDC",
        caip2="eip155:11155111",
        token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    ),
    client_role=False,
)

# ---------------------------------------------------------------------------
# Build the MCP server and wire up ServerWorkflowTools manually so we can
# attach side-effect hooks (Python-only API -- not exposed as MCP tools).
# ---------------------------------------------------------------------------
mcp = FastMCP("x402")

EvmTools(mcp=mcp)
AdapterHubTools(mcp=mcp, hub=hub)

server_tools = ServerWorkflowTools(
    mcp=mcp,
    adapter_hub=hub,
    token_key=TOKEN_KEY,
    token_endpoint="/token",
    token_expires_in=3600,
    enable_auto_settlement=EVM_PRIVATE_KEY is not None,
)


@server_tools.hook(TokenIssuedEvent)
async def on_token_issued(event, deps):
    """Log when a Bearer token is issued."""
    print(f"[hook] token issued: {event.token_response}")


@server_tools.hook(SettleSuccessEvent)
async def on_settle_success(event, deps):
    """Log when an on-chain settlement succeeds."""
    print(f"[hook] settlement succeeded: {event.settlement_result}")


@server_tools.hook(SettleFailedEvent)
async def on_settle_failed(event, deps):
    """Log when an on-chain settlement fails."""
    print(f"[hook] settlement failed: {event.error_message}")


if __name__ == "__main__":
    mcp.run()  # stdio transport -- MCP clients connect via stdin/stdout
    # TODO client and server should be separate with x402-mock, the client role should be the one who use the tools, the server role should be the one who provide the tools, except with in 402 role