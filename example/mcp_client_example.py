"""
X402 MCP Client Example
=======================

Starts an MCP server that exposes the X402 *payment-client* role as tools
an AI agent can call over the Model Context Protocol (stdio transport).

The client is the *paying* party: it handles 402 responses automatically by
signing a payment permit with the registered EVM key and exchanging it for a
Bearer token before retrying the original request.

Tools exposed to the AI agent
------------------------------
- ``add_payment_method`` -- register a payment capability (chain, token, amount,
                            signing key) so the client can fulfil 402 responses.
- ``make_request``       -- make an HTTP request; 402 responses are handled
                            transparently without further agent intervention.
- adapter / EVM helper tools.

Usage
-----
1. Set the optional env var:

    $env:EVM_PRIVATE_KEY = "0x..."   # wallet key used to sign payment permits

2. Run this file:

    python example/mcp_client_example.py

   Configure your AI client to launch this script as an MCP server:

    {
        "mcpServers": {
            "x402-client": {
                "command": "python",
                "args": ["example/mcp_client_example.py"],
                "env": {
                    "EVM_PRIVATE_KEY": "0x..."
                }
            }
        }
    }

3. The agent can then call tools in order:

    # Step 1 -- once, at setup time
    add_payment_method(payment_component={
        "payment_type": "evm",
        "caip2": "eip155:11155111",
        "currency": "USDC",
        "token": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
        "amount": 0.5
    })

    # Step 2 -- for every protected request
    make_request(method="GET", url="https://api.example.com/data")
"""

import os

from mcp.server.fastmcp import FastMCP

from x402_mock.adapters.adapters_hub import AdapterHub
from x402_mock.adapters.evm.schemas import EVMPaymentComponent
from x402_mock.mcp.tools.raw_tools import AdapterHubTools, EvmTools
from x402_mock.mcp.tools.workflow_tools import ClientWorkflowTools

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
EVM_PRIVATE_KEY = os.environ.get("EVM_PRIVATE_KEY")  # optional

# ---------------------------------------------------------------------------
# Build the shared AdapterHub.
# Pre-register a payment method here if the private key is available;
# otherwise the agent must call add_payment_method() before make_request().
# ---------------------------------------------------------------------------
hub = AdapterHub(evm_private_key=EVM_PRIVATE_KEY)

if EVM_PRIVATE_KEY:
    hub.register_payment_methods(
        EVMPaymentComponent(
            amount=0.5,
            currency="USDC",
            caip2="eip155:11155111",
            token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
        ),
        client_role=True,
    )

# ---------------------------------------------------------------------------
# Build the MCP server and register client-side tools
# ---------------------------------------------------------------------------
mcp = FastMCP("x402-client")

EvmTools(mcp=mcp)
AdapterHubTools(mcp=mcp, hub=hub)
ClientWorkflowTools(mcp=mcp, adapter_hub=hub)


if __name__ == "__main__":
    mcp.run()  # stdio transport -- MCP clients connect via stdin/stdout
