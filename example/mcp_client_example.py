import os

from mcp.server.fastmcp import FastMCP

from x402_mock.adapters.adapters_hub import AdapterHub
from x402_mock.adapters.evm.schemas import EVMPaymentComponent
from x402_mock.mcp.facilitor_tools import FacilitorTools

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

FacilitorTools(
    adapter_hub=hub,
    mcp=mcp,
    client_role=True
)

if __name__ == "__main__":
    mcp.run()  # stdio transport -- MCP clients connect via stdin/stdout
