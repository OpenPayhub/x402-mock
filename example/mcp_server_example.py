
import os

from mcp.server.fastmcp import FastMCP

from x402_mock.adapters.adapters_hub import AdapterHub
from x402_mock.adapters.evm.schemas import EVMPaymentComponent

from x402_mock.mcp.facilitor_tools import FacilitorTools


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
        amount=0.8,
        currency="USDC",
        caip2="eip155:11155111",
        token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    ),
    client_role=False,
)

mcp = FastMCP("x402")

tools = FacilitorTools(adapter_hub=hub, mcp=mcp, client_role=False)

mcp.run()