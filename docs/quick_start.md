# Quick Start

x402-mock is an implementation of a payment protocol based on HTTP 402 status code, supporting token payments on EVM blockchains. This guide will help you get started quickly.

## Installation

This project uses `uv` as the package manager.

```bash
uv add x402-mock
uv sync
```

### Environment Configuration

Create a `.env` file in the project root directory to configure your private key and RPC service keys:

```env
# Required: EVM private key (for signing and receiving payments)
EVM_PRIVATE_KEY=your_private_key_here

# Optional: API keys for Infura or Alchemy (for accessing blockchain networks)
EVM_INFURA_KEY=your_infura_key_here
EVM_ALCHEMY_KEY=your_alchemy_key_here
```

## Core Concepts

### Payment Flow Overview

x402-mock implements a payment flow with separation of responsibilities, similar to a cinema's ticketing system:

1. **Server (Payment Receiver)**: Provides services and accepts payments, similar to a cinema
2. **Client (Payment Payer)**: Requests services and completes payments, similar to an audience member
3. **Payment Process**:
   - Client requests a protected resource
   - Server verifies the Client's access token (similar to ticket checking)
   - If the token is invalid, returns 402 status code + payment information (similar to directing to ticket office)
   - Client completes signed payment based on payment information (similar to buying a ticket)
   - Client obtains access token and retries the resource request (similar to entering with ticket)

### Separation of Responsibilities with Status Code 402

The HTTP 402 "Payment Required" status code implements separation of responsibilities in this project:
- **Server side**: Only responsible for verifying the validity of access tokens, not handling payment logic
- **Payment verification**: Handled by an independent `/token` endpoint, receiving payment signatures and issuing access tokens
- **Client side**: Automatically handles 402 responses, completes payment flow and retries requests

This design decouples payment logic from business logic, improving system maintainability and security.

## Server (Payment Receiver)

Server is the party that provides services and accepts payments. Main responsibilities include:
1. Defining accepted payment methods (chain, network, token)
2. Verifying the authenticity and validity of payment signatures
3. Completing on-chain transfer settlement
4. Issuing access tokens

### Creating a Server Instance

```python
from x402_mock.servers import Http402Server, create_private_key
from x402_mock.adapters.evm.schemas import EVMPaymentComponent

# Generate access token signing key
token_key = create_private_key()

# Create Server instance (inherits from FastAPI)
app = Http402Server(
    token_key=token_key,      # Access token signing key
    token_expires_in=300      # Token validity period (seconds)
)
```

#### Http402Server Parameter Description

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `token_key` | str | Yes | Access token signing key, can be generated using `create_private_key()` |
| `token_expires_in` | int | No | Access token validity period (seconds), default 3600 |
| `enable_auto_settlement` | bool | No | Whether to automatically settle payments, default True |
| `token_endpoint` | str | No | Token exchange endpoint path, default "/token" |

### Adding Payment Methods

```python
# Add EVM payment method
app.add_payment_method(
    EVMPaymentComponent(
        amount=0.5,          # Payment amount (human-readable units)
        currency="USDC",     # Token symbol
        caip2="eip155:11155111",  # CAIP-2 chain identifier
        token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"  # Token contract address
    )
)
```

#### EVMPaymentComponent Parameter Description

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `amount` | float | Yes | Payment amount (human-readable units, e.g., 0.5 USDC) |
| `currency` | str | Yes | Token symbol (e.g., "USDC", "USDT", "ETH") |
| `caip2` | str | Yes | CAIP-2 chain identifier (format: `eip155:<chain_id>`) |
| `token` | str | Recommended | Token contract address (0x prefix, 42 characters) |
| `pay_to` | str | No | Payment receiving address, defaults to address corresponding to environment variable private key |
| `rpc_url` | str | No | RPC node URL, defaults to public nodes or automatically configured based on environment variables |
| `token_name` | str | No | Token name, can be omitted if automatically retrieved |
| `token_decimals` | int/str | No | Token decimals, can be omitted if automatically retrieved |
| `token_version` | int/str | No | Token version, can be omitted if automatically retrieved |

**Note**: If `token`, `token_name`, `token_decimals`, `token_version` are not provided, the system will automatically query them based on `caip2` and `currency`.

### Protecting API Endpoints

Use the `@app.payment_required` decorator to protect endpoints that require payment:

```python
@app.get("/api/protected-data")
@app.payment_required
async def get_protected_data(payload):
    """Endpoint that requires payment to access"""
    return {
        "message": "Payment verified successfully",
        "user_address": payload["address"]
    }
```

### Event Handling

Server provides an event system where you can listen to various events during the payment process:

```python
from x402_mock.engine.events import SettleSuccessEvent

@app.hook(SettleSuccessEvent)
async def on_settle_success(event, deps):
    """Processing logic when payment succeeds"""
    print(f"✅ Payment succeeded: {event.settlement_result}")
    # You can log, send notifications, etc. here
```

Available event types:
- `RequestInitEvent`: Request initialization
- `RequestTokenEvent`: Token request
- `TokenIssuedEvent`: Token issued
- `VerifyFailedEvent`: Verification failed
- `AuthorizationSuccessEvent`: Authorization succeeded
- `Http402PaymentEvent`: Payment required
- `SettleSuccessEvent`: Settlement succeeded

## Client (Payment Payer)

Client is the party that requests services and completes payments. Main responsibilities include:
1. Registering supported payment methods
2. Automatically handling 402 responses
3. Generating payment signatures
4. Exchanging signatures for access tokens

### Creating a Client Instance

```python
from x402_mock.clients.http_client import Http402Client
from x402_mock.adapters.evm.schemas import EVMPaymentComponent

async with Http402Client() as client:
    # Register payment method
    client.add_payment_method(
        EVMPaymentComponent(
            caip2="eip155:11155111",
            amount=0.8,          # Maximum payment amount limit
            currency="USDC",
            token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
        )
    )
    
    # Send request (automatically handles 402 payment flow)
    response = await client.get("http://localhost:8000/api/protected-data")
    print(response.json())
```

#### Special Notes on Client-side EVMPaymentComponent

On the Client side, the `amount` parameter represents the **maximum payment amount limit**. If the Server requests an amount exceeding this limit, the Client will refuse to sign the payment.

### Payment Flow Automation

`Http402Client` inherits from `httpx.AsyncClient` and is fully compatible with all its methods. When receiving a 402 response, the Client automatically:

1. Parses payment requirements
2. Matches registered payment methods
3. Generates payment signature
4. Exchanges for access token at `/token` endpoint
5. Retries original request with new token

The entire process is transparent to developers; you just need to use the HTTP client normally.

## Complete Examples

### Complete Server-side Example

```python
from x402_mock.servers import Http402Server, create_private_key
from x402_mock.adapters.evm.schemas import EVMPaymentComponent
from x402_mock.engine.events import SettleSuccessEvent

# Create Server
token_key = create_private_key()
app = Http402Server(token_key=token_key, token_expires_in=300)

# Add payment method
app.add_payment_method(
    EVMPaymentComponent(
        amount=0.5,
        currency="USDC",
        caip2="eip155:11155111",
        token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
    )
)

# Payment success event handling
@app.hook(SettleSuccessEvent)
async def log_payment_success(event, deps):
    print(f"💰 Payment received: {event.settlement_result.authorized_amount} USDC")

# Protected API endpoint
@app.get("/api/premium-content")
@app.payment_required
async def get_premium_content(payload):
    return {
        "content": "This is premium content",
        "paid_by": payload["address"],
        "timestamp": payload.get("timestamp")
    }

# Run Server (using uvicorn)
# uvicorn server:app --host 0.0.0.0 --port 8000
```

### Complete Client-side Example

```python
import asyncio
from x402_mock.clients.http_client import Http402Client
from x402_mock.adapters.evm.schemas import EVMPaymentComponent

async def main():
    async with Http402Client() as client:
        # Register payment method (supports multiple)
        client.add_payment_method(
            EVMPaymentComponent(
                caip2="eip155:11155111",
                amount=1.0,      # Pay up to 1.0 USDC
                currency="USDC",
                token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
            )
        )
        
        # Request protected content (automatically handles payment)
        response = await client.get("http://localhost:8000/api/premium-content")
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Content obtained: {data['content']}")
            print(f"   Payer: {data['paid_by']}")
        else:
            print(f"❌ Request failed: {response.status_code}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Advanced Configuration

### Custom RPC Nodes

```python
# Server-side specify RPC node
app.add_payment_method(
    EVMPaymentComponent(
        amount=0.5,
        currency="USDC",
        caip2="eip155:1",  # Ethereum mainnet
        token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
        rpc_url="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
    )
)
```

### Multi-Chain Support

```python
# Support payment methods for multiple chains
app.add_payment_method(
    EVMPaymentComponent(
        amount=0.1,
        currency="ETH",
        caip2="eip155:1",  # Ethereum mainnet
        token=None  # Use native token
    )
)

app.add_payment_method(
    EVMPaymentComponent(
        amount=1.0,
        currency="USDC",
        caip2="eip155:42161",  # Arbitrum
        token="0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8"
    )
)
```

## Core Component AdapterHub

AdapterHub is a unified blockchain adapter gateway that enables users to verify signatures and complete transfers without relying on external facilitators. It supports EVM blockchains (SVM in development).

### Core Methods

| Method | Function |
|--------|----------|
| `register_payment_methods()` | Register payment methods (`client_role=False` for Server, `True` for Client) |
| `signature()` | Generate payment signature (called by Client) |
| `verify_signature()` | Verify signature (called by Server) |
| `settle()` | Execute on-chain transfer (called by Server) |
| `initialize()` | Client initialization (e.g., Permit2 approval) |

### Code Example

```python
from x402_mock.adapters import AdapterHub
from x402_mock.adapters.evm.schemas import EVMPaymentComponent

# 1. Initialize (requires EVM private key)
hub = AdapterHub(
    evm_private_key="0xyour_private_key",  # or use environment variable EVM_PRIVATE_KEY
    request_timeout=60
)

# 2. Register payment method
hub.register_payment_methods(
    EVMPaymentComponent(
        amount=1.0,
        currency="USDC",
        caip2="eip155:11155111",
        token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
    ),
    client_role=True  # Set to True for Client role
)

# 3. Client generates signature
permit = await hub.signature(remote_components)

# 4. Server verifies signature
result = await hub.verify_signature(permit)
if result.is_valid():
    # 5. Server executes transfer
    confirmation = await hub.settle(permit)
```

### Future Roadmap

- **bundle_settle**: Batch transfers to reduce Gas fees
- **SVM Support**: Solana adapter (in development)

## On-chain Information Retrieval Tools

When configuring payment methods, you may need to obtain various on-chain information such as RPC node addresses, token contract addresses, token decimals, and versions. x402-mock provides a series of utility methods to simplify retrieving this information.

### Import Utility Methods

```python
from x402_mock.adapters.evm.constants import (
    EvmChainInfoFromEthereumLists,
    EvmPublicRpcFromChainList,
    EvmTokenListFromUniswap,
    fetch_erc20_name_version_decimals,
    get_rpc_key_from_env
)
```

### Method Description

#### 1. `EvmChainInfoFromEthereumLists`
**Function**: Retrieve detailed EVM chain configuration information from the ethereum-lists repository.

**Main uses**:
- Get chain's Infura/Alchemy RPC URLs (with API key placeholders)
- Get public RPC node lists
- Get basic chain information (name, explorer addresses, etc.)

**Example usage**:
```python
chain_info = EvmChainInfoFromEthereumLists()

# Get Infura RPC URL (needs API key filled)
infura_url = chain_info.get_infura_rpc_url("eip155:1")
# Returns something like: https://mainnet.infura.io/v3/{RPC_KEYS}

# Get Alchemy RPC URL (needs API key filled)
alchemy_url = chain_info.get_alchemy_rpc_url("eip155:1")
# Returns something like: https://eth-mainnet.g.alchemy.com/v2/{RPC_KEYS}

# Get public RPC node list
public_rpcs = chain_info.get_public_rpc_urls("eip155:1")
# Returns: ["https://api.mycryptoapi.com/eth", ...]
```

#### 2. `EvmPublicRpcFromChainList`
**Function**: Retrieve public RPC node information from Chainlist.org.

**Main uses**:
- Get public RPC nodes with no tracking or limited tracking
- Select RPC nodes based on privacy preferences
- Support HTTPS and WebSocket protocols

**Example usage**:
```python
rpc_finder = EvmPublicRpcFromChainList()

# Get public RPC node with no tracking
public_rpc = rpc_finder.pick_public_rpc(
    caip2="eip155:1",
    start_with="https://",
    tracking_type="none"
)
# Returns something like: https://rpc.ankr.com/eth

# Get all public RPC information for a specific chain
chain_rpcs = rpc_finder.get_specific_chain_public_rpcs("eip155:1")
```

#### 3. `EvmTokenListFromUniswap`
**Function**: Retrieve token information from Uniswap's official token list.

**Main uses**:
- Get token contract addresses and decimals
- Support multi-chain token queries
- Automatic data caching to reduce network requests

**Example usage**:
```python
token_finder = EvmTokenListFromUniswap()

# Get token address and decimals
address, decimals = token_finder.get_token_address_and_decimals(
    caip2="eip155:1",
    symbol="USDC"
)
# Returns: ("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 6)
```

#### 4. `fetch_erc20_name_version_decimals`
**Function**: Query token details directly from chain RPC.

**Main uses**:
- Query token's `name()`, `version()` and `decimals()` functions
- Verify complete token contract information
- Get latest on-chain data

**Example usage**:
```python
# Query token information from chain
name, version, decimals = fetch_erc20_name_version_decimals(
    rpc_url="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY",
    token_address="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
)
# Returns: ("USD Coin", "2", 6)
```

#### 5. `get_rpc_key_from_env`
**Function**: Get RPC service provider API keys from environment variables.

**Main uses**:
- Securely get Infura or Alchemy API keys
- Support custom environment variable names
- Returns `None` to indicate using public nodes

**Example usage**:
```python
# Get Infura key (default)
infura_key = get_rpc_key_from_env("EVM_INFURA_KEY")

# Get Alchemy key
alchemy_key = get_rpc_key_from_env("EVM_ALCHEMY_KEY")

# Build RPC URL using key
if infura_key:
    rpc_url = f"https://mainnet.infura.io/v3/{infura_key}"
else:
    # Use public node
    rpc_finder = EvmPublicRpcFromChainList()
    rpc_url = rpc_finder.pick_public_rpc("eip155:1")
```

### Auto-filling Payment Components

These utility methods are typically used internally by `EVMPaymentComponent` to automatically fill in missing information:

```python
# Only provide basic information, system automatically queries missing data
payment = EVMPaymentComponent(
    amount=0.5,
    currency="USDC",
    caip2="eip155:1"
    # token, token_name, token_decimals, token_version are automatically queried
)

# System internally will:
# 1. Use EvmTokenListFromUniswap to get USDC contract address and decimals
# 2. Use fetch_erc20_name_version_decimals to get token name and version
# 3. Use EvmPublicRpcFromChainList to get public RPC node
# 4. Use get_rpc_key_from_env to check if there are private RPC keys
```

### Best Practices

1. **Production environment**: Recommend providing complete `token`, `rpc_url`, etc. information to reduce network queries
2. **Development environment**: Can rely on automatic queries to simplify configuration
3. **Performance considerations**: Initial queries make network requests, subsequent uses cache
4. **Error handling**: When network is unavailable, automatically falls back to built-in default configurations

## Troubleshooting

### Common Issues

1. **Payment fails after 402 response**
   - Check if private key configuration is correct
   - Confirm sufficient token balance
   - Verify chain ID and token address match

2. **Token verification fails**
   - Check if `token_key` is consistent
   - Confirm token hasn't expired
   - Verify signature algorithm

3. **RPC connection issues**
   - Check network connection
   - Confirm RPC URL is valid
   - Consider using backup nodes

### Debug Mode

x402-mock uses [loguru](https://github.com/Delgan/loguru) as its logging library. By default, no logs are output (to avoid interfering with your application's own logs). Enable logging via `setup_logger`:

```python
from x402_mock.utils import setup_logger

# Output to console only (DEBUG level)
setup_logger(level="DEBUG")

# Also save to file (optional)
setup_logger(level="DEBUG", log_to_file=True, log_path="logs/x402-mock.log")
```

#### `setup_logger` Parameter Description

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `level` | str | `"INFO"` | Log level: `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"` |
| `log_to_file` | bool | `False` | Whether to also save logs to a local file |
| `log_path` | str | `"logs/x402-mock.log"` | Log file path; directory is created automatically if it doesn't exist |

> **Note**: Log files are automatically rotated at 10 MB and retained for 7 days.

## MCP Tool Integration (for AI Agents / LLM Calls)

x402-mock provides native [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) tool support, allowing LLM Agents (such as GitHub Copilot, Claude, GPT, etc.) to call directly and automatically complete the full 402 payment flow — no manual payment code required.

### Install MCP Dependencies

MCP support is provided as an optional extra. Install it with:

```bash
uv sync --extra mcp
```

### Available MCP Tools

| Tool | Role | Description |
|------|------|-------------|
| `source_request` | Client | Access a 402-protected resource with automatic signing and payment retry |
| `signature` | Client | Generate a signed permit from the payment component list returned by the server |
| `verify_and_settle` | Server | Verify a permit signature and settle on-chain in one step |

### Server-side MCP Example

```python
# example/mcp_server_example.py
import os
from mcp.server.fastmcp import FastMCP
from x402_mock.adapters.adapters_hub import AdapterHub
from x402_mock.adapters.evm.schemas import EVMPaymentComponent
from x402_mock.mcp.facilitor_tools import FacilitorTools

TOKEN_KEY = os.environ.get("X402_TOKEN_KEY", "dev-secret-change-me")
EVM_PRIVATE_KEY = os.environ.get("EVM_PRIVATE_KEY")

hub = AdapterHub(evm_private_key=EVM_PRIVATE_KEY)
hub.register_payment_methods(
    EVMPaymentComponent(
        amount=0.8,
        currency="USDC",
        caip2="eip155:11155111",
        token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    ),
    client_role=False,  # server role
)

mcp = FastMCP("x402")
FacilitorTools(adapter_hub=hub, mcp=mcp, client_role=False)
mcp.run()  # stdio transport
```

### Client-side MCP Example

```python
# example/mcp_client_example.py
import os
from mcp.server.fastmcp import FastMCP
from x402_mock.adapters.adapters_hub import AdapterHub
from x402_mock.adapters.evm.schemas import EVMPaymentComponent
from x402_mock.mcp.facilitor_tools import FacilitorTools

EVM_PRIVATE_KEY = os.environ.get("EVM_PRIVATE_KEY")

hub = AdapterHub(evm_private_key=EVM_PRIVATE_KEY)

if EVM_PRIVATE_KEY:
    hub.register_payment_methods(
        EVMPaymentComponent(
            amount=0.5,
            currency="USDC",
            caip2="eip155:11155111",
            token="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
        ),
        client_role=True,  # client role
    )

mcp = FastMCP("x402-client")
FacilitorTools(adapter_hub=hub, mcp=mcp, client_role=True)
mcp.run()  # stdio transport
```

### Configuration in VS Code (GitHub Copilot)

Add the following to your project's `.vscode/mcp.json` (or the user-level MCP config file) to allow Copilot Agent to call x402-mock payment tools directly:

```json
{
  "servers": {
    "X402-Mock-Server": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "example/mcp_server_example.py"],
      "env": {
        "X402_TOKEN_KEY": "dev-secret-change-me",
        "EVM_PRIVATE_KEY": "your_private_key_here",
        "EVM_INFURA_KEY": "your_infura_key_here"
      }
    },
    "X402-Mock-Client": {
      "type": "stdio",
      "command": "uv",
      "args": ["run", "example/mcp_client_example.py"],
      "env": {
        "EVM_PRIVATE_KEY": "your_private_key_here",
        "EVM_INFURA_KEY": "your_infura_key_here"
      }
    }
  }
}
```

Once configured, open Copilot Chat in VS Code (Agent mode) and issue natural language instructions directly, for example:

> Please use the `source_request` tool to access `http://localhost:8000/api/protected-data`

Copilot will automatically call the `source_request` tool, complete the signing, payment, and retry flow, and return the result.

### `source_request` Tool Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | str | required | Target resource URL |
| `method` | str | `"GET"` | HTTP method |
| `headers` | dict | `None` | Additional request headers |
| `timeout` | float | `30.0` | Request timeout in seconds |

Returns a dict containing `status_code`, `headers`, and `body`.

## Next Steps

- View [API Reference Documentation](./reference.md) for detailed interface specifications
- Explore [Example Code](../example/)
- Understand [Event System](./reference.md#Engine) to implement custom business logic

---

**Tips**: In production environments, please ensure:
1. Use secure key management solutions
2. Configure appropriate timeout and retry strategies
3. Monitor payment success rate and failure reasons
4. Regularly update dependencies to get security fixes