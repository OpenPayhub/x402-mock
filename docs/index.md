# x402_mock

A **production-grade Python module** implementing the HTTP 402 Payment Required workflow.

## Overview

`x402_mock` seamlessly integrates **Web2 HTTP protocol** with **Web3 on-chain payments**, enabling automated payment workflows based on the HTTP 402 status code.

**Core Tech Stack:**
- Web3 + USDC (ERC20)
- EIP-2612 Permit signatures (gas-less approval)
- Asynchronous on-chain settlement

**Payment Flow:**
```
Client (Requester) → Server (Recipient) → On-chain Settlement
```

## Key Features

- ✅ Standardized payment protocol based on HTTP 402
- ✅ EIP-2612 Permit signature, no pre-approval required
- ✅ Asynchronous on-chain settlement without blocking business flow
- ✅ Multiple payment method negotiation and matching
- 🤖 Designed for **Agent-to-Agent** automated payment scenarios

## Installation

This project uses `uv` as the package management tool.

```bash
uv add x402-mock
uv sync
```

### Environment Configuration

Create a `.env` file in the project root:

```env
EVM_PRIVATE_KEY=your_private_key_here
EVM_INFURA_KEY=your_infura_key_here  # Optional
```

**Required:**
- `EVM_PRIVATE_KEY` - Wallet private key for signing and on-chain transactions

**Optional:**
- `EVM_INFURA_KEY` - Infura API Key (uses public nodes if not provided)

## Quick Start

### Server Example

```python
from x402_mock.servers import Http402Server, create_private_key

token_key = create_private_key()
app = Http402Server(token_key=token_key, token_expires_in=300)

app.add_payment_method(
    chain_id="eip155:11155111",
    amount=0.5,
    currency="USDC",
)

@app.get("/api/protected-data")
@app.payment_required
async def get_protected_data(authorization):
    return {"message": "Payment verified successfully"}
```

### Client Example

```python
from x402_mock.clients.http_client import Http402Client

async with Http402Client() as client:
    client.add_payment_method(
        chain_id="eip155:11155111",
        amount=0.8,
        currency="USDC"
    )
    response = client.get("http://localhost:8000/api/protected-data")
```

## Next Steps

- Check the [API Reference](reference.md) for detailed documentation
- See the [GitHub Repository](https://github.com/OpenPayhub/Terrazipay-python) for more examples
- **Source Code:** [`/src/terrazip/x402_mock/`](https://github.com/OpenPayhub/Terrazipay-python/tree/main/src/terrazip/x402_mock) in the main repository
- ⚠️ Test on testnet (e.g., Sepolia) before production use
