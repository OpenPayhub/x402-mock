# x402-mock

<p align="center">
  <a href="README.cn.md">
    <img src="https://img.shields.io/badge/中文版本-blue?style=flat-square&logo=github" alt="中文版本" />
  </a>
</p>

> 📚 Protocol primer: [What is EIP / ERC?](./docs/what-is-eip-erc.cn.md) ([English version placeholder](./docs/what-is-eip-erc.en.md))

`x402-mock` is a production-grade module that fully implements the HTTP 402 Payment Required workflow.

## Module Features

This module completes the full payment workflow based on the HTTP 402 Payment Required status code, bridging Web2 HTTP with Web3 on-chain payments.

Targeting Web3 + ERC20 (USDC optimized), the implementation covers the full chain:

> Client (requester) → Server (recipient) → On-chain Settlement

Core features:
- ✅ Standardized payment protocol based on HTTP 402
- ✅ USDC optimization: upgraded from EIP-2612 to ERC-3009 (`transferWithAuthorization`), combining authorization and transfer in one step to save gas
- ✅ Generic ERC20 support: Permit2 (`permitTransferFrom`) enabling offline-signed payments for many ERC20 tokens
- ✅ Asynchronous on-chain settlement to avoid blocking business flows
- ✅ Support for negotiating and matching multiple payment methods
- 🤖 Designed for Agent-to-Agent automated payment scenarios

---

## Important Notes (differences vs. Coinbase-style implementations)

- This implementation does not use a facilitator/relayer; on-chain settlement transactions are broadcast by the operator, therefore the operator pays gas and must provide a usable RPC/Infra key (Infura/Alchemy, etc.).
- Whitelist mode supported: callers may include a custom `authorization key` that the server verifies before allowing access to paid APIs (this check can be performed before entering the 402/payment flow).

---

## Design Goals

- 🧪 Workflow-first: emphasize x402 interaction and semantics rather than engineering completeness
- 🧠 Understandability: minimize hidden logic for easy reading and learning
- 🤖 Agent-oriented: prepare for future agents to automatically initiate/accept/execute payments
- 🔌 Extensibility: designed to evolve into multi-chain, multi-asset, multi-payment-channel support

---

## Complete Interaction Flow

### 1. Initial Request (unauthorized)

Client sends a GET request to a paid server endpoint with an empty or incorrect `Authorization` header.

Server detects unauthorized access, returns `402 Payment Required`, and includes in the response payload:
- `access_token_endpoint`: endpoint to obtain an access token
- `payment_methods`: list of supported payment methods (e.g., EVM/USDC, SVM/USDC)

### 2. Payment Method Matching and Signing

Upon receiving the 402 response, the client:
1. Matches its supported payment methods with the server-provided list
2. Selects a compatible method (e.g., EVM + USDC)
3. Uses the wallet private key to produce an offline signature credential for the chosen currency:
   - USDC: produce an ERC-3009 Authorization for `transferWithAuthorization`
   - Other ERC20: produce a Permit2 signature for `permitTransferFrom`

### 3. Submit Offline Signature to Obtain Access Token

Client includes the generated authorization/permit in the POST body to `access_token_endpoint`.

Server validates the submitted credential (fields differ slightly between ERC-3009 and Permit2), including:
- ✅ `sender`/`owner` (payer address) matches the signature signer
- ✅ `receiver`/`spender` equals the server-designated recipient address
- ✅ validity window (e.g., `valid_before` / `deadline`) is still valid
- ✅ `nonce` has not been used (replay protection)
- ✅ `signature` is cryptographically valid
- ✅ balance / authorized amount is sufficient

If validation passes:
- Immediately return an `access_token` to the client
- Trigger asynchronous on-chain settlement (transaction submission happens in background to avoid blocking)

### 4. Use Access Token to Retrieve Resource

Client places the returned `access_token` into the `Authorization` header and retries the GET request to the paid endpoint.

Server verifies the token and returns the requested resource on success.

### 5. Asynchronous On-chain Settlement

Server performs the on-chain settlement in background:
- USDC: call `transferWithAuthorization` (ERC-3009) to move funds in a single step
- Other ERC20: use Permit2's `permitTransferFrom` to complete the transfer

Settlement results (tx hashes) can be inspected on chain explorers.

---

## Flow Diagram

See the full interaction diagram in the repository:
[assets/402workflow.png](assets/402workflow.png)

---

## Environment Configuration

### Dependency Installation

This project uses `uv` as the package manager. From the project root run:

```bash
uv add x402-mock
uv sync
```

Documentation: https://openpayhub.github.io/x402-mock/

### Environment Variables

Create a `.env` file in the project root or export the following variables:

Required:
- `EVM_PRIVATE_KEY` — wallet private key for signing and broadcasting transactions. Keep it secret.

Optional:
- `EVM_INFURA_KEY` — Infura or other RPC key. Without it public nodes may be used (slower / less reliable).

Example `.env`:

```env
EVM_PRIVATE_KEY=your_private_key_here
EVM_INFURA_KEY=your_infura_key_here  # optional
```

Recommended testnets: Sepolia (Ethereum), Mumbai (Polygon). Use faucets for test ETH and test USDC before switching to mainnet.

---

## Usage Examples

### Server minimal example

```python
# Server minimal example
from x402_mock.servers import Http402Server, create_private_key

token_key = create_private_key()  # server signing private key for issuing/verifying access tokens (not on-chain wallet key)

app = Http402Server(
  token_key=token_key,
  token_expires_in=300,  # access_token expiry in seconds
)

app.add_payment_method(
    chain_id="eip155:11155111",
    amount=0.5,
    currency="USDC",
)

@app.get("/api/protected-data")
@app.payment_required
async def get_protected_data(authorization):
    """This endpoint requires payment to access."""
    return {"message": "Payment verified successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)
```

### Client minimal example

```python
from x402_mock.clients.http_client import Http402Client
from x402_mock.adapters.adapters_hub import AdapterHub

wpk = "your eoa private key"
ah = AdapterHub(wpk)

async with Http402Client() as client:
  client.add_payment_method(
    chain_id="eip155:11155111",
    amount=0.8,
    currency="USDC",
  )
  await ah.initialize(client_role=True)  # initialize adapters for client role (pre-signing)
  response = client.get("http://localhost:8000/api/protected-data")
```

Examples: [example/](example/)

---

## Current Status

- ✅ Full HTTP 402 payment workflow
- ✅ Client → Server request and response
- ✅ Payment method negotiation and matching
- ✅ USDC: ERC-3009 offline signature & verification (gas-optimized)
- ✅ Generic ERC20: Permit2 offline signature & verification
- ✅ On-chain USDC transfer with tx_hash available
- ✅ Asynchronous on-chain settlement

---

## Roadmap

- [ ] Cover more EVM chains (Ethereum, Polygon, Arbitrum, Optimism, etc.)
- [ ] Support smart contract wallet recipients
- [ ] Support EIP-6492 (undeployed contract signature verification)
- [ ] Support SVM (Solana Virtual Machine) and Solana ecosystem

---

## Statement & Recommendations

This module is production-capable, but before running with real assets:

- ⚠️ Strongly test thoroughly on testnets (Sepolia, Mumbai)
- ✅ Verify full payment flow, on-chain settlement, and error handling
- 🔒 Conduct security audits and risk controls for real assets
- 💰 Set reasonable per-transaction limits and risk controls

---

If you are researching:

- x402 protocol
- Agent economic systems
- Automated on-chain payments

Welcome to collaborate and contribute.