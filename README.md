# x402_mock

`x402_mock` is a **production-grade module** that fully implements the **HTTP 402 status code payment workflow**.

## Module Features

This module completes the full payment workflow based on the **HTTP 402 Payment Required** status code, seamlessly integrating Web2 HTTP protocol with Web3 on-chain payments.

Based on **Web3 + USDC (ERC20)**, this module fully implements the following chain:

> **Client (Requester) → Server (Recipient) → On-chain Settlement**

Core Features:
- ✅ Standardized payment protocol based on HTTP 402 status code
- ✅ EIP-2612 Permit signature, no pre-approval required (gas-less approval)
- ✅ Asynchronous on-chain settlement without blocking business flow
- ✅ Support for multiple payment method negotiation and matching
- 🤖 Designed for **Agent-to-Agent** automated payment scenarios

---

## Design Objectives

- 🧪 **Workflow-first**: Focus on x402's interaction and semantics rather than engineering completeness  
- 🧠 **Understandability**: Minimize hidden logic for easier learning and review  
- 🤖 **Agent-ready**: Prepare for future agents to automatically initiate/accept/execute payments  
- 🔌 **Extensibility**: Naturally evolve to support multi-chain, multi-asset, and multi-payment channels  

---

## Complete Interaction Workflow

### 1. Initial Request (Unauthorized)

**Client** sends a GET request to **Server**'s paid endpoint with an empty or incorrect `Authorization` header.

**Server** detects unauthorized access, returns `402 Payment Required` status code, and includes in the response payload:
- `access_token_endpoint`: Endpoint address for obtaining access token
- `payment_methods`: List of supported payment methods (e.g., EVM/USDC, SVM/USDC, etc.)

### 2. Payment Method Matching and Signing

**Client** receives the 402 response and:
1. **Matches** its supported payment methods with Server's offered payment methods
2. Selects a matching payment method (e.g., EVM + USDC)
3. Uses wallet private key to **sign** payment information, generating signature data compliant with **EIP-2612 Permit** standard

### 3. Submit Permit to Obtain Access Token

**Client** places the generated Permit data in the request body and sends a POST request to `access_token_endpoint`.

**Server** receives the Permit and performs the following validations:
- ✅ **owner** (payer address) matches the Permit signer
- ✅ **spender** (recipient address) matches Server's specified address
- ✅ **deadline** (expiration time) is still valid
- ✅ **signature** is legitimate
- ✅ **balance** is sufficient

After validation passes:
- Immediately returns `access_token` to Client
- Simultaneously triggers **asynchronous on-chain settlement** (asynchronous processing to avoid blocking due to slow blockchain transactions)

### 4. Use Access Token to Obtain Resources

**Client** receives the `access_token` and:
- Places `access_token` in `Authorization` header
- Re-requests the paid endpoint with GET
- **Server** validates token validity and returns requested resources, completing the interaction

### 5. Asynchronous On-chain Settlement

**Server** uses Permit in the background to call smart contract's `permit()` and `transferFrom()` functions, completing on-chain fund transfer. Settlement results can be queried on blockchain explorer via transaction hash (tx_hash).

---

## Workflow Diagram

> 📌 See the diagram below for complete interaction workflow  
> [Diagram](../../../assets/work_flow.png)

---

## Environment Configuration

### Dependency Installation

This project uses `uv` as the package management tool. Execute in the project root directory:

```bash
uv add x402-mock
uv sync
```

### Environment Variable Configuration

Create a `.env` file in the project **root directory**, or configure the following environment variables:

#### Required Configuration

- **`EVM_PRIVATE_KEY`** (Required)  
  Wallet private key for signing and on-chain transactions. **Please keep it safe and do not leak!**

#### Optional Configuration

- **`EVM_INFURA_KEY`** (Optional)  
  Infura API Key. If not provided, public nodes will be used (speed and stability may be poor).

> 💡 More parameters will be added in the future, such as `SVM_PRIVATE_KEY`.

Example `.env` file:

```env
EVM_PRIVATE_KEY=your_private_key_here
EVM_INFURA_KEY=your_infura_key_here  # Optional
```

### Network Selection Recommendations

**Before using in production environment, strongly recommend thorough testing on testnet first:**

- **Recommended Testnets**: Sepolia (Ethereum), Mumbai (Polygon), etc.
- **Test Assets**: Free test ETH and test USDC available from official Faucets of each chain
- **Verification Process**: Confirm complete payment workflow, on-chain settlement, exception handling, and other functions work properly

After testing passes, switch to mainnet for production deployment.

---

## Usage Examples

### Server-side Minimal Code Example

```python
# Server minimal example code
from x402_mock.servers import Http402Server, create_private_key

token_key = create_private_key() # Server signing private key for issuing and verifying access_token (not blockchain wallet private key, can be provided by configuration)

app = Http402Server(
  token_key=token_key,
  token_expires_in=300 # access_token expiration in seconds
)
app.add_payment_method(
    chain_id="eip155:11155111",
    amount=0.5,
    currency="USDC",
) # Accepted payment methods

@app.get("/api/protected-data") # Usage inherits from fastapi
@app.payment_required # Any endpoint with this decorator requires payment
async def get_protected_data(authorization):
    """This endpoint requires payment to access."""
    # Endpoint logic can be written here
    return {
        "message": "Payment verified successfully",
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000)

```

### Client-side Minimal Code Example

```python
from x402_mock.clients.http_client import Http402Client
from x402_mock.adapters.adapters_hub import AdapterHub

async with Http402Client() as client: # Usage inherits from httpx
  clinet.add_payment_method(
            chain_id="eip155:11155111",
            amount=0.8, # Limit payment amount
            currency="USDC"
        ) # Add payment method, earlier configured methods have priority in matching
  response = client.get("http://localhost:8000/api/protected-data") # Request resource endpoint

```
* Code Examples:
[Examples](./example/)


---

## Current Status

* ✅ Complete HTTP 402 payment workflow
* ✅ Client → Server request and response
* ✅ Payment method negotiation and matching
* ✅ EIP-2612 Permit signature and verification
* ✅ On-chain USDC transfer with queryable tx_hash
* ✅ Asynchronous on-chain settlement without blocking business
* 🚀 Production-grade implementation

---

## Roadmap

* [ ] Support for most EVM chains (Ethereum, Polygon, Arbitrum, Optimism, etc.)
* [ ] Support for EIP-6492 (signature verification for undeployed contracts)
* [ ] Support for SVM (Solana Virtual Machine) and Solana ecosystem

---

## Disclaimer and Recommendations

This module has reached production-ready level, but before deploying to production environment, please note:

⚠️ **Strongly recommend thorough testing on testnet (e.g., Sepolia) first**  
✅ Confirm complete payment workflow, exception handling, on-chain settlement, and other functions meet expectations  
🔒 For real asset usage, please ensure security audits and risk controls are completed  
💰 Recommend setting reasonable per-transaction limits and risk control mechanisms

---

For research on:

* x402 protocol
* Agent economic systems
* Automated on-chain payments

Welcome to collaborate and contribute.