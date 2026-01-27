# x402_mock

`x402_mock` is an **experimental module for demonstrating and verifying the x402 payment workflow**.

Based on **Web3 + USDC (ERC20)**, this module fully implements the following chain:

> **Client → Server → On-chain (Permit + Transfer)**

Current achievements:
- Client initiates payment request to server  
- Server verifies request and constructs on-chain transaction  
- Signature verification based on `permit`  
- Final USDC transfer on-chain  

The module's goal is **not production readiness**, but rather to make x402's payment semantics and interaction flows **clear, verifiable, and demonstrable**, laying the foundation for future **Agent-to-Agent automated payments**.

---

## Design Objectives

- 🧪 **Workflow-first**: Focus on x402's interaction and semantics rather than engineering completeness  
- 🧠 **Understandability**: Minimize hidden logic for easier learning and review  
- 🤖 **Agent-ready**: Prepare for future agents to automatically initiate/accept/execute payments  
- 🔌 **Extensibility**: Naturally evolve to support multi-chain, multi-asset, and multi-payment channels  

---

## Interaction Workflow

The complete interaction workflow is shown below:

```

Client
│
│  (x402 request)
▼
Server
│
│  (permit verification)
│
▼
On-chain (USDC)

```

> 📌 See the diagram below for visual reference  
> [Diagram](../../../assets/work_flow.png)

---

## Execution Guide (Demo)

### 1. Install Dependencies

This module uses `extra` for dependency management:

```bash
uv sync --extra x402
```

---

### 2. Network & Asset Preparation

**Strongly recommend using test networks** before launching the demo:

* Network: `Sepolia`
* Required assets:

  * Test USDC (ERC20)
  * Minimal Sepolia ETH (for gas fees)

Free test tokens can be obtained through official faucets.

---

### 3. Server Configuration

Configuration path:

```
x402_mock/servers/env.server
```

Required environment variables:

* `INFURA_KEY`
* `WALLET_ADDRESS`
* `PRIVATE_KEY`

Start server:

```bash
uv run -m src.terrazip.x402_mock.servers.server
```

The server will listen for payment requests from clients after startup.

---

### 4. Client Configuration

Configuration path:

```
x402_mock/clients/env.client
```

Same configuration required for the payer:

* `INFURA_KEY`
* `WALLET_ADDRESS`
* `PRIVATE_KEY`

After launching the client:
* Automatically initiates requests
* Completes interaction with server
* Triggers on-chain deduction

No manual operation required.

---

## Current Status

* ✅ Client → Server request flow
* ✅ Permit signature and verification
* ✅ On-chain USDC transfer with tx_hash
* 🧪 Demo-level implementation

---

## Roadmap

> Future directions (not committed timelines)

* [ ] Abstract unified payment interface
* [ ] Support more chains (EVM / Non-EVM)
* [ ] Support more assets (Native / ERC20 / Stablecoin)
* [ ] Production-ready mode (risk control, retries, state machine)
* [ ] Agent-oriented payment SDK / protocol encapsulation

---

## Disclaimer

This module is for **experimental/educational purposes** only. Not recommended for production use.  
For real asset usage, please complete security audits and risk controls independently.

---

For research on:

* x402 protocol
* Agent economic systems
* Automated on-chain payments

Welcome to collaborate and contribute.