# EVM Protocol Overview

## About

Glad you opened this document. This is a personal account of my learning journey through payment protocols and blockchain standards, written for readers who are interested in x402, blockchain, token payments, or just getting started in the space.

> **Note**: All content reflects my personal understanding and is for reference only. If you find it helpful, a star on the project would be greatly appreciated. If anything is incorrect, feel free to point it out — thank you.

When I first started looking into Ethereum signatures and transfers, the docs were full of strings starting with "e": `erc20`, `eip712` — no big deal at first. But then more numbers kept appearing: `erc4337`, `erc8004`, `eip2612`, and some docs called it `erc2612`...

**WTF? What is this? What's that? Are they even different?** To figure this out, I had to go back to basics.

---

## Wallet Types

For now, only two wallet types are covered — these two account for all the logic in the current version of x402-mock.

### EOA Wallet (Traditional Wallet)

The most familiar wallet type is the traditional **EOA wallet**, like MetaMask or OKX Wallet. They come as mobile apps or browser extensions, and are fully controlled by your **Private Key**, with a **seed phrase** as a backup to prevent key loss. **Your private key is your wallet — it controls everything.**

In practice: if you try to send USDC to someone on the ETH mainnet, you'll need to pay a Gas fee. That fee must be paid in native ETH, so holding USDC alone isn't enough — you also need ETH to cover Gas.

### AA Wallet (Account Abstraction Wallet)

**Account Abstraction (AA) wallets** address several pain points of EOA wallets. At their core, they are **smart contract code**, offering features like recoverable keys, gas payment in tokens (someone else can pay Gas for you), and customizable logic.

They don't fundamentally change how the blockchain works — they add a layer of logic before transactions are bundled on-chain (via a Bundler). Think of it as a layer sitting beneath L2 but with a similar experience. Protocol reference: **ERC-4337**.

---

## Protocol Overview

### What are EIP and ERC?

**Ethereum Improvement Proposals (EIPs)** are the foundation of Ethereum's evolution — proposals for how the existing ecosystem should be improved. The process goes: **Propose → Review → Discuss & Revise → Reach Consensus**. `EIP + number` represents the sequence; lower numbers were proposed earlier.

**Ethereum Request for Comments (ERC)** is a subtype of EIP. When first proposed, it's an EIP; once categorized as an **"application-layer standard"**, it becomes an ERC. So `erc{int}` and `eip{int}` are essentially the same thing — the distinction isn't worth overthinking.

---

### ERC-20 — Token Standard

**ERC-20** is the most widely used asset protocol in Web3. Major stablecoins like USDT and USDC are digital currencies issued on Ethereum via smart contracts that strictly follow the ERC-20 standard. Every token on-chain has a unique contract address (Token Address) — like a token's **"ID number"** — ensuring that even similarly named assets are never confused.

---

### EIP-712 — Structured Data Signing Standard

**EIP-712** is a structured data signing standard on Ethereum. It transforms raw, unreadable hex data into a human-readable form, so users know exactly what they're authorizing when they sign. Think of it like a bank check: you fill in the transfer details in a fixed format and sign it with your private key.

Core logic: User A uses their private key to perform a mathematical operation on specific fields — recipient, amount, Nonce, chain ID — producing a digital signature made up of three components: `v`, `r`, `s`. A verifier (e.g., a smart contract) reverses the math using those components and the original data; if the recovered address matches A, the instruction is proven genuine and untampered.

Both ERC-3009 and Uniswap's Permit2 are essentially built on top of EIP-712, each defining different business fields within its framework.

---

### ERC-1271 — Smart Contract Signature Verification

EOA wallet signatures are backed by a private key. But smart contract wallets (like AA wallets) have no private key — so how do they prove **"this is my signature"**? **ERC-1271** was created exactly for this — a **"signature verifier"** that defines a standard interface:

```solidity
function isValidSignature(bytes32 hash, bytes memory signature) 
    external view returns (bytes4 magicValue);
```

Call `isValidSignature`, and if it's a valid contract, it returns a fixed **Magic Value** bytes value: `0x1626ba7e`.

---

### EIP-2612 — Token Permit Protocol

**EIP-2612** is a relatively complete standard covering token signing + signature verification + transfer execution. It has a built-in `permit` method that anyone can call to complete a transfer — including a third party on your behalf, so they can cover the Gas Fee for you (this is called a **Paymaster**).

Known limitations: the `nonce` (number of signatures used per address) must increment sequentially, requiring a nonce check each time, and it doesn't support legacy tokens like USDT.

---

### ERC-3009 — Circle/Coinbase Transfer Authorization Standard

**ERC-3009** is a signed transfer standard designed by Circle (issuer of USDC) and Coinbase, differing from EIP-2612 in key ways: `nonce` no longer needs to be sequential — each transfer is independent; signatures can be cancelled via `cancelAuthorization`; `transferWithAuthorization` completes the transfer in a single call (instead of the old `permit + transfer` pattern), and is theoretically cheaper on Gas.

> **x402-mock note**: If the signing token is USDC, prefer ERC-3009.

---

### ERC-4337 — Account Abstraction Protocol

**ERC-4337 (Account Abstraction)** breaks the constraint of traditional EOA wallets being entirely dependent on a private key. It introduces the **UserOperation** object — essentially a **"to-do list"** submitted to an Ethereum account. These instructions are sent to a dedicated mempool, where a **Bundler** batches them and merges N operations into a single on-chain transaction.

Validation logic shifts from a hardcoded private key check to a programmable smart contract, enabling social recovery, multi-sig verification, third-party Gas sponsorship, and truly making **"account = contract"** a reality.

---

### ERC-6492 — Pre-deployment Signature Verification

**ERC-6492** solves the problem of smart contract wallets (AA) being unable to verify signatures before the contract is officially deployed.

> Imagine you're a payee, and an AI Agent wants to pay you. The Agent uses a contract wallet, but to save money, it only deploys to the chain the first time it sends a transaction.

ERC-6492 acts like a **"pre-sale receipt"** — it lets an account prove itself via a special signature format before ever touching the chain or paying Gas. The signature includes: who creates the contract, what the initialization code is, and what the original signature is. **"I'm not on-chain yet, but I guarantee this address is mine, and my signature now will be valid once I'm 'born'."**

---

### EIP-7702 — Temporary Contract Delegation Protocol

**EIP-7702** lets a traditional EOA wallet **"temporarily transform"** into a smart contract during a transaction. Unlike ERC-4337, it doesn't require you to abandon your existing private key address. Instead, when initiating a payment, you attach a specific piece of contract code to your address via a digital signature — once the transaction completes, the address reverts to normal private key mode.

Capabilities: execute multiple token payments in a single click (batch operations), let someone else pay your Gas, and set daily spending limits. It perfectly balances private key control with contract flexibility — currently the smoothest path toward **"universal account abstraction"**.

---

### Permit2 — Uniswap Next-Gen Authorization Protocol

**Permit2** is a next-generation token authorization protocol from Uniswap Labs, acting as a middle-layer **"signature processor"** that solves the inefficiency and security problems of the traditional ERC-20 `approve` mechanism. You give Permit2 a **one-time unlimited approval**, and from then on, all token transfers, trades, or cross-chain operations only require an offline signature.

It's compatible with legacy tokens that don't support EIP-2612 (like USDT); introduces highly flexible signature expiry; supports batch transfers; and in payment scenarios, lets users enjoy a **"sign-to-pay"** experience without the risk of over-approval leaving assets permanently exposed.

---

## References

This document is an informal introduction. For protocol details and usage, refer to the official documentation:

- [**ETH docs**](https://eips.ethereum.org/all) - Official Ethereum documentation
- [**Uniswap Docs**](https://docs.uniswap.org/contracts/permit2/overview) - Uniswap Permit2 protocol documentation
- [**LearnBlockchain**](https://learnblockchain.cn/) - Chinese blockchain learning community

---

<div align="center">
<small>Thanks for reading! If this was helpful, please give the project a star.</small>
</div>