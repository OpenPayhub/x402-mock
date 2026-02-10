# API Reference

Comprehensive API documentation for x402_mock module.

## Servers

**HTTP 402 Payment Protocol Server Implementation**

The Servers module provides a FastAPI-based server framework for implementing HTTP 402 Payment Required protocol. It offers an event-driven architecture that encapsulates all payment collection logic, allowing payment receivers to integrate cryptocurrency payment acceptance with minimal configuration.

**Key Features:**
- **FastAPI Integration**: Extended FastAPI application with built-in payment endpoint routes
- **Token Management**: Secure JWT-based access token generation and verification
- **Event-Driven Architecture**: Subscribe to payment lifecycle events (request, verification, settlement)
- **Multi-Chain Support**: Register multiple payment methods across different blockchain networks
- **Auto-Settlement**: Optional automatic on-chain settlement after successful verification
- **Security Utilities**: Private key generation, token signing, and environment key management

**Main Components:**
- `Http402Server`: Main server class extending FastAPI with payment protocol support
- Security helpers: `generate_token()`, `verify_token()`, `create_private_key()`, `save_key_to_env()`

::: x402_mock.servers

## Clients

**HTTP 402 Payment Client Middleware**

The Clients module provides an intelligent HTTP client that transparently handles HTTP 402 Payment Required responses. It extends `httpx.AsyncClient` to automatically intercept payment challenges, generate signed payment permits, exchange them for access tokens, and retry the original request—all without requiring explicit user intervention.

**Key Features:**
- **Transparent Payment Handling**: Automatically processes 402 responses without manual intervention
- **httpx Compatibility**: Fully compatible drop-in replacement for httpx.AsyncClient
- **Permit Auto-Signing**: Generates blockchain-specific signed permits using registered payment methods
- **Token Exchange**: Automatically exchanges permits for access tokens at server endpoints
- **Request Retry**: Seamlessly retries original requests with obtained authorization
- **Multi-Chain Support**: Register payment capabilities across different blockchain networks

**Main Components:**
- `Http402Client`: Extended async HTTP client with automatic payment flow handling

**Usage Pattern:**
1. Initialize client and register payment methods
2. Make standard HTTP requests to protected resources
3. Client automatically handles 402 challenges and obtains access
4. Receive successful responses transparently

::: x402_mock.clients

## Adapters

**Unified Blockchain Adapter Interface**

The Adapters module provides a unified abstraction layer that bridges differences between various blockchain platforms (EVM, Solana, etc.). It implements a plugin-based architecture with automatic blockchain type detection, enabling consistent payment permit signing, signature verification, and on-chain settlement operations across heterogeneous blockchain ecosystems.

**Key Features:**
- **Blockchain Abstraction**: Unified interface for EVM, SVM (Solana), and other blockchain platforms
- **Automatic Type Detection**: Identifies blockchain type from chain identifiers (CAIP-2 format)
- **Signature Operations**: Generate and verify blockchain-specific cryptographic signatures
- **Permit Validation**: Verify permit authenticity, expiration, nonce, and on-chain conditions
- **Transaction Settlement**: Execute on-chain transfers with confirmation tracking
- **Balance Queries**: Query token balances and allowances across different chains
- **Extensible Architecture**: Factory pattern enables easy addition of new blockchain adapters

**Main Components:**
- `AdapterHub`: Central gateway routing operations to appropriate blockchain adapters
- `AdapterFactory`: Abstract base class defining adapter interface contracts
- `PaymentRegistry`: Manages payment method registration and retrieval
- Platform-specific adapters: `EVMAdapter` (Ethereum/EVM chains), SVM adapter (coming soon)

**Architecture Pattern:**
Uses the Adapter pattern combined with Factory pattern to provide a consistent API while delegating to blockchain-specific implementations under the hood.

::: x402_mock.adapters

## Schemas

**Base Schema Models and Type System**

The Schemas module defines the foundational type system and data models that underpin the entire x402_mock framework. It provides RFC8785-compliant Pydantic models for cryptographic operations, abstract base classes ensuring type safety across blockchain implementations, and standardized HTTP protocol message formats.

**Key Features:**
- **RFC8785 Compliance**: Canonical JSON serialization for deterministic signature generation
- **Type Safety**: Pydantic-based validation with comprehensive type hints
- **Abstract Base Classes**: Define contracts for permits, signatures, verification results, and confirmations
- **Protocol Messages**: Standardized HTTP 402 request/response payload schemas
- **Version Management**: Protocol version negotiation and compatibility handling
- **Blockchain Agnostic**: Base models inherited by all blockchain-specific implementations

**Main Components:**
- `CanonicalModel`: RFC8785-compliant base model with deterministic JSON serialization
- Abstract types: `BasePermit`, `BaseSignature`, `BaseVerificationResult`, `BaseTransactionConfirmation`
- HTTP protocol: `ClientRequestHeader`, `Server402ResponsePayload`, `ClientTokenRequest`, `ServerTokenResponse`
- Payment models: `BasePaymentComponent` defining payment requirements
- Status enums: `VerificationStatus`, `TransactionStatus`
- Version handling: `ProtocolVersion`, `SupportedVersions`

**Purpose:**
Serves as the type foundation ensuring consistent data structures and validations across servers, clients, adapters, and engine components.

::: x402_mock.schemas

## Engine

**Event-Driven Execution Engine**

The Engine module implements a sophisticated event-driven architecture for orchestrating payment protocol workflows. It provides a typed event system with an event bus that allows subscribers to hook into the payment lifecycle, monitor execution flow, capture errors, and customize behavior at critical execution points.

**Key Features:**
- **Typed Event System**: Strongly-typed events representing each stage of payment processing
- **Event Bus**: Publish-subscribe pattern for decoupled event handling
- **Hook Subscription**: Use `add_hook()` to subscribe handlers to specific event types
- **Event Chain Execution**: Sequential event processing with state transitions
- **Comprehensive Events**: Request initialization, token exchange, verification, settlement, errors
- **Dependency Injection**: Clean separation of business logic from infrastructure dependencies
- **Exception Hierarchy**: Rich exception types for granular error handling
- **Async-Native**: Built for asynchronous execution with asyncio support

**Key Event Types:**
- `RequestInitEvent`: Initial request with optional authorization token
- `RequestTokenEvent`: Payment permit submission for token exchange
- `Http402PaymentEvent`: Payment required response with payment schemes
- `VerifySuccessEvent` / `VerifyFailedEvent`: Signature verification results
- `SettleSuccessEvent` / `SettleFailedEvent`: On-chain settlement outcomes
- `TokenIssuedEvent`: Successful access token generation
- `AuthorizationSuccessEvent`: Successful request authorization

**Main Components:**
- `EventBus`: Central event dispatcher with subscriber management
- `EventChain`: Orchestrates event sequence execution
- `Dependencies`: Immutable container for shared infrastructure
- Typed events: All events inherit from `BaseEvent`
- Custom exceptions: Detailed error types for different failure scenarios

**Usage Pattern:**
Developers can subscribe custom handlers to events using `event_bus.subscribe(EventType, handler)` to intercept events, log transactions, trigger webhooks, or implement custom business logic at any point in the payment flow.

::: x402_mock.engine
