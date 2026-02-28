"""
Abstract Base Classes for Blockchain Adapters

Defines the interface that all blockchain adapters (EVM, Solana, etc.) must implement.
These abstract classes ensure consistent behavior across different blockchain implementations,
defining the factory pattern for server-side and client-side blockchain operations.

Core Classes:
    - AdapterServerFactory: Server-side blockchain operations (signature verification, transaction settlement, balance queries)
    - AdapterClientFactory: Client-side blockchain operations (message building, signature generation)

All implementations must inherit from these base classes and implement the required abstract methods.
Different blockchains (EVM, Solana, etc.) will have their own concrete adapter implementations.
"""

from abc import ABC, abstractmethod
from typing import List

from ..schemas.bases import (
    BasePermit,
    BasePaymentComponent,
    BaseVerificationResult,
    BaseTransactionConfirmation,
)


class AdapterFactory(ABC):
    """
    Abstract Base Class for Server-Side Blockchain Adapters.
    
    Defines the interface for server-side operations that interact directly with blockchain nodes.
    Server-side adapters are responsible for:
    - Verifying permit signatures and permit validity on-chain
    - Executing transactions (settle/send_transaction) on-chain
    - Querying token balances and other on-chain state
    
    Server adapters use the application's private key to sign and send transactions.
    They act as the bridge between the x402 system and the blockchain.
    
    Key Responsibilities:
    1. verify_signature: Validate permit signature and check permit conditions on-chain
    2. settle: Execute the permit transaction on-chain and return confirmation
    3. get_balance: Query token balance of an address on-chain
    4. signature: Support signing operations for blockchain-specific formats
    
    Example Implementation:
        class EVMServerAdapter(AdapterServerFactory):
            # EVM/Ethereum-specific implementation
            pass
        
        class SolanaServerAdapter(AdapterServerFactory):
            # Solana-specific implementation
            pass
    """

    @abstractmethod
    async def verify_signature(
        self,
        permit: BasePermit,
        payment_requirement: BasePaymentComponent,
    ) -> BaseVerificationResult:
        """
        Verify permit signature validity and check permit conditions on-chain.
        
        This is the critical security operation that ensures:
        1. The permit signature is cryptographically valid
        2. The recovered signer matches the permit owner
        3. The permit has not expired
        4. The nonce prevents replay attacks
        5. The owner has sufficient balance and allowance
        6. The payment amount matches or exceeds requirements
        
        Args:
            permit: BasePermit instance containing permit data and signature
            payment_requirement: BasePaymentComponent specifying expected payment amount/conditions
        
        Returns:
            BaseVerificationResult: Detailed verification result including:
                - status: Verification result status (SUCCESS, INVALID_SIGNATURE, EXPIRED, etc.)
                - is_valid: Boolean indicating if permit is valid
                - permit_owner: Verified owner address
                - authorized_amount: Verified authorized amount
                - message: Human-readable status message
                - blockchain_state: Optional on-chain state data
        
        Raises:
            Should not raise exceptions; instead return failed verification results
        
        Implementation Notes:
            - Must recover the signer from signature
            - Must verify signature against permit data hash
            - Must check permit.is_expired()
            - Must query on-chain state (nonce, allowance, balance)
            - Must validate payment amount meets requirements
        
        Example:
            result = await adapter.verify_signature(permit, payment_req)
            if result.is_success():
                # Permit is valid, proceed to settlement
                await adapter.settle(permit)
            else:
                # Return verification error to client
                error_msg = result.get_error_message()
        """
        pass

    @abstractmethod
    async def settle(
        self,
        permit: BasePermit,
    ) -> BaseTransactionConfirmation:
        """
        Execute permit transaction on-chain (settlement/transaction execution).
        
        This method actually executes the token transfer on-chain using the permit signature.
        It should only be called after verify_signature has confirmed the permit is valid.
        
        Steps:
        1. Construct permit() call with signature components (v, r, s)
        2. Build the complete transaction (gas estimation, nonce, etc.)
        3. Sign transaction with server's private key
        4. Broadcast transaction to blockchain
        5. Wait for transaction confirmation
        6. Return transaction confirmation with hash and receipt data
        
        Args:
            permit: BasePermit instance with valid signature (assumed verified)
        
        Returns:
            BaseTransactionConfirmation: Transaction execution result including:
                - status: Transaction status (SUCCESS, FAILED, PENDING, etc.)
                - tx_hash: Transaction hash on-chain
                - block_number: Block number containing transaction
                - block_timestamp: Block timestamp
                - gas_used: Actual gas consumed
                - confirmations: Number of block confirmations
                - error_message: Error details if transaction failed
        
        Raises:
            Typically should not raise; return failed confirmation instead
        
        Implementation Notes:
            - Estimate gas before sending
            - Sign transaction with server private key
            - Handle blockchain-specific transaction formats
            - Wait for configurable number of confirmations
            - Handle network errors gracefully
        
        Example:
            result = await adapter.settle(permit)
            if result.is_success():
                print(f"Settlement complete: {result.tx_hash}")
                # Update database with tx_hash
            else:
                print(f"Settlement failed: {result.error_message}")
        """
        pass

    @abstractmethod
    async def get_balance(self, address: str) -> int:
        """
        Query token balance for an address on the blockchain.
        
        Retrieves the current balance of the configured token (typically USDC) for the given address.
        This is used for:
        - Verification: Check owner has sufficient balance
        - Queries: Allow clients to check addresses' balances
        
        Args:
            address: Wallet address to query (blockchain format, e.g., "0x..." for EVM)
        
        Returns:
            int: Token balance in smallest units (e.g., wei for EVM where 1 USDC = 1e6)
                 Returns 0 if address has no balance
        
        Raises:
            Typically should handle gracefully and return 0 or raise custom exception
        
        Implementation Notes:
            - Use blockchain node RPC call (balanceOf for ERC20)
            - Handle address validation/checksum
            - Cache results if possible for performance
            - Handle blockchain-specific address formats
        
        Example:
            balance = await adapter.get_balance("0x1234...5678")
            # balance = 1000000 (representing 1 USDC with 6 decimals)
        """
        pass
    
    @abstractmethod
    async def signature(
        self,
        payment_component: BasePaymentComponent,
    ) -> BasePermit:
        """
        Generate complete signed permit from payment component.
        
        This method builds the permit message, signs it with user's private key/wallet,
        and returns a fully signed and ready-to-submit permit object.
        All permit parameters are derived from the payment_component.
        
        Args:
            payment_component: BasePaymentComponent specifying payment requirements, 
                              blockchain type, and all permit parameters
        
        Returns:
            BasePermit: Fully signed permit ready for server submission. For EVM, this is EIP2612Permit with:
                - owner: Token owner address
                - spender: Authorized spender address
                - token: Token contract address
                - value: Authorized amount
                - deadline: Permit expiration timestamp
                - nonce: Replay attack prevention nonce
                - signature: EIP2612PermitSignature with v, r, s components
                - permit_type: Blockchain-specific type (e.g., "EIP2612")
        
        Implementation Notes:
            - Extract all permit parameters from payment_component
            - Must validate payment_component matches the adapter's blockchain type
            - Must build blockchain-specific permit message internally
            - Must sign with user's private key (not server's)
            - Must validate signature format before returning
            - Must return complete permit with signature components
            - Should not leak private key
        
        Raises:
            TypeError: If payment_component blockchain type doesn't match adapter
            ValueError: If payment_component is invalid or signing fails
        
        Example:
            adapter = EVMClientAdapter()
            payment = EVMPaymentComponent(payment_type="evm", ...)
            permit = await adapter.signature(payment_component=payment)
            # permit now contains complete signed data ready to send to server
            await server.settle(permit)
        """
        pass



    async def client_init(self, payment_components: List[BasePaymentComponent]) -> None:
        """
        One-time client-side pre-signing initialisation hook.

        Called by AdapterHub.initialize(role="client") once at startup, before
        any signature() calls are made.  Concrete adapters should override this
        to perform chain-specific on-chain setup required by the signing role
        (e.g. ERC-20 allowance approval for Permit2 on EVM, SPL token delegation
        on SVM).  The default implementation is a no-op so that server-only
        adapters and future adapters can inherit without modification.

        Args:
            payment_components: All payment components registered via
                register_payment_methods(). The implementation may filter
                these down to the subset it manages.

        Raises:
            RuntimeError: If any required on-chain setup fails.
        """
        pass

    @abstractmethod
    def get_wallet_address(self) -> str:
        """
        Get server wallet address from private key.
        
        Returns:
            str: Server wallet address in checksum format
        """
        pass


class AdapterRegistry(ABC):
    """
    Abstract Base Class for Payment Method Registration Factory.
    
    Defines the factory interface for registering payment methods across different blockchain adapters.
    All concrete adapter implementations must inherit from this class and implement the
    payment_method_register() method to ensure consistent payment method registration.
    
    This class serves as a factory pattern that enforces a unified specification for how
    payment methods (both payment collection and disbursement methods) should be registered
    across different blockchain implementations (EVM, Solana, etc.).
    
    Key Responsibilities:
        1. Provide a standardized interface for payment method registration
        2. Ensure all adapters follow the same registration pattern
        3. Enable centralized management of payment methods across different blockchains
        4. Support extensibility for new payment methods and blockchain types
    
    Implementation Requirements:
        - Each concrete adapter must implement payment_method_register()
        - Registration should include all supported payment methods for the blockchain
        - Methods should be registered in a format compatible with the AdapterHub
        - Registration should handle both server-side and client-side payment operations
    
    Example Implementation:
        class EVMAdapterRegistry(AdapterRegistry):
            def payment_method_register(self) -> None:
                # Register EVM-specific payment methods
                # e.g., ERC20 tokens, native ETH transfers, etc.
                pass
        
        class SolanaAdapterRegistry(AdapterRegistry):
            def payment_method_register(self) -> None:
                # Register Solana-specific payment methods
                # e.g., SPL tokens, native SOL transfers, etc.
                pass
    
    Usage:
        registry = EVMAdapterRegistry()
        registry.payment_method_register()
        # Payment methods are now registered and available through AdapterHub
    """
    payment_component: List[BasePaymentComponent] = []
    
    @abstractmethod
    def payment_method_register(self) -> None:
        """
        Register payment methods for the specific blockchain adapter.
        
        This factory method must be implemented by all concrete adapter implementations
        to register their supported payment methods (both collection and disbursement).
        The registration ensures that payment methods are available through the unified
        AdapterHub interface and follow consistent patterns across different blockchains.
        
        Implementation should:
        1. Register all supported payment methods for the blockchain
        2. Include both server-side (receiving) and client-side (sending) methods
        3. Store registered payment components in the class variable `payment_component`
        4. Handle any blockchain-specific configuration or initialization
        
        The registered methods should be accessible through:
            - AdapterHub.get_payment_methods()
            - PaymentRegistry.get_support_list()
            - The class variable `payment_component` (List[BasePaymentComponent])
        
        Note:
            This method is typically called during adapter initialization or
            when the AdapterHub is being set up. It should not be called
            directly by application code in most cases.
            Implementations should populate the `payment_component` list with
            registered payment components for easy access and management.
        
        Raises:
            RuntimeError: If registration fails due to configuration issues
            ValueError: If payment method parameters are invalid
        
        Example (EVM implementation):
            def payment_method_register(self) -> None:
                # Register USDC on Ethereum mainnet
                usdc_component = EVMPaymentComponent(
                    payment_type='evm',
                    amount=100.0,
                    token='0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
                    currency='USD',
                    chain_id=1,
                    metadata={...}
                )
                self.payment_component.append(usdc_component)
                
                # Register DAI on Polygon
                dai_component = EVMPaymentComponent(
                    payment_type='evm',
                    amount=50.0,
                    token='0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063',
                    currency='DAI',
                    chain_id=137,
                    metadata={...}
                )
                self.payment_component.append(dai_component)
        """
        pass
