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

