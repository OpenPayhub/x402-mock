"""
Exception and Error Definitions Module

Defines custom exception hierarchy for payment processing, permit verification,
and blockchain interactions. All exceptions inherit from BaseException for
unified exception handling.

Exception Hierarchy:
    BaseException (root)
    ├── AuthenticationError
    ├── PaymentMethodError
    ├── PaymentSignatureError
    ├── PaymentVerificationError
    │   ├── InsufficientFundsError
    │   ├── SignatureVerificationError
    │   ├── PermitExpiredError
    │   └── PermitNonceError
    ├── TokenError
    │   ├── TokenExpiredError
    │   ├── InvalidTokenError
    │   └── TokenNotFoundError
    ├── ConfigurationError
    └── InvalidTransition
"""


class BaseException(Exception):
    """
    Root exception class for all project-specific exceptions.
    
    All custom exceptions should inherit from this class to enable
    unified exception handling and centralized error processing.
    """
    pass

    
class AuthenticationError(BaseException):
    """
    Raised when authentication fails or credentials are invalid.
    
    This includes scenarios such as:
    - Invalid or expired access tokens
    - Missing authentication headers
    - Authentication signature verification failure
    """
    pass


class PaymentMethodError(BaseException):
    """
    Raised when a payment method is invalid or unsupported.
    
    This includes scenarios such as:
    - Unsupported payment type (on-chain vs off-chain mismatch)
    - Missing required payment method configuration
    - Payment method not registered on server
    """
    pass


class PaymentSignatureError(BaseException):
    """
    Raised when payment signature generation or processing fails.
    
    This includes scenarios such as:
    - Signature format validation failure
    - Private key access issues
    - Signature encoding errors
    """
    pass


class TokenError(BaseException):
    """
    Base exception for token-related errors.
    
    Parent class for all token validation and management errors.
    """
    pass


class TokenExpiredError(TokenError):
    """
    Raised when a token has expired and is no longer valid.
    
    Attributes:
        expiration_time: When the token expired
    """
    pass


class InvalidTokenError(TokenError):
    """
    Raised when a token is invalid or malformed.
    
    This includes scenarios such as:
    - Corrupted token data
    - Invalid token signature
    - Unsupported token version
    """
    pass


class TokenNotFoundError(TokenError):
    """
    Raised when a requested token cannot be found.
    
    Typically occurs in token lookup or retrieval operations.
    """
    pass


class PaymentVerificationError(BaseException):
    """
    Base exception for payment verification failures.
    
    Parent class for all errors that occur during payment validation.
    """
    pass


class SignatureVerificationError(PaymentVerificationError):
    """
    Raised when permit signature verification fails.
    
    This includes scenarios such as:
    - Invalid ECDSA signature
    - Signature from wrong address
    - Tampered signature data
    - Signer address mismatch
    
    Attributes:
        permit_type: Type of permit being verified
        signer: Expected signer address
        recovered: Actually recovered address from signature
    """
    pass


class PermitExpiredError(PaymentVerificationError):
    """
    Raised when a permit has expired and can no longer be executed.
    
    The permit deadline has passed on the blockchain.
    
    Attributes:
        deadline: The expired permit deadline
        current_time: Current block timestamp
    """
    pass


class PermitNonceError(PaymentVerificationError):
    """
    Raised when permit nonce is invalid or already used.
    
    This protects against replay attacks by ensuring each permit
    has a unique nonce that increments with each use.
    
    Attributes:
        expected_nonce: Nonce expected on-chain
        provided_nonce: Nonce in the permit
    """
    pass


class InsufficientFundsError(PaymentVerificationError):
    """
    Raised when account balance is insufficient for the payment.
    
    This includes scenarios such as:
    - Token balance less than permit amount
    - Insufficient gas for transaction execution
    
    Attributes:
        required: Amount required
        available: Amount available
    """
    pass


class ConfigurationError(BaseException):
    """
    Raised when configuration is missing or invalid.
    
    This includes scenarios such as:
    - Missing required configuration keys
    - Invalid configuration values
    - RPC URL unreachable
    - Unsupported network configuration
    """
    pass


class InvalidTransition(Exception):
    """
    Raised when an invalid state transition occurs in event processing.
    
    This indicates that the payment state machine received an event
    that is not valid for the current state.
    
    Attributes:
        current_state: Current payment/transaction state
        event_type: Event that triggered the transition
        message: Description of why transition is invalid
    """
    pass


class BlockchainInteractionError(BaseException):
    """
    Raised when blockchain interaction (RPC call) fails.
    
    This includes scenarios such as:
    - RPC call timeout
    - Network connectivity issues
    - Invalid contract address
    - Contract call revert
    
    Attributes:
        rpc_method: RPC method that was called (e.g., 'eth_call')
        reason: Error reason from blockchain node
    """
    pass


class TransactionExecutionError(BlockchainInteractionError):
    """
    Raised when blockchain transaction execution fails.
    
    This includes scenarios such as:
    - Transaction reverted on-chain
    - Out of gas
    - Invalid transaction parameters
    - Nonce conflicts
    
    Attributes:
        tx_hash: Transaction hash if available
        revert_reason: Reason transaction was reverted
    """
    pass