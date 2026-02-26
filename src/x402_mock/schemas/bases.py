"""
Base Schema Models for x402 Mock System

This module defines the fundamental base classes and abstract models that all
other schema models inherit from. It provides the foundation for type safety,
validation, and consistent behavior across the entire x402 system.

Core Classes:
    - CanonicalModel: RFC8785-compliant Pydantic base model for cryptographic operations
    - BaseSignature: Abstract signature component model for different blockchains
    - BasePermit: Abstract permit model for blockchain approval mechanisms
    - BasePaymentComponent: Abstract payment requirement specification
    - BaseVerificationResult: Abstract verification result model
    - BaseTransactionConfirmation: Abstract transaction confirmation model

Dependencies:
    - pydantic: For data validation and serialization
"""

import json
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class CanonicalModel(BaseModel):
    """
    RFC8785-compliant Pydantic base model with canonical JSON serialization.
    
    This model ensures consistent, deterministic JSON representation suitable
    for cryptographic operations, signature verification, and hashing.
    
    Features:
        - Automatic conversion of Pydantic objects, enums, and Decimals to standard types
        - Deterministic key sorting in JSON output
        - No extra whitespace for consistent hashing and signature verification
        - RFC8785 compliance for canonical JSON representation
    
    All schema models should inherit from this class to ensure consistent
    serialization across the system.
    
    Example:
        class MyModel(CanonicalModel):
            name: str
            value: int
        
        model = MyModel(name="test", value=123)
        canonical_json = model.to_canonical_json()  # Guaranteed consistent format
    """
    
    model_config = ConfigDict(populate_by_name=True)

    def to_canonical_json(self) -> str:
        """
        Convert model to RFC8785-compliant canonical JSON string.
        
        This method ensures that the JSON representation is:
        1. Deterministically ordered (sorted keys)
        2. Whitespace-minimal (compact format)
        3. Suitable for cryptographic operations
        
        The conversion process:
        1. model_dump(mode="json") converts Pydantic objects, enums, and Decimals
           to standard Python types (str, int, float, etc.)
        2. json.dumps with separators and sort_keys ensures RFC8785 compliance
        
        Returns:
            str: RFC8785-compliant JSON string with sorted keys and no extra whitespace.
        
        Example:
            model = MyModel(name="test", value=123)
            json_str = model.to_canonical_json()
            # Returns: '{"name":"test","value":123}'
        """
        data = self.model_dump(mode="json")
        return json.dumps(
            data,
            separators=(",", ":"),
            sort_keys=True,
            ensure_ascii=False
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert model to dictionary representation.
        
        Returns:
            Dict[str, Any]: Dictionary with all model fields.
        """
        return self.model_dump()


class BaseSignature(CanonicalModel, ABC):
    """
    Abstract base class for blockchain signature components.
    
    This class defines the interface that all blockchain-specific signature
    implementations must follow. Different blockchains use different signature
    formats (e.g., EIP2612 for EVM uses v/r/s, Solana uses 64-byte signature).
    
    All concrete signature classes should inherit from this base class and
    implement the abstract methods to ensure consistent signature handling
    across the system.
    
    Attributes:
        signature_type: The type of signature (e.g., "EIP2612", "Solana")
        created_at: Timestamp when the signature was created
        
    Methods:
        validate_format: Check if signature format is valid for the blockchain
        to_dict: Convert signature to dictionary (inherited from CanonicalModel)
    """
    
    signature_type: str = Field(..., description="Type of signature (e.g., EIP2612, Solana)")
    created_at: datetime = Field(default_factory=datetime.now, description="Signature creation timestamp")

    def validate_format(self) -> bool:
        """
        Validate the signature format for the specific blockchain.
        
        This method should check that all signature components are in valid format
        for the target blockchain. For example:
        - EIP2612: Check v is 27 or 28, r and s are 64 hex chars
        - Solana: Check signature is 64 bytes
        
        Returns:
            bool: True if signature format is valid, False otherwise.
        
        Raises:
            ValueError: If signature format is invalid with descriptive message.
        """
        pass


class BasePermit(CanonicalModel, ABC):
    """
    Abstract base class for blockchain permit/approval mechanisms.
    
    A permit is a signed message that authorizes a spender to transfer tokens
    on behalf of the token owner. Different blockchains implement permits
    differently (EIP2612 for EVM, etc.).
    
    This base class provides the minimal common fields across all permit types.
    Blockchain-specific implementations should extend this class and add their
    specific fields such as owner, spender, token, value, and nonce.
    
    Attributes:
        permit_type: Type of permit (e.g., "EIP2612", "Solana")
        signature: Signature components for permit authorization
        created_at: Timestamp when permit was created
        
    Methods:
        validate_structure: Validate permit structure (blockchain-specific)
    """
    
    permit_type: str = Field(..., description="Type of permit (e.g., EIP2612, Solana)")
    signature: Optional[BaseSignature] = Field(None, description="Signature components")
    created_at: datetime = Field(default_factory=datetime.now, description="Permit creation timestamp")

    def validate_structure(self) -> bool:
        """
        Validate the permit structure and required fields for the blockchain.
        
        Should check that all required fields are present and in valid format
        for the specific blockchain permit type.
        
        Returns:
            bool: True if permit structure is valid, False otherwise.
        
        Raises:
            ValueError: If permit structure is invalid with descriptive message.
        """
        pass


class BasePaymentComponent(CanonicalModel, ABC):
    """
    Abstract base class for payment requirement specifications.
    
    Payment components define what payment is expected: the amount, currency,
    and any additional payment-related constraints or metadata.
    Blockchain-specific implementations (e.g., EVM, SVM) should extend this class
    and add their specific fields such as token addresses.
    
    Attributes:
        payment_type: Type of payment (e.g., "evm", "svm")
        amount: Payment amount for human readability
        currency: Currency code (e.g., "USD", "ETH")
        metadata: Additional payment-related metadata
        created_at: Timestamp when payment component was created
    """
    
    payment_type: str = Field(..., description="Type of payment (e.g., evm, svm)")
    amount: float = Field(..., ge=0, description="Payment amount for human readability")
    currency: str = Field(..., description="Currency code (e.g., USD, ETH)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional payment metadata")
    created_at: datetime = Field(default_factory=datetime.now, description="Payment component creation timestamp")


    def validate_payment(self) -> bool:
        """
        Validate the payment specification.
        
        Should check that payment type, amount, and token are valid and
        compatible with the system requirements.
        
        Returns:
            bool: True if payment specification is valid, False otherwise.
        
        Raises:
            ValueError: If payment specification is invalid with descriptive message.
        """
        pass


class VerificationStatus(str, Enum):
    """
    Enumeration of possible verification result statuses.
    
    Attributes:
        SUCCESS: Permit signature is valid and verification passed
        INVALID_SIGNATURE: Signature is invalid or signer mismatch
        EXPIRED: Permit deadline has passed
        INSUFFICIENT_ALLOWANCE: Authorized amount is insufficient
        INSUFFICIENT_BALANCE: Token balance insufficient for transaction
        REPLAY_ATTACK: Nonce indicates potential replay attack
        BLOCKCHAIN_ERROR: Error querying blockchain state
        UNKNOWN_ERROR: Unexpected error during verification
    """
    SUCCESS = "success"
    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED = "expired"
    INSUFFICIENT_ALLOWANCE = "insufficient_allowance" # TODO IS VALIED FOR TESTNET?
    INSUFFICIENT_BALANCE = "insufficient_balance"
    REPLAY_ATTACK = "replay_attack"
    BLOCKCHAIN_ERROR = "blockchain_error"
    UNKNOWN_ERROR = "unknown_error"


class BaseVerificationResult(CanonicalModel, ABC):
    """
    Abstract base class for permit signature verification results.
    
    This class encapsulates the result of verifying a permit signature and
    checking permit validity on-chain. It provides a standard interface for
    reporting verification status, success/failure details, and diagnostic information.
    
    Attributes:
        verification_type: Type of verification (e.g., "evm", "svm")
        status: Verification result status (VerificationStatus enum)
        is_valid: Boolean indicating if verification was successful
        message: Human-readable status message
        error_details: Detailed error information if verification failed
        verified_at: Timestamp when verification was performed
        
    Methods:
        is_success: Check if verification was successful
        get_error_message: Get formatted error message
    """
    
    verification_type: str = Field(..., description="Type of verification (e.g., evm, svm)")
    status: VerificationStatus = Field(..., description="Verification result status")
    is_valid: bool = Field(..., description="Whether permit is valid and verified")
    message: str = Field(..., description="Human-readable status message")
    error_details: Optional[Dict[str, Any]] = Field(None, description="Detailed error information")
    verified_at: datetime = Field(default_factory=datetime.now, description="Verification timestamp")

    def is_success(self) -> bool:
        """
        Check if verification was successful.
        
        Convenience method to check if the verification passed.
        
        Returns:
            bool: True if verification was successful, False otherwise.
        
        Example:
            result = await adapter.verify_signature(permit, payment)
            if result.is_success():
                # Proceed with transaction
            else:
                # Handle verification failure
        """
        return self.is_valid and self.status == VerificationStatus.SUCCESS

    def get_error_message(self) -> Optional[str]:
        """
        Get formatted error message from verification result.
        
        Returns a human-readable error message explaining why verification failed.
        Returns None if verification was successful.
        
        Returns:
            Optional[str]: Error message if verification failed, None if successful.
        
        Example:
            if not result.is_success():
                error_msg = result.get_error_message()
                print(f"Verification failed: {error_msg}")
        """
        if self.is_success():
            return None
        
        error_msg = f"Verification failed: {self.message}"
        if self.error_details:
            details_str = json.dumps(self.error_details, indent=2)
            error_msg += f"\nDetails: {details_str}"
        return error_msg


class TransactionStatus(str, Enum):
    """
    Enumeration of possible transaction execution statuses.
    
    Attributes:
        SUCCESS: Transaction executed successfully on-chain
        FAILED: Transaction reverted or failed on-chain
        PENDING: Transaction is pending confirmation
        INSUFFICIENT_GAS: Transaction failed due to insufficient gas
        TIMEOUT: Transaction confirmation timed out
        NETWORK_ERROR: Network error during transaction submission
        INVALID_TRANSACTION: Transaction is malformed or invalid
        UNKNOWN_ERROR: Unexpected error during transaction execution
    """
    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    INSUFFICIENT_GAS = "insufficient_gas"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    INVALID_TRANSACTION = "invalid_transaction"
    UNKNOWN_ERROR = "unknown_error"


class BaseTransactionConfirmation(CanonicalModel, ABC):
    """
    Abstract base class for blockchain transaction confirmation/receipt data.
    
    This class captures the result of executing a transaction on-chain, including
    execution status, timing, and confirmation information.
    
    Attributes:
        confirmation_type: Type of confirmation (e.g., "evm", "svm")
        status: Transaction execution status (TransactionStatus enum)
        execution_time: Time taken to confirm transaction (in seconds)
        confirmations: Number of block confirmations
        error_message: Error message if transaction failed
        logs: Optional transaction logs/events
        created_at: Timestamp when confirmation was recorded
        
    Methods:
        is_success: Check if transaction executed successfully
        get_confirmation_status: Get human-readable confirmation status
    """
    
    confirmation_type: str = Field(..., description="Type of confirmation (e.g., evm, svm)")
    status: TransactionStatus = Field(..., description="Transaction execution status")
    execution_time: Optional[float] = Field(None, ge=0, description="Time to confirm (seconds)")
    confirmations: int = Field(default=0, ge=0, description="Number of block confirmations")
    error_message: Optional[str] = Field(None, description="Error message if transaction failed")
    logs: Optional[List[Dict[str, Any]]] = Field(None, description="Transaction logs/events")
    created_at: datetime = Field(default_factory=datetime.now, description="Confirmation recording timestamp")

    def is_success(self) -> bool:
        """
        Check if transaction executed successfully on-chain.
        
        Returns True if the transaction was executed without errors and achieved
        the intended state change on the blockchain.
        
        Returns:
            bool: True if transaction succeeded, False if failed or pending.
        
        Example:
            confirmation = await adapter.send_transaction(permit)
            if confirmation.is_success():
                print(f"Transaction confirmed: {confirmation.tx_hash}")
            else:
                print(f"Transaction failed: {confirmation.error_message}")
        """
        return self.status == TransactionStatus.SUCCESS

    def get_confirmation_status(self) -> str:
        """
        Get human-readable confirmation status message.
        
        Returns:
            str: Human-readable status message describing transaction state.
        
        Example:
            status_msg = confirmation.get_confirmation_status()
            # May return: "Transaction confirmed with 10 confirmations"
        """
        if self.status == TransactionStatus.SUCCESS:
            confirmations_text = f"with {self.confirmations} confirmations" if self.confirmations > 0 else "pending confirmations"
            return f"Transaction confirmed {confirmations_text}"
        elif self.status == TransactionStatus.PENDING:
            return "Transaction is pending confirmation"
        else:
            return f"Transaction failed: {self.error_message or self.status.value}"
