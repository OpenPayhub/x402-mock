"""
EVM Adapter Schema Models

Pydantic models specifically for EVM/EIP2612 permit operations.
These models extend the base schema classes from schemas.bases with EVM-specific implementations.
They serve as the data contract for EVM permit handling across the system.

Core Classes:
    - EIP2612PermitSignature: ECDSA signature components (v, r, s) - inherits from BaseSignature
    - EIP2612Permit: Complete EIP2612 permit with signature - inherits from BasePermit
    - EVMPaymentComponent: EVM-specific payment requirement - inherits from BasePaymentComponent
    - EVMVerificationResult: EVM-specific verification result - inherits from BaseVerificationResult
    - EVMTransactionConfirmation: EVM-specific transaction confirmation - inherits from BaseTransactionConfirmation

HTTP Payload Classes:
    - PermitExecutionPayload: Request payload for permit settlement execution
    - PermitVerificationPayload: Request payload for permit signature verification
    - TokenBalanceQuery: Request payload for token balance queries
"""

from typing import Optional, Dict, Any, Literal

from pydantic import Field

from ...schemas.bases import (
    BaseSignature,
    BasePermit,
    BasePaymentComponent,
    BaseVerificationResult,
    BaseTransactionConfirmation,
    CanonicalModel,
)

class EIP2612PermitSignature(BaseSignature):
    """
    EIP2612 ECDSA Signature Components.
    
    Represents the three components of an ECDSA signature used in EIP2612 permits.
    These components (v, r, s) are extracted from signing EIP712 typed data and are required
    to execute the permit() function on EVM smart contracts.
    
    Inherits from BaseSignature and implements EVM-specific signature validation.
    
    Attributes:
        signature_type: Always "EIP2612" for this implementation
        created_at: Timestamp when the signature was created (inherited from BaseSignature)
        v: Recovery ID for ECDSA signature recovery (27 or 28)
        r: X-coordinate of signature point (64 hex characters, may include 0x prefix)
        s: Y-coordinate of signature point (64 hex characters, may include 0x prefix)
    
    Example:
        sig = EIP2612PermitSignature(
            signature_type="EIP2612",
            v=27,
            r="0x" + "a" * 64,
            s="0x" + "b" * 64
        )
        sig.validate_format()  # Returns True if valid
    """
    
    signature_type: Literal["EIP2612"] = Field(default="EIP2612", description="Signature type identifier")
    v: int = Field(..., ge=27, le=28, description="Recovery ID for signature recovery (27 or 28)")
    r: str = Field(..., description="Signature X-coordinate (64 hex chars, may include 0x prefix)")
    s: str = Field(..., description="Signature Y-coordinate (64 hex chars, may include 0x prefix)")

    def validate_format(self) -> bool:
        """
        Validate EIP2612 signature format.
        
        Checks that all signature components are in valid format for EVM:
        - v must be 27 or 28
        - r and s must be valid hex strings of 64 characters (excluding optional 0x prefix)
        
        Returns:
            bool: True if signature format is valid, False otherwise
        
        Raises:
            ValueError: With descriptive message if validation fails
        
        Example:
            try:
                sig.validate_format()
            except ValueError as e:
                print(f"Invalid signature: {e}")
        """
        # Validate v
        if self.v not in (27, 28):
            raise ValueError(f"Invalid recovery ID: {self.v}. Must be 27 or 28")
        
        # Validate r and s format
        for component_name, component_value in [("r", self.r), ("s", self.s)]:
            # Remove 0x prefix if present
            hex_str = component_value.replace("0x", "").replace("0X", "")
            
            # Check length
            if len(hex_str) != 64:
                raise ValueError(
                    f"Invalid {component_name}: expected 64 hex chars, got {len(hex_str)}"
                )
            
            # Check if valid hex
            try:
                int(hex_str, 16)
            except ValueError:
                raise ValueError(f"Invalid {component_name}: not valid hexadecimal")
        
        return True


class EIP2612Permit(BasePermit):
    """
    EIP2612 Token Approval Permit.
    
    Represents a complete EIP2612 permit for delegated token approval on EVM blockchains.
    This permit can be used with the permit() function on USDC and other permit-enabled
    tokens to grant approval without requiring a separate approve() transaction.
    
    The permit must be signed by the token owner with an EIP712 signature (recovered from v, r, s).
    
    Inherits from BasePermit and adds all EVM-specific permit fields.
    
    Attributes:
        permit_type: Always "EIP2612" for this implementation
        signature: EIP2612 ECDSA signature components (v, r, s)
        deadline: Unix timestamp when permit expires (owner must sign before this time)
        created_at: Timestamp when permit was created (inherited from BasePermit)
        owner: Token owner's wallet address (EVM address format: 0x...) (EVM-specific)
        spender: Address authorized to transfer tokens (typically server address) (EVM-specific)
        token: Token contract address (e.g., USDC address on specific chain) (EVM-specific)
        value: Amount of tokens authorized for transfer (in smallest units, e.g., 1e6 for 1 USDC) (EVM-specific)
        nonce: Unique counter from on-chain state to prevent replay attacks (EVM-specific)
        chain_id: Blockchain network ID (1=Ethereum, 11155111=Sepolia, etc.) (EVM-specific)
    
    Example:
        permit = EIP2612Permit(
            permit_type="EIP2612",
            owner="0x1234...5678",
            spender="0x8765...4321",
            token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            value=1000000,  # 1 USDC with 6 decimals
            deadline=1704067200,
            nonce=0,
            chain_id=11155111,
            signature=EIP2612PermitSignature(...)
        )
    """
    
    permit_type: Literal["EIP2612"] = Field(default="EIP2612", description="Permit type identifier")
    owner: str = Field(..., description="Token owner's wallet address")
    spender: str = Field(..., description="Authorized spender address")
    token: str = Field(..., description="Token contract address")
    value: int = Field(..., ge=0, description="Token amount in smallest units")
    nonce: int = Field(..., ge=0, description="Nonce for replay attack prevention")
    chain_id: int = Field(..., ge=1, description="EVM network ID (1=Ethereum, 11155111=Sepolia, etc.)")
    signature: EIP2612PermitSignature = Field(..., description="EIP2612 ECDSA signature components")

    def validate_structure(self) -> bool:
        """
        Validate EIP2612 permit structure and required fields.
        
        Checks that:
        - All required fields are present and non-empty
        - Addresses are in valid EVM format (0x...)
        - Nonce and other numeric fields are non-negative
        - Signature is present and valid
        
        Returns:
            bool: True if permit structure is valid
        
        Raises:
            ValueError: With descriptive message if validation fails
        
        Example:
            try:
                permit.validate_structure()
            except ValueError as e:
                print(f"Invalid permit: {e}")
        """
        # Validate addresses (should start with 0x and be 42 chars long)
        for field_name, field_value in [("owner", self.owner), ("spender", self.spender), ("token", self.token)]:
            if not field_value.startswith("0x"):
                raise ValueError(f"{field_name} must start with 0x")
            if len(field_value) != 42:
                raise ValueError(f"{field_name} must be 42 characters long (including 0x)")
        
        # Validate signature is present
        if not self.signature:
            raise ValueError("Signature is required for EIP2612 permit")
        
        # Validate signature format
        try:
            self.signature.validate_format()
        except ValueError as e:
            raise ValueError(f"Signature validation failed: {e}")
        
        # Validate chain_id is positive
        if self.chain_id < 1:
            raise ValueError("chain_id must be positive")
        
        return True


class EVMPaymentComponent(BasePaymentComponent):
    """
    EVM-Specific Payment Component.
    
    Extends BasePaymentComponent with EVM-specific payment requirements including
    token contract address and chain ID.
    Typically used for USDC payments on EVM networks (Ethereum, Sepolia, etc.).
    
    Attributes:
        payment_type: Always "evm" for this implementation
        amount: Payment amount for human readability (e.g., 1.0 for 1 USDC)
        currency: Currency code (typically "USD" for stablecoins)
        metadata: Additional payment metadata (may include gas limits, fees, etc.)
        created_at: Timestamp when payment component was created
        token: Token contract address on specific EVM chain (EVM-specific)
        chain_id: EVM network ID (1=Ethereum, 11155111=Sepolia, etc.) (EVM-specific)
    
    Example:
        payment = EVMPaymentComponent(
            payment_type="evm",
            amount=1.0,  # 1 USDC
            currency="USD",
            token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            chain_id=11155111,
            metadata={"gas_price": "20", "priority_fee": "2"}
        )
    """
    
    payment_type: Literal["evm"] = Field(default="evm", description="Payment type identifier")
    token: str = Field(..., description="Token contract address on EVM chain")
    chain_id: int = Field(..., ge=1, description="EVM network ID")

    def validate_payment(self) -> bool:
        """
        Validate EVM payment specification.
        
        Checks that:
        - payment_type is "evm" 
        - amount is non-negative
        - token is valid EVM address format (0x...)
        - chain_id is valid EVM network
        
        Returns:
            bool: True if payment specification is valid
        
        Raises:
            ValueError: With descriptive message if validation fails
        """
        # Validate token address format
        if not self.token.startswith("0x"):
            raise ValueError("Token must be valid EVM address starting with 0x")
        
        if len(self.token) != 42:
            raise ValueError("Token address must be 42 characters long")
        
        # Validate payment type
        if self.payment_type.lower() != "evm":
            raise ValueError(f"Unsupported payment type: {self.payment_type}")
        
        # Validate chain_id
        if self.chain_id < 1:
            raise ValueError("chain_id must be positive")
        
        return True


class EVMVerificationResult(BaseVerificationResult):
    """
    EVM-Specific Permit Verification Result.
    
    Extends BaseVerificationResult with EVM-specific verification information.
    Returned by EVMServerAdapter.verify_signature() method.
    
    Attributes:
        verification_type: Always "evm" for this implementation
        status: Verification result status (inherited from BaseVerificationResult)
        is_valid: Boolean indicating if verification was successful
        message: Human-readable status message (inherited from BaseVerificationResult)
        error_details: Detailed error information if verification failed (inherited from BaseVerificationResult)
        verified_at: Timestamp when verification was performed (inherited from BaseVerificationResult)
        permit_owner: Verified permit owner address (EVM address)
        authorized_amount: Amount verified as authorized (in smallest units)
        blockchain_state: On-chain state data (nonce, allowance, balance, etc.)
        on_chain_nonce: Current on-chain nonce counter for owner
        on_chain_allowance: Current approved allowance amount
        owner_balance: Token balance of owner address
    
    Example:
        result = await evm_adapter.verify_signature(permit, payment)
        if result.is_success():
            print(f"Permit valid. Owner: {result.permit_owner}")
        else:
            print(f"Verification failed: {result.get_error_message()}")
    """
    
    verification_type: Literal["evm"] = Field(default="evm", description="Verification type identifier")
    permit_owner: Optional[str] = Field(None, description="Verified permit owner address (EVM address)")
    authorized_amount: Optional[int] = Field(None, ge=0, description="Verified authorized amount (in smallest units)")
    blockchain_state: Optional[Dict[str, Any]] = Field(None, description="On-chain state data (nonce, allowance, balance, etc.)")
    on_chain_nonce: Optional[int] = Field(None, ge=0, description="Current on-chain nonce counter")
    on_chain_allowance: Optional[int] = Field(None, ge=0, description="Current approved allowance")
    owner_balance: Optional[int] = Field(None, ge=0, description="Token balance of owner")


class EVMTransactionConfirmation(BaseTransactionConfirmation):
    """
    EVM-Specific Transaction Confirmation.
    
    Extends BaseTransactionConfirmation with EVM-specific transaction receipt data.
    Returned by EVMServerAdapter.settle() method.
    
    Attributes:
        confirmation_type: Always "evm" for this implementation
        status: Transaction execution status (inherited from BaseTransactionConfirmation)
        execution_time: Time taken to confirm transaction (seconds) (inherited from BaseTransactionConfirmation)
        confirmations: Number of block confirmations (inherited from BaseTransactionConfirmation)
        error_message: Error details if transaction failed (inherited from BaseTransactionConfirmation)
        logs: Transaction logs/events (inherited from BaseTransactionConfirmation)
        created_at: Timestamp when confirmation was recorded (inherited from BaseTransactionConfirmation)
        tx_hash: Transaction hash (0x-prefixed hex string on EVM)
        block_number: Block number containing transaction
        block_timestamp: Block timestamp (Unix)
        gas_used: Actual gas consumed by transaction
        gas_limit: Gas limit specified for transaction
        transaction_fee: Amount of ETH/native token paid as transaction fee (in wei)
        from_address: Transaction sender address
        to_address: Transaction receiver/contract address
    
    Example:
        confirmation = await evm_adapter.settle(permit)
        if confirmation.is_success():
            print(f"Settlement confirmed: {confirmation.tx_hash}")
            print(f"Gas used: {confirmation.gas_used}")
        else:
            print(f"Settlement failed: {confirmation.error_message}")
    """
    
    confirmation_type: Literal["evm"] = Field(default="evm", description="Confirmation type identifier")
    tx_hash: str = Field(..., description="Transaction hash (0x-prefixed hex string on EVM)")
    block_number: Optional[int] = Field(None, ge=0, description="Block number containing transaction")
    block_timestamp: Optional[int] = Field(None, ge=0, description="Block timestamp (Unix)")
    gas_used: Optional[int] = Field(None, ge=0, description="Actual gas consumed by transaction")
    gas_limit: Optional[int] = Field(None, ge=0, description="Gas limit specified for transaction")
    transaction_fee: Optional[int] = Field(None, ge=0, description="Transaction fee in wei")
    from_address: Optional[str] = Field(None, description="Transaction sender address")
    to_address: Optional[str] = Field(None, description="Transaction receiver/contract address")


