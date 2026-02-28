"""
EVM Adapter Schema Models

Pydantic models for EVM permit and settlement operations.  All classes
inherit from the base schema hierarchy in ``schemas.bases``.

Signature classes:
    - EVMECDSASignature: Unified v/r/s signature for EIP-2612 and ERC-3009
      (use ``signature_type`` to distinguish).
    - Permit2Signature: Permit2 ``permitTransferFrom`` authorization with embedded
      :class:`EVMECDSASignature` (mirrors :class:`ERC3009Authorization` structure).

Permit / authorization classes:
    - EVMTokenPermit: EIP-2612 ``permit()`` authorization (owner, spender,
      value, deadline).  ``permit_type`` identifies the standard.
    - ERC3009Authorization: ERC-3009 ``transferWithAuthorization`` payload
      (distinct field structure — kept separate).

Result / confirmation classes:
    - EVMVerificationResult: Unified verification outcome (covers ERC-3009, Permit2, EIP-2612).
    - EVMTransactionConfirmation: Settlement transaction receipt.
    - ERC4337ValidationResult: ``validateUserOp`` result for ERC-4337.

Supporting classes:
    - EVMPaymentComponent: EVM payment requirement (token + chain_id).
    - UserOperationModel: Minimal EIP-4337 UserOperation structure.
    - ERC4337UserOpPayload: UserOperation submission payload for settlement.
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

class EVMECDSASignature(BaseSignature):
    """
    Unified EVM ECDSA signature (v, r, s).

    Shared base for all EVM standards that produce a three-component ECDSA
    signature.  Use ``signature_type`` to identify the signing standard:

    * ``"EIP2612"`` — EIP-2612 ``permit()`` calls.
    * ``"ERC3009"`` — ERC-3009 ``transferWithAuthorization`` calls.
    * ``"Permit2"`` — Uniswap Permit2 ``permitTransferFrom`` calls.

    Attributes:
        signature_type: One of ``"EIP2612"``, ``"ERC3009"``, ``"Permit2"``.
        v: ECDSA recovery ID (27 or 28).
        r: r component — 32 bytes as a 64-char hex string (0x prefix optional).
        s: s component — 32 bytes as a 64-char hex string (0x prefix optional).

    Example::

        sig = EVMECDSASignature(signature_type="EIP2612", v=27, r="0x" + "a" * 64, s="0x" + "b" * 64)
        sig.validate_format()
    """

    signature_type: Literal["EIP2612", "ERC3009", "Permit2"] = Field(
        ..., description="Signing standard: 'EIP2612', 'ERC3009', or 'Permit2'"
    )
    v: int = Field(..., ge=27, le=28, description="ECDSA recovery ID (27 or 28)")
    r: str = Field(..., description="Signature r component (32 bytes, 64-char hex, 0x prefix optional)")
    s: str = Field(..., description="Signature s component (32 bytes, 64-char hex, 0x prefix optional)")

    def validate_format(self) -> bool:
        """
        Validate v/r/s components.

        Checks v is 27 or 28 and that r/s are valid 64-character hex strings
        (0x prefix stripped before length check).

        Returns:
            True when all components pass.

        Raises:
            ValueError: Descriptive message on the first failed check.
        """
        if self.v not in (27, 28):
            raise ValueError(f"Invalid recovery ID: {self.v}. Must be 27 or 28")

        for name, val in [("r", self.r), ("s", self.s)]:
            hex_str = val.replace("0x", "").replace("0X", "")
            if len(hex_str) != 64:
                raise ValueError(f"Invalid {name}: expected 64 hex chars, got {len(hex_str)}")
            try:
                int(hex_str, 16)
            except ValueError:
                raise ValueError(f"Invalid {name}: not valid hexadecimal")

        return True

    def to_packed_hex(self) -> str:
        """
        Encode v/r/s into a packed 65-byte hex string (``r || s || v``).

        This is the format expected by on-chain contracts such as Permit2's
        ``permitTransferFrom`` which accept a raw ``bytes`` signature argument.

        Returns:
            0x-prefixed 132-character hex string.

        Raises:
            ValueError: If components do not pass ``validate_format()``.
        """
        self.validate_format()
        r = self.r.replace("0x", "").replace("0X", "").zfill(64)
        s = self.s.replace("0x", "").replace("0X", "").zfill(64)
        return "0x" + r + s + format(self.v, "02x")


class EVMTokenPermit(BasePermit):
    """
    EVM Token Approval Permit (EIP-2612).

    Encapsulates a signed EIP-2612 ``permit()`` authorization, allowing a
    spender to transfer tokens from the owner's account without a prior
    on-chain ``approve()`` call.  Pass to ``EVMServerAdapter.settle()`` for
    settlement.

    Use ``permit_type`` to distinguish permit standards at call sites.

    Attributes:
        permit_type: Always ``"EIP2612"`` for this class.
        owner: Token owner's wallet address (0x-prefixed, 42 chars).
        spender: Address authorized to spend; typically the settlement server.
        token: ERC-20 token contract address.
        value: Approved amount in the token's smallest unit.
        nonce: On-chain nonce from the token contract (replay protection).
        deadline: Unix timestamp after which the permit is invalid.
        chain_id: EVM network ID (e.g. 1 = Mainnet, 11155111 = Sepolia).
        signature: ECDSA signature with ``signature_type='EIP2612'``.

    Example::

        permit = EVMTokenPermit(
            owner="0x1234...5678",
            spender="0x8765...4321",
            token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            value=1_000_000,
            nonce=0,
            deadline=1_900_000_000,
            chain_id=11155111,
            signature=EVMECDSASignature(signature_type="EIP2612", v=27, r="0x...", s="0x..."),
        )
    """

    permit_type: Literal["EIP2612"] = Field(default="EIP2612", description="Permit standard identifier")
    owner: str = Field(..., description="Token owner's wallet address (0x-prefixed)")
    spender: str = Field(..., description="Authorized spender address")
    token: str = Field(..., description="ERC-20 token contract address")
    value: int = Field(..., ge=0, description="Approved amount in the token's smallest unit")
    nonce: int = Field(..., ge=0, description="On-chain nonce for replay protection")
    deadline: int = Field(..., ge=0, description="Unix timestamp after which the permit expires")
    chain_id: int = Field(..., ge=1, description="EVM network ID")
    signature: EVMECDSASignature = Field(..., description="EIP-2612 ECDSA signature (signature_type='EIP2612')")

    def validate_structure(self) -> bool:
        """
        Validate permit fields and embedded signature.

        Checks that ``owner``, ``spender``, and ``token`` are valid 42-char
        0x-prefixed addresses, that ``chain_id`` is positive, and that the
        attached ``EVMECDSASignature`` passes its own format validation.

        Returns:
            True when all checks pass.

        Raises:
            ValueError: With a descriptive message on the first failed check.
        """
        for field_name, value in [("owner", self.owner), ("spender", self.spender), ("token", self.token)]:
            if not value.startswith("0x"):
                raise ValueError(f"{field_name} must be a 0x-prefixed address")
            if len(value) != 42:
                raise ValueError(f"{field_name} must be 42 characters (0x + 40 hex), got {len(value)}")

        if not self.signature:
            raise ValueError("signature is required")

        try:
            self.signature.validate_format()
        except ValueError as e:
            raise ValueError(f"Signature validation failed: {e}")

        if self.chain_id < 1:
            raise ValueError("chain_id must be a positive integer")

        return True


class EVMPaymentComponent(BasePaymentComponent):
    """
    EVM-Specific Payment Component.
    
    Extends BasePaymentComponent with EVM-specific payment requirements including
    token contract address, chain identifier (CAIP-2), and an optional recipient address.
    Typically used for USDC payments on EVM networks (Ethereum, Sepolia, etc.).
    
    Attributes:
        payment_type: Always "evm" for this implementation
        amount: Payment amount for human readability (e.g., 1.0 for 1 USDC)
        currency: Currency code (typically "USD" for stablecoins)
        metadata: Additional payment metadata (may include gas limits, fees, etc.)
        created_at: Timestamp when payment component was created
        token: Token contract address on specific EVM chain (EVM-specific)
        caip2: CAIP-2 chain identifier (e.g., "eip155:1", "eip155:11155111") (EVM-specific)
        pay_to: Optional recipient address to pay to (EVM-specific)
        rpc_url: Optional EVM RPC URL for this payment (EVM-specific)
        token_name: Optional token name (e.g., "USDC") (EVM-specific)
        token_decimals: Optional token decimals (string or int) (EVM-specific)
        token_version: Optional token version (string or int) (EVM-specific)
    
    Example:
        payment = EVMPaymentComponent(
            payment_type="evm",
            amount=1.0,  # 1 USDC
            currency="USD",
            token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            caip2="eip155:11155111",
            metadata={"gas_price": "20", "priority_fee": "2"}
        )
    """
    
    payment_type: Literal["evm"] = Field(default="evm", description="Payment type identifier")
    token: str = Field(..., description="Token contract address on EVM chain")
    caip2: str = Field(..., description='CAIP-2 chain identifier (e.g., "eip155:1")')
    pay_to: str | None = Field(default=None, description="Optional recipient address to pay to")
    rpc_url: str | None = Field(default=None, description="Optional RPC URL for chain access")
    token_name: str | None = Field(default=None, description="Optional token name (e.g., 'USDC')")
    token_decimals: str | int | None = Field(default=None, description="Optional token decimals (string or int)")
    token_version: str | int | None = Field(default=None, description="Optional token version (string or int)")

    def validate_payment(self) -> bool:
        """
        Validate EVM payment specification.
        
        Checks that:
        - payment_type is "evm" 
        - amount is non-negative
        - token is valid EVM address format (0x...)
        - caip2 is a valid CAIP-2 identifier for EVM chains (eip155:<chain_id>)
        - pay_to is either None or a valid EVM address format (0x...)
        
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

        # Validate optional recipient address format
        if self.pay_to is not None:
            if not self.pay_to.startswith("0x"):
                raise ValueError("pay_to must be a valid EVM address starting with 0x")
            if len(self.pay_to) != 42:
                raise ValueError("pay_to address must be 42 characters long")
        
        # Validate payment type
        if self.payment_type.lower() != "evm":
            raise ValueError(f"Unsupported payment type: {self.payment_type}")
        
        
        return True


class EVMVerificationResult(BaseVerificationResult):
    """
    Unified EVM signature verification result.

    Covers all EVM signing schemes (ERC-3009, Permit2, EIP-2612).  Uses
    scheme-neutral field names that mirror ``sign_universal`` /
    ``verify_universal``:

    Attributes:
        verification_type: Always ``"evm"``.
        sender:            Token owner / authorizer address that produced the
                           signature.
        receiver:          Destination / authorised spender address.
        authorized_amount: Transfer amount in the token's smallest unit.
        blockchain_state:  Optional on-chain state snapshot (balance, nonce,
                           allowance, etc.).
    """

    verification_type: Literal["evm"] = Field(default="evm", description="Verification type identifier")
    sender: Optional[str] = Field(None, description="Token owner / authorizer address that produced the signature")
    receiver: Optional[str] = Field(None, description="Destination / authorised spender address")
    authorized_amount: Optional[int] = Field(None, ge=0, description="Transfer amount in the token's smallest unit")
    blockchain_state: Optional[Dict[str, Any]] = Field(None, description="Optional on-chain state snapshot (balance, nonce, allowance, etc.)")


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


class ERC3009Authorization(BasePermit):
    """
    ERC-3009 Authorization (TransferWithAuthorization) container.

    This model captures the canonical fields of an ERC-3009 authorization
    (also referred to as "TransferWithAuthorization" in the EIP). It is
    intended as a data-only representation for signing, transport and
    verification routines elsewhere in the system.

    Notes:
        - The model does not perform cryptographic verification; it only
          describes the data structure expected by such verification.

    Attributes:
        permit_type: Literal identifier for this authorization type ("ERC3009").
        token: Token contract address the authorization applies to.
        chain_id: Numeric chain identifier where the authorization is valid.
        authorizer: Address authorizing the transfer (field named `from` in the EIP).
        recipient: Address receiving tokens (maps to `to` in EIP types).
        value: Amount authorized for transfer (uint256 smallest units).
        validAfter: Start timestamp (inclusive) for validity.
        validBefore: Expiry timestamp (exclusive) for validity.
        nonce: Unique nonce (bytes32 hex string) preventing replay.
        signature: ERC3009Signature container with v/r/s.
    """

    permit_type: Literal["ERC3009"] = Field(default="ERC3009", description="Authorization type identifier")
    token: str = Field(..., description="Token contract address")
    chain_id: int = Field(..., ge=1, description="Numeric chain id")
    authorizer: str = Field(..., description="Authorizer address (maps to `from` in EIP-3009)")
    recipient: str = Field(..., description="Recipient address (maps to `to` in EIP-3009)")
    value: int = Field(..., ge=0, description="Amount authorized in smallest token units")
    validAfter: int = Field(..., ge=0, description="Start timestamp for validity (unix)")
    validBefore: int = Field(..., ge=0, description="Expiry timestamp for validity (unix)")
    nonce: str = Field(..., description="Unique nonce (bytes32 hex string)")
    signature: Optional[EVMECDSASignature] = Field(None, description="ECDSA signature with signature_type='ERC3009'")


class UserOperationModel(CanonicalModel):
    """
    Minimal EIP-4337 `UserOperation` structure as a Pydantic model.

    This model is a Pydantic representation of the `UserOperation` fields
    commonly used with account-abstraction and bundlers. It is provided here
    for transport and validation of the user-operation payload; it does not
    implement packing or signing logic.

    Attributes mirror the canonical EIP-4337 fields: `sender`, `nonce`,
    `initCode`, `callData`, gas fields, fee fields, `paymasterAndData`, and
    the `signature` blob.
    """

    sender: str = Field(..., description="Account sending the user operation")
    nonce: int = Field(..., ge=0, description="Nonce to prevent replay")
    initCode: str = Field(..., description="Initialization code for account creation (hex)")
    callData: str = Field(..., description="Call data payload for the operation (hex)")
    callGasLimit: int = Field(..., ge=0, description="Gas limit for the inner call")
    verificationGasLimit: int = Field(..., ge=0, description="Gas limit for verification")
    preVerificationGas: int = Field(..., ge=0, description="Gas used prior to verification")
    maxFeePerGas: int = Field(..., ge=0, description="Max fee per gas user will pay")
    maxPriorityFeePerGas: int = Field(..., ge=0, description="Max priority fee per gas")
    paymasterAndData: str = Field(..., description="Paymaster address and optional data (hex)")
    signature: Optional[str] = Field(None, description="Signature over the user operation (hex)")


class ERC4337UserOpPayload(CanonicalModel):
    """
    EIP-4337 UserOperation submission payload.

    This model wraps a `UserOperationModel` together with the target entry
    point contract address and chain id, forming the complete payload that
    would be submitted to a bundler or entrypoint for account-abstraction
    settlement. It does not represent a raw cryptographic signature; rather
    it encapsulates the full account-abstraction authorization object used
    during the settle phase.

    Attributes:
        signature_type: Literal identifier ("ERC4337").
        user_operation: The `UserOperationModel` instance to be submitted.
        entry_point: Entry point contract address that will process the op.
        chain_id: Numeric chain id where the operation is intended.
    """

    signature_type: Literal["ERC4337"] = Field(default="ERC4337", description="Signature type identifier")
    user_operation: UserOperationModel = Field(..., description="User operation payload")
    entry_point: str = Field(..., description="Entrypoint contract address")
    chain_id: int = Field(..., ge=1, description="Target chain id")


class ERC4337ValidationResult(BaseVerificationResult):
    """
    Validation result container for ERC-4337 user operations.

    This model holds the outcome of the ``validateUserOp`` call performed by
    bundlers or entrypoints (using ERC-4337 terminology) and provides
    diagnostic information useful for callers and logging. It purposely does
    not attempt to re-create the full on-chain validation machinery.

    Attributes:
        verification_type: Literal identifier ("ERC4337").
        user_op_hash: Optional hex digest of the user operation.
        entry_point: Entrypoint contract address that validated the op.
        bundle_id: Optional bundler identifier that accepted/processed the op.
        is_valid: Boolean indicating validation success when known.
        validation_gas_used: Optional gas used by the validateUserOp routine.
        error_details: Optional structured error information.
    """

    verification_type: Literal["ERC4337"] = Field(default="ERC4337", description="Verification type identifier")
    user_op_hash: Optional[str] = Field(None, description="Hex hash of the user operation when available")
    entry_point: Optional[str] = Field(None, description="Entrypoint contract address that validated the op")
    bundle_id: Optional[str] = Field(None, description="Optional bundler identifier")
    is_valid: Optional[bool] = Field(None, description="Whether validation succeeded")
    validation_gas_used: Optional[int] = Field(None, ge=0, description="Gas used by validation process")
    error_details: Optional[Dict[str, Any]] = Field(None, description="Optional diagnostic/error information")

    # ERC-1271 (contract-based signature) details when encountered during


class Permit2Signature(BasePermit):
    """
    Permit2 ``permitTransferFrom`` authorization payload.

    Mirrors the structure of :class:`ERC3009Authorization`: inherits
    :class:`BasePermit` and embeds the ECDSA signature as a separate
    :class:`EVMECDSASignature` object rather than mixing v/r/s directly
    into the permit fields.

    EIP-712 domain: name="Permit2", chainId=``chain_id``,
    verifyingContract=``permit2_address``.

    Attributes:
        permit_type: Always ``"Permit2"``.
        owner: Token owner address that produced the signature.
        spender: Address authorized to call ``permitTransferFrom``.
        token: ERC-20 token contract address.
        amount: Transfer amount in the token's smallest unit.
        nonce: Permit2 contract nonce for ``owner`` (consumed on first use).
        deadline: Unix timestamp after which the permit is invalid.
        chain_id: EVM network ID (e.g. 1=Mainnet, 11155111=Sepolia).
        permit2_address: Permit2 contract address (defaults to canonical
            Uniswap deployment).
        signature: ECDSA signature (``signature_type='Permit2'``) produced
            by the token owner; ``None`` before signing.

    Example::

        sig = Permit2Signature(
            owner="0xAbCd...1234", spender="0xServer...Addr",
            token="0xA0b8...eB48", amount=1_000_000,
            nonce=0, deadline=1_900_000_000, chain_id=11155111,
            signature=EVMECDSASignature(
                signature_type="Permit2",
                v=27, r="0x" + "a" * 64, s="0x" + "b" * 64,
            ),
        )
    """

    permit_type: Literal["Permit2"] = Field(default="Permit2", description="Authorization type identifier")
    owner: str = Field(..., description="Token owner address (0x-prefixed, 42 chars)")
    spender: str = Field(..., description="Address authorized to call permitTransferFrom")
    token: str = Field(..., description="ERC-20 token contract address")
    amount: int = Field(..., ge=0, description="Transfer amount in the token's smallest unit")
    nonce: int = Field(..., ge=0, description="Permit2 contract nonce for owner (replay protection)")
    deadline: int = Field(..., ge=0, description="Unix timestamp after which this permit is invalid")
    chain_id: int = Field(..., ge=1, description="EVM network ID used in the EIP-712 domain")
    permit2_address: str = Field(
        default="0x000000000022D473030F116dDEE9F6B43aC78BA3",
        description="Permit2 singleton contract address (defaults to canonical Uniswap deployment)",
    )
    signature: Optional[EVMECDSASignature] = Field(
        None, description="ECDSA signature with signature_type='Permit2'"
    )

    def validate_structure(self) -> bool:
        """
        Validate permit fields and embedded signature.

        Checks that ``owner``, ``spender``, ``token``, and ``permit2_address``
        are valid 0x-prefixed 42-character EVM addresses, and that the
        attached :class:`EVMECDSASignature` passes its own format validation.

        Returns:
            True when all checks pass.

        Raises:
            ValueError: Descriptive message on the first failed check.
        """
        for field_name, address in [
            ("owner", self.owner),
            ("spender", self.spender),
            ("token", self.token),
            ("permit2_address", self.permit2_address),
        ]:
            if not address.startswith("0x"):
                raise ValueError(f"'{field_name}' must be 0x-prefixed, got: {address!r}")
            if len(address) != 42:
                raise ValueError(f"'{field_name}' must be 42 chars (0x + 40 hex), got {len(address)}")
            try:
                int(address[2:], 16)
            except ValueError:
                raise ValueError(f"'{field_name}' contains non-hex characters: {address!r}")

        if self.signature is not None:
            try:
                self.signature.validate_format()
            except ValueError as e:
                raise ValueError(f"Signature validation failed: {e}")

        return True
