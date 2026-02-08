from typing import Optional, List, Literal
from dataclasses import dataclass, field
from pydantic import BaseModel, Field

from .x402_utils import canonical_json


@dataclass(frozen=True)
class CryptoPaymentComponent:
    """Represents cryptocurrency payment component details.

    Attributes:
        network: Blockchain network name (e.g., 'ethereum')
        currency: Currency symbol (e.g., 'USDC')
        chain_id: Blockchain network ID
        contract_address: Optional token contract address
        decimals: Number of decimal places for the currency
    """

    network: str
    currency: str
    chain_id: int
    contract_address: Optional[str] = None
    decimals: int = 6


class X402PaymentScheme(BaseModel):
    """Defines the payment scheme structure for X402 protocol.

    Attributes:
        version: Protocol version (default: 'x402')
        to_address: Recipient wallet address
        amount: Payment amount in string format
        methods: Available payment methods
        metadata: Additional payment metadata
    """

    version: str = "x402"
    to_address: str = Field(default="")
    amount: str = Field(default="0.5")
    methods: List[CryptoPaymentComponent] = Field(
        default_factory=list, description="Payment methods"
    )
    metadata: dict = Field(default_factory=dict)


@dataclass
class X402PaymentIntent:
    """Represents a payment intent with all required transaction details.

    Attributes:
        intent_id: Unique identifier for this payment intent
        payer: Wallet address of the payer
        payee: Wallet address of the payee
        network: Blockchain network (e.g., 'ethereum')
        currency: Payment currency (fixed as USDC)
        amount: Payment amount in string format
        expiry: Unix timestamp when the intent expires
        nonce: Unique number to prevent replay attacks
        metadata: Additional transaction metadata
    """

    intent_id: str
    payer: str
    payee: str
    network: str
    currency: Literal["USDC"]
    amount: str
    expiry: int
    nonce: str
    metadata: dict

    def to_message(self) -> str:
        """Generates a canonical JSON message for signing.

        Returns:
            str: JSON string representation of the payment intent
        """
        return canonical_json(self.__dict__)


@dataclass(frozen=True)
class X402PaymentIntentWithSignature:
    intent: X402PaymentIntent
    signature: str
    signer: str

    def message(self) -> str:
        """Gets the signed message from the payment intent.

        Returns:
            str: The canonical JSON message from the intent
        """
        return self.intent.to_message()


@dataclass(frozen=True)
class PermitSignatureEIP2612:
    """EIP-2612 permit signature components.

    Attributes:
        v: Signature recovery byte
        r: First half of ECDSA signature
        s: Second half of ECDSA signature
    """

    v: int
    r: str
    s: str


@dataclass
class Permit:
    """Represents an EIP-2612 permit for token spending authorization.

    Attributes:
        token: USDC contract address
        chain_id: Blockchain network ID
        owner: Token owner's wallet address
        spender: Authorized spender's wallet address
        value: Amount of tokens to spend (matches payment intent amount)
        deadline: Unix timestamp for permit expiration
        nonce: Unique value to prevent replay attacks
        signature: EIP-2612 signature for the permit
    """

    token: str  # USDC contract
    chain_id: int
    owner: str
    spender: str
    value: int  # == intent.amount
    deadline: int
    nonce: int
    signature: PermitSignatureEIP2612

    def __post_init__(self):
        """Converts dictionary signature to PermitSignatureEIP2612 object."""
        if isinstance(self.signature, dict):
            self.signature = PermitSignatureEIP2612(**self.signature)


@dataclass(frozen=True)
class PaymentAuthorization:
    """Represents a complete payment authorization.

    Attributes:
        kind: Authorization type/version
        intent: Signed payment intent
        permit: Token spending permit
    """

    kind: Literal["x402.payment_authorization.v1"]
    intent: X402PaymentIntentWithSignature
    permit: Permit
