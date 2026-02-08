from dataclasses import dataclass, field
from typing import Dict, Any, List


# -----------------------------
# EIP-712 Domain
# -----------------------------

@dataclass
class EIP712Domain:
    """
    EIP-712 domain separator.
    Used to prevent signature replay across domains.
    """
    name: str
    version: str
    chainId: int
    verifyingContract: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "chainId": self.chainId,
            "verifyingContract": self.verifyingContract,
        }


# -----------------------------
# Permit Message (EIP-2612)
# -----------------------------

@dataclass
class PermitMessage:
    """
    Permit message as defined in EIP-2612.
    Represents token allowance authorization.
    """
    owner: str
    spender: str
    value: int
    nonce: int
    deadline: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner": self.owner,
            "spender": self.spender,
            "value": self.value,
            "nonce": self.nonce,
            "deadline": self.deadline,
        }


# -----------------------------
# EIP-712 Typed Data Wrapper
# -----------------------------

@dataclass
class EIP712TypedData:
    """
    Generic EIP-712 typed data container.
    This object can be directly passed to signTypedData.
    """
    domain: EIP712Domain
    message: PermitMessage

    primary_type: str = "Permit"

    types: Dict[str, List[Dict[str, str]]] = field(
        default_factory=lambda: {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
            ],
        }
    )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the typed data into a dict compatible with EIP-712 signing.
        """
        return {
            "types": self.types,
            "primaryType": self.primary_type,
            "domain": self.domain.to_dict(),
            "message": self.message.to_dict(),
        }


@dataclass
class EIP2612PermitSign:
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
class EIP2612PermitTypedData:
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
    signature: EIP2612PermitSign

    def __post_init__(self):
        """Converts dictionary signature to PermitSignatureEIP2612 object."""
        if isinstance(self.signature, dict):
            self.signature = EIP2612PermitSign(**self.signature)    