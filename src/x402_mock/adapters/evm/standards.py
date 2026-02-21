from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


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
# EIP-3009: Transfer With Authorization
# -----------------------------


@dataclass
class TransferWithAuthorizationMessage:
    """
    Represents the message payload for EIP-3009 "TransferWithAuthorization".

    This dataclass mirrors the typed fields required by the EIP-3009
    structured data specification. Note that the EIP defines the field
    name `from` which is a Python reserved word; this class uses
    `authorizer` as the attribute name and maps it to `from` in
    `to_dict()`.

    Attributes:
        authorizer: Address of the account authorizing the transfer (maps to `from`).
        recipient: Address receiving the tokens (maps to `to`).
        value: Amount of tokens to transfer (uint256).
        validAfter: Unix timestamp after which the authorization becomes valid.
        validBefore: Unix timestamp before which the authorization expires.
        nonce: A unique nonce (bytes32 hex string) preventing replay.
    """
    authorizer: str
    recipient: str
    value: int
    validAfter: int
    validBefore: int
    nonce: str

    def to_dict(self) -> Dict[str, Any]:
        """Return a dictionary representation compatible with EIP-712 signing.

        The returned keys follow the names required by the EIP-3009 typed
        definition (i.e. `from`, `to`, `value`, `validAfter`, `validBefore`, `nonce`).
        """
        return {
            "from": self.authorizer,
            "to": self.recipient,
            "value": self.value,
            "validAfter": self.validAfter,
            "validBefore": self.validBefore,
            "nonce": self.nonce,
        }


@dataclass
class ERC3009TypedData:
    """
    Container for ERC-3009 typed data usable with EIP-712 signing routines.

    This class provides the `to_dict()` helper producing a dict compatible
    with most `signTypedData` implementations: it includes `types`,
    `primaryType`, `domain` and `message` entries.

    Attributes:
        domain: EIP712Domain instance describing the signing domain.
        message: TransferWithAuthorizationMessage instance carrying the payload.
        primary_type: The primary EIP-712 type (defaults to "TransferWithAuthorization").
        types: The typed definitions required by EIP-712 (automatically set).
    """
    domain: EIP712Domain
    message: TransferWithAuthorizationMessage

    primary_type: str = "TransferWithAuthorization"

    types: Dict[str, List[Dict[str, str]]] = field(
        default_factory=lambda: {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        }
    )

    def to_dict(self) -> Dict[str, Any]:
        """Return a dictionary compatible with EIP-712 structured signing.

        The returned structure follows the conventional layout consumed by
        EIP-712 signing libraries: { types, primaryType, domain, message }.
        """
        return {
            "types": self.types,
            "primaryType": self.primary_type,
            "domain": self.domain.to_dict(),
            "message": self.message.to_dict(),
        }


# -----------------------------
# ERC-1271: Contract-based signature validation objects
# -----------------------------

@dataclass
class ERC1271ABI:
    """
    ABI definition for the ERC-1271 ``isValidSignature`` function.

    Encodes the single function entry required to call
    ``isValidSignature(bytes32 _hash, bytes _signature) returns (bytes4)``
    on any contract implementing the ERC-1271 standard.

    Use ``to_dict()`` to obtain the raw ABI entry dict, or ``to_list()``
    to get the full ABI list accepted by ``web3.eth.contract``.
    """

    def to_dict(self) -> Dict[str, Any]:
        """Return the ``isValidSignature`` ABI entry as a dict."""
        return {
            "inputs": [
                {"name": "_hash", "type": "bytes32"},
                {"name": "_signature", "type": "bytes"},
            ],
            "name": "isValidSignature",
            "outputs": [{"name": "", "type": "bytes4"}],
            "stateMutability": "view",
            "type": "function",
        }

    def to_list(self) -> List[Dict[str, Any]]:
        """Return the full ABI as a list compatible with ``web3.eth.contract``."""
        return [self.to_dict()]


@dataclass
class ERC1271Signature:
    """
    Representation of an on-chain signature verification request for a contract
    implementing ERC-1271.

    This dataclass is a simple container describing the minimal pieces of
    information needed to express a signature verification request against
    a contract that conforms to ERC-1271. It purposely does not implement
    any verification logic — it only represents data.

    Attributes:
        contract: Address of the ERC-1271 contract that will verify the signature.
        message_hash: Hash of the message (bytes32 hex string) passed to `isValidSignature`.
        signature: The signature bytes (hex string, 0x-prefixed) to be checked.
        message: Optional raw message data that was signed (as hex string or utf-8 string).
    """

    contract: str
    message_hash: str
    signature: str
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict suitable for serialization or logging."""
        return {
            "contract": self.contract,
            "message": self.message,
            "signature": self.signature,
            "message_hash": self.message_hash,
        }


# -----------------------------
# EIP-6492: On-chain signature provenance / proof objects
# -----------------------------


@dataclass
class ERC6492Proof:
    """
    Represents a generic proof object produced under EIP-6492-style schemes.

    This dataclass models a proof bundle that accompanies a signature or
    authorization and demonstrates how the signature or key material can be
    constructed or verified on-chain. The exact semantics of each field are
    intentionally left generic to avoid coupling this representation to any
    single proof scheme; consumers of the object can serialize and interpret
    the inner values as needed.

    Attributes:
        proof_type: A short identifier describing the proof scheme (e.g. "merkle", "delegation").
        root: Root digest associated with the proof (hex string).
        siblings: Optional list of sibling hashes or intermediate nodes (hex strings).
        signer: Address or identifier of the signer this proof is associated with.
        aux_data: Optional free-form auxiliary data needed to interpret the proof.
    """

    proof_type: str
    root: str
    siblings: Optional[List[str]] = None
    signer: Optional[str] = None
    aux_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict representation of the proof."""
        return {
            "proof_type": self.proof_type,
            "root": self.root,
            "siblings": self.siblings,
            "signer": self.signer,
            "aux_data": self.aux_data,
        }


@dataclass
class ERC6492GeneratedObject:
    """
    Container for an object produced when generating ERC-6492-style proofs.

    This object ties a specific data payload (for example, a signature or
    an authorization) to a proof describing why or how that payload is
    considered valid under a particular on-chain verification scheme.

    Attributes:
        subject: The hex-encoded subject of the proof (e.g. signature, key, or payload digest).
        proof: An `ERC6492Proof` instance describing the provenance or construction.
        metadata: Optional dictionary for any additional, arbitrary metadata.
    """

    subject: str
    proof: ERC6492Proof
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain dict suitable for serialization or transport."""
        return {
            "subject": self.subject,
            "proof": self.proof.to_dict(),
            "metadata": self.metadata,
        }


# -----------------------------
# Permit2: PermitTransferFrom typed data
# -----------------------------


@dataclass
class Permit2TypedData:
    """
    EIP-712 typed-data container for a Permit2 ``permitTransferFrom`` authorization.

    Encapsulates all runtime fields (chain, addresses, amounts, nonce, deadline)
    together with the canonical Permit2 type definitions.  ``to_dict()`` produces
    a structure directly consumable by ``eth_account.sign_typed_data`` and
    ``eth_signTypedData_v4``.

    The domain follows the canonical Permit2 convention: ``name="Permit2"`` with
    no ``version`` field.  Types embed both ``PermitTransferFrom`` and its nested
    ``TokenPermissions`` sub-struct.

    Attributes:
        chain_id:            EVM network ID (e.g. ``1`` Mainnet, ``8453`` Base).
        verifying_contract:  Permit2 singleton contract address.
        spender:             Address authorised to call ``permitTransferFrom``.
        token:               ERC-20 token contract address.
        amount:              Transfer amount in the token's smallest unit.
        nonce:               Permit2 nonce for the owner; consumed on first use.
        deadline:            Unix timestamp after which the permit is invalid.
        types:               EIP-712 type schema (pre-populated with the Permit2
                             domain, ``PermitTransferFrom``, and ``TokenPermissions``
                             definitions; rarely needs to be overridden).
    """

    chain_id: int
    verifying_contract: str
    spender: str
    token: str
    amount: int
    nonce: int
    deadline: int

    types: Dict[str, List[Dict[str, str]]] = field(
        default_factory=lambda: {
            "EIP712Domain": [
                {"name": "name",              "type": "string"},
                {"name": "chainId",           "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "PermitTransferFrom": [
                {"name": "permitted", "type": "TokenPermissions"},
                {"name": "spender",   "type": "address"},
                {"name": "nonce",     "type": "uint256"},
                {"name": "deadline",  "type": "uint256"},
            ],
            "TokenPermissions": [
                {"name": "token",  "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
        }
    )

    def to_dict(self) -> Dict[str, Any]:
        """Return a dict compatible with EIP-712 structured signing.

        The returned structure follows the conventional layout consumed by
        EIP-712 signing libraries: { types, primaryType, domain, message }.
        """
        return {
            "types": self.types,
            "primaryType": "PermitTransferFrom",
            "domain": {
                "name": "Permit2",
                "chainId": self.chain_id,
                "verifyingContract": self.verifying_contract,
            },
            "message": {
                "permitted": {
                    "token": self.token,
                    "amount": self.amount,
                },
                "spender": self.spender,
                "nonce": self.nonce,
                "deadline": self.deadline,
            },
        }
            
            
