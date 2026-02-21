"""
EVM Off-Chain Signing Utilities

Local EIP-712 signing helpers for ERC-3009 ``transferWithAuthorization``
and Permit2 ``permitTransferFrom``.  All cryptographic operations are
performed in-process using ``eth_account``; no RPC calls or on-chain state
queries are made.

Exported helpers
----------------
sign_erc3009_authorization
    Build the EIP-712 payload, sign with a private key, and return a
    complete ``ERC3009Authorization`` with ``EVMECDSASignature`` (v, r, s).

sign_permit2
    Build the Permit2 EIP-712 payload, sign with a private key, and return
    a complete ``Permit2Signature`` with v, r, s and all permit fields.

build_erc3009_typed_data
    Low-level helper that wraps an ``ERC3009Authorization`` in an
    ``ERC3009TypedData`` envelope without signing.  Useful when the signing
    step is handled externally (e.g. a hardware wallet or MPC service).
"""

import os
from typing import Literal, Optional, Union

from eth_account import Account

from .standards import (
    EIP712Domain,
    TransferWithAuthorizationMessage,
    ERC3009TypedData,
    Permit2TypedData,
)
from .schemas import ERC3009Authorization, EVMECDSASignature, Permit2Signature


# ---------------------------------------------------------------------------
# Low-level typed-data builder (ERC-3009)
# ---------------------------------------------------------------------------

def build_erc3009_typed_data(
    authorization: ERC3009Authorization,
    *,
    domain_name: str,
    domain_version: str,
) -> ERC3009TypedData:
    """
    Wrap an ``ERC3009Authorization`` in an EIP-712 ``ERC3009TypedData`` envelope
    without signing.

    Use this when signing is handled externally (e.g. a hardware wallet or
    MPC service).  For the common in-process case, prefer
    ``sign_erc3009_authorization``.

    Args:
        authorization:  An ``ERC3009Authorization`` instance (unsigned is fine).
        domain_name:    EIP-712 domain ``name`` as stored in the token contract
                        (e.g. ``"USD Coin"`` for USDC).
        domain_version: EIP-712 domain ``version`` string (e.g. ``"2"``).

    Returns:
        ``ERC3009TypedData`` whose ``to_dict()`` is compatible with
        ``eth_account.sign_typed_data`` and ``eth_signTypedData_v4``.

    Example::

        typed_data = build_erc3009_typed_data(
            authorization,
            domain_name="USD Coin",
            domain_version="2",
        )
        payload = typed_data.to_dict()   # hand off to external signer
    """
    domain = EIP712Domain(
        name=domain_name,
        version=domain_version,
        chainId=authorization.chain_id,
        verifyingContract=authorization.token,
    )
    message = TransferWithAuthorizationMessage(
        authorizer=authorization.authorizer,
        recipient=authorization.recipient,
        value=authorization.value,
        validAfter=authorization.validAfter,
        validBefore=authorization.validBefore,
        nonce=authorization.nonce,
    )
    return ERC3009TypedData(domain=domain, message=message)


# ---------------------------------------------------------------------------
# ERC-3009 signer
# ---------------------------------------------------------------------------

def sign_erc3009_authorization(
    *,
    private_key: str,
    token: str,
    chain_id: int,
    authorizer: str,
    recipient: str,
    value: int,
    valid_after: int,
    valid_before: int,
    domain_name: str,
    domain_version: str,
    nonce: Optional[str] = None,
) -> ERC3009Authorization:
    """
    Sign an ERC-3009 ``transferWithAuthorization`` payload and return a
    complete ``ERC3009Authorization`` with the signature attached.

    Signing is performed entirely in-process via ``eth_account``; no RPC
    endpoint or network connection is required.  The EIP-712 structured-data
    hash is computed from the token's domain separator and the authorization
    message fields, then signed with the supplied private key to produce the
    canonical (v, r, s) ECDSA components.

    Args:
        private_key:    Hex-encoded secp256k1 private key of the authorizer
                        (with or without ``0x`` prefix).
        token:          ERC-20 token contract address (0x-prefixed, 42 chars).
                        Also used as the EIP-712 ``verifyingContract``.
        chain_id:       EVM network ID (e.g. ``1`` Mainnet, ``8453`` Base).
        authorizer:     Address that owns the tokens and is authorising the
                        transfer (``from`` in the EIP-3009 type definition).
                        Must match the address derived from ``private_key``.
        recipient:      Address that will receive the tokens
                        (``to`` in the EIP-3009 type definition).
        value:          Amount to transfer in the token's smallest unit.
        valid_after:    Unix timestamp after which the authorisation is valid.
                        Pass ``0`` for immediate validity.
        valid_before:   Unix timestamp before which the authorisation must be
                        submitted on-chain.
        domain_name:    EIP-712 domain ``name`` exactly as registered in the
                        token contract (e.g. ``"USD Coin"`` for USDC).
        domain_version: EIP-712 domain ``version`` string (e.g. ``"2"``).
        nonce:          Optional bytes32 hex string for replay protection.
                        A cryptographically random nonce is generated
                        automatically when omitted.

    Returns:
        ``ERC3009Authorization`` with ``signature`` populated (v, r, s).

    Raises:
        ValueError: If ``valid_after >= valid_before``.

    Example::

        auth = sign_erc3009_authorization(
            private_key="0xYOUR_PRIVATE_KEY",
            token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            chain_id=1,
            authorizer="0xYourAddress",
            recipient="0xRecipientAddress",
            value=1_000_000,            # 1 USDC (6 decimals)
            valid_after=0,
            valid_before=1_900_000_000,
            domain_name="USD Coin",
            domain_version="2",
        )
        # auth.signature contains v, r, s — ready for on-chain submission
    """
    if valid_after >= valid_before:
        raise ValueError(
            f"valid_after ({valid_after}) must be strictly less than "
            f"valid_before ({valid_before})"
        )

    resolved_nonce = nonce if nonce is not None else "0x" + os.urandom(32).hex()

    # Build the unsigned authorization object.
    authorization = ERC3009Authorization(
        token=token,
        chain_id=chain_id,
        authorizer=authorizer,
        recipient=recipient,
        value=value,
        validAfter=valid_after,
        validBefore=valid_before,
        nonce=resolved_nonce,
    )

    # Construct the EIP-712 typed-data envelope and sign it locally.
    typed_data = build_erc3009_typed_data(
        authorization,
        domain_name=domain_name,
        domain_version=domain_version,
    )
    signed = Account.sign_typed_data(private_key, full_message=typed_data.to_dict())

    # Attach the resulting ECDSA components to the authorization.
    authorization.signature = EVMECDSASignature(
        signature_type="ERC3009",
        v=signed.v,
        r=hex(signed.r),
        s=hex(signed.s),
    )

    return authorization


# ---------------------------------------------------------------------------
# Permit2 signer
# ---------------------------------------------------------------------------

def sign_permit2(
    *,
    private_key: str,
    owner: str,
    spender: str,
    token: str,
    amount: int,
    nonce: int,
    deadline: int,
    chain_id: int,
    permit2_address: str = "0x000000000022D473030F116dDEE9F6B43aC78BA3",
) -> Permit2Signature:
    """
    Sign a Permit2 ``permitTransferFrom`` authorization and return a
    ``Permit2Signature`` with v, r, s attached.

    Signing is performed entirely in-process via ``eth_account``.  The
    EIP-712 structured-data hash follows the canonical Permit2 domain
    (``name="Permit2"``, no ``version`` field) and the
    ``PermitTransferFrom`` type with a nested ``TokenPermissions`` sub-struct.

    Args:
        private_key:     Hex-encoded secp256k1 private key of the token owner
                         (with or without ``0x`` prefix).
        owner:           Token owner address (0x-prefixed, 42 chars).
                         Must match the address derived from ``private_key``.
        spender:         Address authorised to call ``permitTransferFrom``
                         (typically the settlement server).
        token:           ERC-20 token contract address.
        amount:          Transfer amount in the token's smallest unit.
        nonce:           Permit2 nonce for ``owner``; consumed on first use,
                         preventing replay.
        deadline:        Unix timestamp after which the permit is invalid.
        chain_id:        EVM network ID (e.g. ``1`` Mainnet, ``8453`` Base).
        permit2_address: Permit2 singleton contract address.  Defaults to the
                         canonical Uniswap deployment
                         ``0x000000000022D473030F116dDEE9F6B43aC78BA3``.

    Returns:
        ``Permit2Signature`` with ``v``, ``r``, ``s`` populated and all
        permit fields set.  Call ``.to_packed_hex()`` to obtain the packed
        ``bytes`` argument for the on-chain ``permitTransferFrom`` call.

    Example::

        sig = sign_permit2(
            private_key="0xYOUR_PRIVATE_KEY",
            owner="0xYourAddress",
            spender="0xServerAddress",
            token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            amount=1_000_000,            # 1 USDC (6 decimals)
            nonce=0,
            deadline=1_900_000_000,
            chain_id=1,
        )
        packed_sig = sig.to_packed_hex()  # ready for on-chain submission
    """
    typed_data = Permit2TypedData(
        chain_id=chain_id,
        verifying_contract=permit2_address,
        spender=spender,
        token=token,
        amount=amount,
        nonce=nonce,
        deadline=deadline,
    )

    signed = Account.sign_typed_data(private_key, full_message=typed_data.to_dict())

    return Permit2Signature(
        v=signed.v,
        r=hex(signed.r),
        s=hex(signed.s),
        owner=owner,
        spender=spender,
        token=token,
        amount=amount,
        nonce=nonce,
        deadline=deadline,
        chain_id=chain_id,
        permit2_address=permit2_address,
    )


# ---------------------------------------------------------------------------
# Universal signer
# ---------------------------------------------------------------------------

def sign_universal(
    *,
    private_key: str,
    chain_id: int,
    token: str,
    # --- Scheme selector: auto-detected when None ---
    # "erc3009" is selected when domain_name is provided;
    # "permit2" is selected when deadline is provided without domain_name.
    scheme: Optional[Literal["erc3009", "permit2"]] = None,
    # --- ERC-3009 fields ---
    authorizer: Optional[str] = None,
    recipient: Optional[str] = None,
    value: Optional[int] = None,
    valid_after: Optional[int] = None,
    valid_before: Optional[int] = None,
    domain_name: Optional[str] = None,
    domain_version: Optional[str] = None,
    nonce: Optional[str] = None,          # bytes32 hex str; auto-generated if None
    # --- Permit2 fields ---
    owner: Optional[str] = None,
    spender: Optional[str] = None,
    amount: Optional[int] = None,
    permit2_nonce: Optional[int] = None,  # int nonce for Permit2
    deadline: Optional[int] = None,
    permit2_address: str = "0x000000000022D473030F116dDEE9F6B43aC78BA3",
) -> Union[ERC3009Authorization, Permit2Signature]:
    """
    Unified entry point for ERC-3009 and Permit2 signing.

    Scheme selection
    ----------------
    Pass ``scheme="erc3009"`` or ``scheme="permit2"`` to be explicit.
    When ``scheme`` is omitted the function auto-detects:

    - ``domain_name`` present  →  ERC-3009
    - ``deadline`` present, ``domain_name`` absent  →  Permit2
    - Neither present  →  ``ValueError``

    Parameters
    ----------
    private_key :    Hex-encoded secp256k1 private key (with or without ``0x``).
    chain_id :       EVM network ID.
    token :          ERC-20 token contract address (required for both schemes).
    scheme :         Optional explicit scheme selector.
    authorizer :     ERC-3009 signer / token owner address (``from``).
    recipient :      ERC-3009 destination address (``to``).
    value :          ERC-3009 transfer amount in the token's smallest unit.
    valid_after :    ERC-3009 start timestamp (``0`` for immediate validity).
    valid_before :   ERC-3009 expiry timestamp.
    domain_name :    EIP-712 domain name (ERC-3009 only, e.g. ``"USD Coin"``).
    domain_version : EIP-712 domain version (ERC-3009 only, e.g. ``"2"``).
    nonce :          ERC-3009 bytes32 hex nonce; auto-generated when ``None``.
    owner :          Permit2 token owner address.
    spender :        Permit2 authorised spender address.
    amount :         Permit2 transfer amount in the token's smallest unit.
    permit2_nonce :  Permit2 integer nonce for ``owner`` (consumed on first use).
    deadline :       Permit2 expiry timestamp.
    permit2_address: Permit2 singleton contract address.

    Returns
    -------
    ``ERC3009Authorization`` (with signature attached) or ``Permit2Signature``
    depending on the resolved scheme.

    Raises
    ------
    ValueError
        When the scheme cannot be inferred or required fields are missing.
    """
    # ---- Resolve scheme ----
    resolved = scheme
    if resolved is None:
        if domain_name is not None:
            resolved = "erc3009"
        elif deadline is not None:
            resolved = "permit2"
        else:
            raise ValueError(
                "Cannot infer scheme: supply 'domain_name' for ERC-3009, "
                "'deadline' for Permit2, or set 'scheme' explicitly."
            )

    if resolved == "erc3009":
        missing = [
            name for name, val in [
                ("authorizer", authorizer), ("recipient", recipient),
                ("value", value), ("valid_after", valid_after),
                ("valid_before", valid_before), ("domain_name", domain_name),
                ("domain_version", domain_version),
            ] if val is None
        ]
        if missing:
            raise ValueError(f"ERC-3009 signing missing required fields: {missing}")

        return sign_erc3009_authorization(
            private_key=private_key, token=token, chain_id=chain_id,
            authorizer=authorizer, recipient=recipient, value=value,
            valid_after=valid_after, valid_before=valid_before,
            domain_name=domain_name, domain_version=domain_version,
            nonce=nonce,
        )

    # resolved == "permit2"
    missing = [
        name for name, val in [
            ("owner", owner), ("spender", spender),
            ("amount", amount), ("permit2_nonce", permit2_nonce),
            ("deadline", deadline),
        ] if val is None
    ]
    if missing:
        raise ValueError(f"Permit2 signing missing required fields: {missing}")

    return sign_permit2(
        private_key=private_key, owner=owner, spender=spender,
        token=token, amount=amount, nonce=permit2_nonce,
        deadline=deadline, chain_id=chain_id,
        permit2_address=permit2_address,
    )
