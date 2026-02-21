"""
EVM Signature Verification Helpers

Off-chain verification functions for EVM signature schemes.  Each function
accepts the raw authorization fields as individual keyword arguments (rather
than a pre-built object) so callers can feed values from any source -- a
parsed HTTP header, a database row, or a schema model -- without coupling to
a specific container type.

All cryptographic operations are performed in-process using ``eth_account``;
no RPC calls or on-chain state queries are made.  Optional on-chain state
(balance, nonce) may be supplied by the caller to enable richer semantic
checks alongside the cryptographic verification.

Current coverage
----------------
verify_erc3009_eoa
    Verify an ERC-3009 ``transferWithAuthorization`` signed by an ordinary
    EOA private key (ECDSA secp256k1).  Reconstructs the EIP-712 struct hash
    from the supplied fields, recovers the signer address from (v, r, s), and
    confirms it matches ``authorizer``.
"""

import time
from typing import Any, Dict, Literal, Optional, Union

from eth_account import Account

try:
    from eth_account.messages import encode_typed_data as _encode_typed_data
except ImportError:
    from eth_account.messages import encode_structured_data as _encode_typed_data  # type: ignore

def encode_typed_data(message):
    """Compatibility wrapper for eth-account EIP-712 typed data encoding."""
    try:
        return _encode_typed_data(full_message=message)
    except TypeError:
        return _encode_typed_data(message)

from .standards import (
    EIP712Domain,
    TransferWithAuthorizationMessage,
    ERC3009TypedData,
    Permit2TypedData,
    ERC1271ABI,
)
from .schemas import ERC3009VerificationResult, Permit2VerificationResult
from ...schemas.bases import VerificationStatus
from .constants import ERC1271_MAGIC_VALUE

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _verify_eip712_signature(
    signable,
    *,
    v: int,
    r: str,
    s: str,
    authorizer: str,
    w3=None,
) -> bool:
    """
    Verify an EIP-712 ``signable`` against ``authorizer``.

    Generic helper reused by all EIP-712-based verifiers (ERC-3009, Permit2, …).
    Tries EOA ECDSA recovery first.  If the recovered address does not match
    *and* a Web3 provider (``w3``) is supplied, falls back to an on-chain
    ERC-1271 ``isValidSignature`` call so that smart-contract wallets are
    also supported.

    Args:
        signable:   ``SignableMessage`` produced by ``encode_typed_data``.
        v:          ECDSA recovery ID.
        r:          Signature ``r`` component (0x-prefixed hex).
        s:          Signature ``s`` component (0x-prefixed hex).
        authorizer: Expected signer address (EOA or contract).
        w3:         Optional ``web3.Web3`` instance used for ERC-1271
                    contract calls.  When ``None``, only EOA verification
                    is attempted.

    Returns:
        ``True`` if the signature is valid for ``authorizer``, ``False``
        otherwise.
    """
    # ---- EOA: ECDSA recovery ----
    try:
        recovered = Account.recover_message(signable, vrs=(v, int(r, 16), int(s, 16)))
        if recovered.lower() == authorizer.lower():
            return True
    except Exception:
        pass

    # ---- ERC-1271: smart-contract wallet ----
    if w3 is not None:
        from eth_utils import keccak

        msg_hash: bytes = keccak(
            b"\x19" + signable.version + signable.header + signable.body
        )
        sig_bytes = (
            bytes.fromhex(r[2:].zfill(64))
            + bytes.fromhex(s[2:].zfill(64))
            + bytes([v])
        )
        try:
            contract = w3.eth.contract(address=authorizer, abi=ERC1271ABI().to_list())
            result: bytes = contract.functions.isValidSignature(msg_hash, sig_bytes).call()
            return result == ERC1271_MAGIC_VALUE
        except Exception:
            return False

    return False

def _is_valid_evm_address(addr: Optional[str]) -> bool:
    """
    Check whether ``addr`` is a syntactically valid EVM address.

    Accepts only 0x-prefixed, 42-character strings.  This is a format
    check only -- checksum and on-chain existence are not validated.

    Args:
        addr: Candidate address string.

    Returns:
        ``True`` if ``addr`` matches the expected format, ``False`` otherwise.
    """
    return isinstance(addr, str) and addr.startswith("0x") and len(addr) == 42


def _build_erc3009_typed_data_dict(
    *,
    token: str,
    chain_id: int,
    authorizer: str,
    recipient: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: str,
    domain_name: str,
    domain_version: str,
) -> Dict[str, Any]:
    """
    Reconstruct the EIP-712 typed-data dict for an ERC-3009 authorization.

    Uses the same ``ERC3009TypedData`` dataclass as the signing path so that
    the hash computed here is identical to the one signed by
    ``sign_erc3009_authorization``.

    Args:
        token:          ERC-20 token contract address (also ``verifyingContract``).
        chain_id:       EVM network ID.
        authorizer:     ``from`` address in the EIP-3009 type definition.
        recipient:      ``to`` address in the EIP-3009 type definition.
        value:          Transfer amount in the token's smallest unit.
        valid_after:    Unix timestamp after which the authorization is valid.
        valid_before:   Unix timestamp before which it must be submitted.
        nonce:          bytes32 hex string for replay protection.
        domain_name:    EIP-712 domain ``name`` (e.g. ``"USD Coin"``).
        domain_version: EIP-712 domain ``version`` (e.g. ``"2"``).

    Returns:
        ``dict`` compatible with ``eth_account.messages.encode_structured_data``.
    """
    domain = EIP712Domain(
        name=domain_name,
        version=domain_version,
        chainId=chain_id,
        verifyingContract=token,
    )
    message = TransferWithAuthorizationMessage(
        authorizer=authorizer,
        recipient=recipient,
        value=value,
        validAfter=valid_after,
        validBefore=valid_before,
        nonce=nonce,
    )
    return ERC3009TypedData(domain=domain, message=message).to_dict()


# ---------------------------------------------------------------------------
# ERC-3009 EOA verification
# ---------------------------------------------------------------------------

def verify_erc3009(
    *,
    token: str,
    chain_id: int,
    authorizer: str,
    recipient: str,
    value: int,
    valid_after: int,
    valid_before: int,
    nonce: str,
    v: int,
    r: str,
    s: str,
    domain_name: str,
    domain_version: str,
    owner_balance: Optional[int] = None,
    on_chain_nonce: Optional[str] = None,
    current_time: Optional[int] = None,
    w3=None,
) -> ERC3009VerificationResult:
    """
    Verify an ERC-3009 ``transferWithAuthorization`` signed by an EOA or a smart-contract wallet (ERC-1271).

    Performs the following checks in order, returning on the first failure:

    1. **Address format** -- ``authorizer`` and ``recipient`` must be
       0x-prefixed, 42-character strings.
    2. **Time window** -- ``current_time`` must satisfy
       ``valid_after < current_time < valid_before``.
    3. **Balance** -- when ``owner_balance`` is supplied, it must be
       ``>= value``.
    4. **Nonce** -- when ``on_chain_nonce`` is supplied, it is compared
       case-insensitively against ``nonce``; a mismatch indicates the
       authorization has already been used.
    5. **ECDSA recovery** -- reconstructs the EIP-712 struct hash from the
       supplied fields and recovers the signer address from (v, r, s).
       The recovered address must equal ``authorizer`` (case-insensitive).

    All five steps are pure in-process operations; no RPC call is made.
    If the EOA ECDSA check fails and a ``web3.Web3`` instance is provided,
    an ERC-1271 ``isValidSignature`` call is attempted, enabling smart-contract
    wallet (e.g. Safe, Argent) support.

    Args:
        token:          ERC-20 token contract address (0x-prefixed, 42 chars).
                        Also used as the EIP-712 ``verifyingContract``.
        chain_id:       EVM network ID (e.g. ``1`` Mainnet, ``8453`` Base).
        authorizer:     Address that signed the authorization (``from`` in EIP-3009).
        recipient:      Address that will receive the tokens (``to`` in EIP-3009).
        value:          Transfer amount in the token's smallest unit.
        valid_after:    Unix timestamp after which the authorization is valid.
        valid_before:   Unix timestamp before which it must be submitted.
        nonce:          bytes32 hex string used for replay protection.
        v:              ECDSA recovery ID (27 or 28).
        r:              Signature ``r`` component (0x-prefixed hex string).
        s:              Signature ``s`` component (0x-prefixed hex string).
        domain_name:    EIP-712 domain ``name`` exactly as registered in the
                        token contract (e.g. ``"USD Coin"`` for USDC).
        domain_version: EIP-712 domain ``version`` string (e.g. ``"2"``).
        owner_balance:  Optional current token balance of ``authorizer`` in
                        the token's smallest unit.  When provided, a balance
                        check is performed against ``value``.
        on_chain_nonce: Optional on-chain nonce (bytes32 hex string) for
                        ``authorizer``.  When provided, it is compared against
                        ``nonce`` to detect replayed or already-used
                        authorizations.
        current_time:   Optional Unix timestamp used for time-window checks.
                        Defaults to ``int(time.time())`` when omitted.
        w3:             Optional ``web3.Web3`` instance.  When supplied and
                        the EOA ECDSA check fails, an ERC-1271
                        ``isValidSignature`` call is attempted, enabling
                        smart-contract wallet (e.g. Safe, Argent) support.

    Returns:
        ``ERC3009VerificationResult`` with all diagnostic fields populated.
        ``is_valid=True`` and ``status=SUCCESS`` only when every check passes.

    Example::

        auth = sign_erc3009_authorization(
            private_key="0x...",
            token="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            chain_id=1,
            authorizer="0xYourAddress",
            recipient="0xRecipientAddress",
            value=1_000_000,
            valid_after=0,
            valid_before=1_900_000_000,
            domain_name="USD Coin",
            domain_version="2",
        )
        result = verify_erc3009_eoa(
            token=auth.token,
            chain_id=auth.chain_id,
            authorizer=auth.authorizer,
            recipient=auth.recipient,
            value=auth.value,
            valid_after=auth.validAfter,
            valid_before=auth.validBefore,
            nonce=auth.nonce,
            v=auth.signature.v,
            r=auth.signature.r,
            s=auth.signature.s,
            domain_name="USD Coin",
            domain_version="2",
        )
        assert result.is_valid
    """
    now = int(current_time) if current_time is not None else int(time.time())

    # Collect optional on-chain state for inclusion in the result.
    blockchain_state: Dict[str, Any] = {}
    if owner_balance is not None:
        blockchain_state["owner_balance"] = owner_balance
    if on_chain_nonce is not None:
        blockchain_state["on_chain_nonce"] = on_chain_nonce

    def _fail(
        status: VerificationStatus,
        message: str,
        error_details: Optional[Dict[str, Any]] = None,
    ) -> ERC3009VerificationResult:
        return ERC3009VerificationResult(
            verification_type="ERC3009",
            status=status,
            is_valid=False,
            message=message,
            error_details=error_details,
            authorizer=authorizer,
            recipient=recipient,
            authorized_amount=value,
            valid_after=valid_after,
            valid_before=valid_before,
            nonce=nonce,
            blockchain_state=blockchain_state or None,
        )

    # ------------------------------------------------------------------
    # 1. Address format
    # ------------------------------------------------------------------
    if not _is_valid_evm_address(authorizer):
        return _fail(
            VerificationStatus.INVALID_SIGNATURE,
            "Invalid authorizer address format.",
            {"authorizer": authorizer},
        )

    if not _is_valid_evm_address(recipient):
        return _fail(
            VerificationStatus.INVALID_SIGNATURE,
            "Invalid recipient address format.",
            {"recipient": recipient},
        )

    # ------------------------------------------------------------------
    # 2. Time window
    # ------------------------------------------------------------------
    if now <= int(valid_after):
        return _fail(
            VerificationStatus.INVALID_SIGNATURE,
            f"Authorization not yet valid: current_time={now} <= valid_after={valid_after}.",
            {"current_time": now, "valid_after": valid_after},
        )

    if now >= int(valid_before):
        return _fail(
            VerificationStatus.EXPIRED,
            f"Authorization has expired: current_time={now} >= valid_before={valid_before}.",
            {"current_time": now, "valid_before": valid_before},
        )

    # ------------------------------------------------------------------
    # 3. Balance sufficiency
    # ------------------------------------------------------------------
    if owner_balance is not None and int(owner_balance) < int(value):
        return _fail(
            VerificationStatus.INSUFFICIENT_BALANCE,
            f"Insufficient balance: owner_balance={owner_balance} < value={value}.",
            {"owner_balance": owner_balance, "value": value},
        )

    # ------------------------------------------------------------------
    # 4. Nonce consistency
    # ------------------------------------------------------------------
    if on_chain_nonce is not None:
        if nonce.lower() != on_chain_nonce.lower():
            return _fail(
                VerificationStatus.REPLAY_ATTACK,
                "Nonce mismatch: authorization nonce does not match on-chain nonce.",
                {"provided_nonce": nonce, "on_chain_nonce": on_chain_nonce},
            )

    # ------------------------------------------------------------------
    # 5. Signature verification (EOA ECDSA or ERC-1271 smart-contract wallet)
    # ------------------------------------------------------------------
    try:
        typed_data_dict = _build_erc3009_typed_data_dict(
            token=token,
            chain_id=chain_id,
            authorizer=authorizer,
            recipient=recipient,
            value=value,
            valid_after=valid_after,
            valid_before=valid_before,
            nonce=nonce,
            domain_name=domain_name,
            domain_version=domain_version,
        )
        signable = encode_typed_data(typed_data_dict)
        sig_verified = _verify_eip712_signature(
            signable, v=v, r=r, s=s, authorizer=authorizer, w3=w3
        )
    except Exception as exc:
        return _fail(
            VerificationStatus.INVALID_SIGNATURE,
            f"Signature recovery failed: {exc}",
            {"error": str(exc)},
        )

    if not sig_verified:
        return _fail(
            VerificationStatus.INVALID_SIGNATURE,
            "Signature invalid: signer does not match authorizer.",
            {"expected": authorizer},
        )

    # ------------------------------------------------------------------
    # All checks passed.
    # ------------------------------------------------------------------
    return ERC3009VerificationResult(
        verification_type="ERC3009",
        status=VerificationStatus.SUCCESS,
        is_valid=True,
        message="Authorization valid: signer verified as authorizer.",
        authorizer=authorizer,
        recipient=recipient,
        authorized_amount=value,
        valid_after=valid_after,
        valid_before=valid_before,
        nonce=nonce,
        blockchain_state=blockchain_state or None,
    )


# ---------------------------------------------------------------------------
# Permit2 verification
# ---------------------------------------------------------------------------

def verify_permit2(
    *,
    owner: str,
    spender: str,
    token: str,
    amount: int,
    nonce: int,
    deadline: int,
    chain_id: int,
    v: int,
    r: str,
    s: str,
    permit2_address: str = "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    owner_balance: Optional[int] = None,
    current_time: Optional[int] = None,
    w3=None,
) -> Permit2VerificationResult:
    """
    Verify a Permit2 ``permitTransferFrom`` authorization.

    Performs checks in order, returning on the first failure:

    1. **Address format** -- ``owner``, ``spender``, ``token``, and
       ``permit2_address`` must be 0x-prefixed 42-character strings.
    2. **Deadline** -- ``current_time`` must be strictly less than
       ``deadline``.
    3. **Balance** -- when ``owner_balance`` is supplied it must be
       ``>= amount``.
    4. **Signature** -- reconstructs the Permit2 EIP-712 struct hash and
       verifies via EOA ECDSA recovery.  If that fails and ``w3`` is
       provided, falls back to an ERC-1271 ``isValidSignature`` call.

    Args:
        owner:           Token owner address (signer of the permit).
        spender:         Address authorised to call ``permitTransferFrom``.
        token:           ERC-20 token contract address.
        amount:          Transfer amount in the token's smallest unit.
        nonce:           Permit2 integer nonce for ``owner`` (consumed on use).
        deadline:        Unix timestamp after which the permit is invalid.
        chain_id:        EVM network ID.
        v:               ECDSA recovery ID (27 or 28).
        r:               Signature ``r`` component (0x-prefixed hex).
        s:               Signature ``s`` component (0x-prefixed hex).
        permit2_address: Permit2 singleton contract address.
        owner_balance:   Optional current token balance of ``owner``; when
                         provided a ``balance >= amount`` check is performed.
        current_time:    Optional Unix timestamp for deadline checks.
                         Defaults to ``int(time.time())``.
        w3:              Optional ``web3.Web3`` instance enabling ERC-1271
                         smart-contract wallet fallback.

    Returns:
        ``Permit2VerificationResult`` with all diagnostic fields populated.
    """
    now = int(current_time) if current_time is not None else int(time.time())

    blockchain_state: Dict[str, Any] = {}
    if owner_balance is not None:
        blockchain_state["owner_balance"] = owner_balance

    def _fail(
        status: VerificationStatus,
        message: str,
        error_details: Optional[Dict[str, Any]] = None,
    ) -> Permit2VerificationResult:
        return Permit2VerificationResult(
            verification_type="Permit2",
            status=status,
            is_valid=False,
            message=message,
            error_details=error_details,
            owner=owner,
            spender=spender,
            authorized_amount=amount,
            deadline=deadline,
            nonce=nonce,
            blockchain_state=blockchain_state or None,
        )

    # ------------------------------------------------------------------
    # 1. Address format
    # ------------------------------------------------------------------
    for field_name, addr in [
        ("owner", owner),
        ("spender", spender),
        ("token", token),
        ("permit2_address", permit2_address),
    ]:
        if not _is_valid_evm_address(addr):
            return _fail(
                VerificationStatus.INVALID_SIGNATURE,
                f"Invalid {field_name} address format.",
                {field_name: addr},
            )

    # ------------------------------------------------------------------
    # 2. Deadline
    # ------------------------------------------------------------------
    if now >= int(deadline):
        return _fail(
            VerificationStatus.EXPIRED,
            f"Permit has expired: current_time={now} >= deadline={deadline}.",
            {"current_time": now, "deadline": deadline},
        )

    # ------------------------------------------------------------------
    # 3. Balance sufficiency
    # ------------------------------------------------------------------
    if owner_balance is not None and int(owner_balance) < int(amount):
        return _fail(
            VerificationStatus.INSUFFICIENT_BALANCE,
            f"Insufficient balance: owner_balance={owner_balance} < amount={amount}.",
            {"owner_balance": owner_balance, "amount": amount},
        )

    # ------------------------------------------------------------------
    # 4. Signature verification (EOA ECDSA or ERC-1271 smart-contract wallet)
    # ------------------------------------------------------------------
    try:
        typed_data_dict = Permit2TypedData(
            chain_id=chain_id,
            verifying_contract=permit2_address,
            spender=spender,
            token=token,
            amount=amount,
            nonce=nonce,
            deadline=deadline,
        ).to_dict()
        signable = encode_typed_data(typed_data_dict)
        sig_verified = _verify_eip712_signature(
            signable, v=v, r=r, s=s, authorizer=owner, w3=w3
        )
    except Exception as exc:
        return _fail(
            VerificationStatus.INVALID_SIGNATURE,
            f"Signature recovery failed: {exc}",
            {"error": str(exc)},
        )

    if not sig_verified:
        return _fail(
            VerificationStatus.INVALID_SIGNATURE,
            "Signature invalid: signer does not match owner.",
            {"expected": owner},
        )

    # ------------------------------------------------------------------
    # All checks passed.
    # ------------------------------------------------------------------
    return Permit2VerificationResult(
        verification_type="Permit2",
        status=VerificationStatus.SUCCESS,
        is_valid=True,
        message="Permit valid: signer verified as owner.",
        owner=owner,
        spender=spender,
        authorized_amount=amount,
        deadline=deadline,
        nonce=nonce,
        blockchain_state=blockchain_state or None,
    )


# ---------------------------------------------------------------------------
# Universal verifier
# ---------------------------------------------------------------------------

def verify_universal(
    *,
    # --- Signature components (required for both schemes) ---
    v: int,
    r: str,
    s: str,
    chain_id: int,
    # --- Scheme selector: auto-detected when None ---
    # "erc3009" is selected when domain_name is provided;
    # "permit2" is selected when deadline is provided without domain_name.
    scheme: Optional[Literal["erc3009", "permit2"]] = None,
    # --- ERC-3009 fields ---
    token: Optional[str] = None,
    authorizer: Optional[str] = None,
    recipient: Optional[str] = None,
    value: Optional[int] = None,
    valid_after: Optional[int] = None,
    valid_before: Optional[int] = None,
    nonce: Optional[Any] = None,          # str (bytes32) for ERC-3009, int for Permit2
    domain_name: Optional[str] = None,
    domain_version: Optional[str] = None,
    on_chain_nonce: Optional[str] = None,
    # --- Permit2 fields ---
    owner: Optional[str] = None,
    spender: Optional[str] = None,
    amount: Optional[int] = None,
    deadline: Optional[int] = None,
    permit2_address: str = "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    # --- Shared optional fields ---
    owner_balance: Optional[int] = None,
    current_time: Optional[int] = None,
    w3=None,
) -> Union[ERC3009VerificationResult, Permit2VerificationResult]:
    """
    Unified entry point for ERC-3009 and Permit2 signature verification.

    Scheme selection
    ----------------
    Pass ``scheme="erc3009"`` or ``scheme="permit2"`` to be explicit.
    When ``scheme`` is omitted the function auto-detects:

    - ``domain_name`` present  →  ERC-3009
    - ``deadline`` present, ``domain_name`` absent  →  Permit2
    - Neither present  →  ``ValueError``

    Parameters
    ----------
    v, r, s :       ECDSA signature components (required for both schemes).
    chain_id :      EVM network ID.
    scheme :        Optional explicit scheme selector.
    token :         ERC-20 token address (ERC-3009 domain / Permit2 token field).
    authorizer :    ERC-3009 signer address (``from``).
    recipient :     ERC-3009 destination address (``to``).
    value :         ERC-3009 transfer amount.
    valid_after :   ERC-3009 start timestamp.
    valid_before :  ERC-3009 expiry timestamp.
    nonce :         ``str`` (bytes32) for ERC-3009; ``int`` for Permit2.
    domain_name :   EIP-712 domain name (ERC-3009 only, e.g. ``"USD Coin"``).
    domain_version: EIP-712 domain version (ERC-3009 only, e.g. ``"2"``).
    on_chain_nonce: On-chain nonce for replay detection (ERC-3009 only).
    owner :         Permit2 token owner / signer address.
    spender :       Permit2 authorised spender address.
    amount :        Permit2 transfer amount.
    deadline :      Permit2 expiry timestamp.
    permit2_address:Permit2 singleton contract address.
    owner_balance : Optional token balance of the signer for a balance check.
    current_time :  Optional Unix timestamp (defaults to ``int(time.time())``).
    w3 :            Optional ``web3.Web3`` instance for ERC-1271 fallback.

    Returns
    -------
    ``ERC3009VerificationResult`` or ``Permit2VerificationResult`` depending
    on the resolved scheme.

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
        # Validate required ERC-3009 fields
        missing = [
            name for name, val in [
                ("token", token), ("authorizer", authorizer),
                ("recipient", recipient), ("value", value),
                ("valid_after", valid_after), ("valid_before", valid_before),
                ("nonce", nonce), ("domain_name", domain_name),
                ("domain_version", domain_version),
            ] if val is None
        ]
        if missing:
            raise ValueError(f"ERC-3009 verification missing required fields: {missing}")

        return verify_erc3009(
            token=token, chain_id=chain_id, authorizer=authorizer,
            recipient=recipient, value=value, valid_after=valid_after,
            valid_before=valid_before, nonce=nonce, v=v, r=r, s=s,
            domain_name=domain_name, domain_version=domain_version,
            owner_balance=owner_balance, on_chain_nonce=on_chain_nonce,
            current_time=current_time, w3=w3,
        )

    # resolved == "permit2"
    missing = [
        name for name, val in [
            ("owner", owner), ("spender", spender), ("token", token),
            ("amount", amount), ("nonce", nonce), ("deadline", deadline),
        ] if val is None
    ]
    if missing:
        raise ValueError(f"Permit2 verification missing required fields: {missing}")

    return verify_permit2(
        owner=owner, spender=spender, token=token, amount=amount,
        nonce=nonce, deadline=deadline, chain_id=chain_id, v=v, r=r, s=s,
        permit2_address=permit2_address, owner_balance=owner_balance,
        current_time=current_time, w3=w3,
    )

