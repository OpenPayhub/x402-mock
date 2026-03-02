"""
EVM Signature Verification Helpers

Off-chain verification functions for EVM signature schemes.  Each function
accepts the raw authorization fields as individual keyword arguments (rather
than a pre-built object) so callers can feed values from any source -- a
parsed HTTP header, a database row, or a schema model -- without coupling to
a specific container type.

All cryptographic operations are performed in-process using ``eth_account``.
When a Web3 provider is supplied, some verifiers may also perform lightweight
on-chain checks (e.g. ERC-1271 wallet validation, or querying a token's
``DOMAIN_SEPARATOR``) to prevent late settlement failures. Optional on-chain
state (balance, nonce) may also be supplied by the caller to enable richer
semantic checks alongside the cryptographic verification.

Current coverage
----------------
verify_erc3009_eoa
    Verify an ERC-3009 ``transferWithAuthorization`` signed by an ordinary
    EOA private key (ECDSA secp256k1).  Reconstructs the EIP-712 struct hash
    from the supplied fields, recovers the signer address from (v, r, s), and
    confirms it matches ``authorizer``.
"""

import time
from typing import Any, Dict, Literal, Optional, Union, Tuple

from eth_account import Account
from web3.exceptions import Web3Exception
from web3 import AsyncWeb3

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
from .ERC20_ABI import get_allowance_abi
from .schemas import EVMVerificationResult
from ...schemas.bases import VerificationStatus
from .constants import ERC1271_MAGIC_VALUE

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _verify_eip712_signature(
    signable,
    *,
    v: int,
    r: str,
    s: str,
    authorizer: str,
    w3: Optional[AsyncWeb3] = None,
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

            result: bytes = await contract.functions.isValidSignature(msg_hash, sig_bytes).call()
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


async def _query_eip712_domain_separator(
    w3: AsyncWeb3,
    *,
    token: str,
) -> bytes:
    """
    Query an ERC-20 token's EIP-712 domain separator on-chain.

    Many EIP-712 / permit-style tokens expose a ``DOMAIN_SEPARATOR()`` view
    function. Some expose ``domainSeparator()`` instead. This helper tries
    both to support common variants.

    Args:
        w3:    AsyncWeb3 instance connected to the target chain.
        token: Token contract address.

    Returns:
        The domain separator as raw 32-byte value.

    Raises:
        Exception: If neither selector is available or the call fails.
    """
    checksum_token = w3.to_checksum_address(token)

    abi_domain_separator = [
        {
            "name": "DOMAIN_SEPARATOR",
            "type": "function",
            "stateMutability": "view",
            "inputs": [],
            "outputs": [{"name": "", "type": "bytes32"}],
        }
    ]
    contract = w3.eth.contract(address=checksum_token, abi=abi_domain_separator)
    try:
        return bytes(await contract.functions.DOMAIN_SEPARATOR().call())
    except Exception:
        # Fallback selector used by some contracts.
        abi_domain_separator_fallback = [
            {
                "name": "domainSeparator",
                "type": "function",
                "stateMutability": "view",
                "inputs": [],
                "outputs": [{"name": "", "type": "bytes32"}],
            }
        ]
        contract = w3.eth.contract(
            address=checksum_token, abi=abi_domain_separator_fallback
        )
        return bytes(await contract.functions.domainSeparator().call())


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

async def verify_erc3009(
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
) -> EVMVerificationResult:
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

    Cryptographic checks are performed in-process. When a ``web3.Web3`` instance
    is provided, the verifier may also perform on-chain validation steps such as
    querying ``DOMAIN_SEPARATOR()`` to ensure the supplied EIP-712 domain
    parameters match the token contract (preventing late settlement failures).
    If the EOA ECDSA check fails and ``w3`` is provided, an ERC-1271
    ``isValidSignature`` call is attempted, enabling smart-contract wallet
    (e.g. Safe, Argent) support.

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
        ``EVMVerificationResult`` with all diagnostic fields populated.
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
    ) -> EVMVerificationResult:
        return EVMVerificationResult(
            status=status,
            is_valid=False,
            message=message,
            error_details=error_details,
            sender=authorizer,
            receiver=recipient,
            authorized_amount=value,
            blockchain_state=blockchain_state or None,
        )

    # ------------------------------------------------------------------
    # 1. Address format
    # ------------------------------------------------------------------
    if not _is_valid_evm_address(token):
        return _fail(
            VerificationStatus.INVALID_SIGNATURE,
            "Invalid token address format.",
            {"token": token},
        )

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
    except Exception as exc:
        return _fail(
            VerificationStatus.INVALID_SIGNATURE,
            f"Failed to encode EIP-712 typed data: {exc}",
            {"error": str(exc)},
        )

    # Optional: cross-check the off-chain EIP-712 domain against the token's
    # on-chain ``DOMAIN_SEPARATOR``. This catches mismatched domain fields
    # (token address / name / version / chainId) early, rather than letting the
    # later on-chain settlement fail with an "invalid signature" revert.
    if w3 is not None:
        try:
            on_chain_separator = await _query_eip712_domain_separator(w3, token=token)
        except Exception as exc:
            return _fail(
                VerificationStatus.BLOCKCHAIN_ERROR,
                f"Failed to query token DOMAIN_SEPARATOR: {exc}",
                {"token": token, "error": str(exc)},
            )

        expected_separator = bytes(signable.header)
        if expected_separator != on_chain_separator:
            return _fail(
                VerificationStatus.INVALID_SIGNATURE,
                "EIP-712 domain mismatch: provided token/name/version/chain_id do not match the token contract.",
                {
                    "token": token,
                    "chain_id": chain_id,
                    "domain_name": domain_name,
                    "domain_version": domain_version,
                    "expected_domain_separator": "0x" + expected_separator.hex(),
                    "on_chain_domain_separator": "0x" + on_chain_separator.hex(),
                },
            )

    try:
        sig_verified = await _verify_eip712_signature(
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
    return EVMVerificationResult(
        status=VerificationStatus.SUCCESS,
        is_valid=True,
        message="Authorization valid: signer verified as authorizer.",
        sender=authorizer,
        receiver=recipient,
        authorized_amount=value,
        blockchain_state=blockchain_state or None,
    )


# ---------------------------------------------------------------------------
# Permit2 verification
# ---------------------------------------------------------------------------

async def verify_permit2(
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
) -> EVMVerificationResult:
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
        ``EVMVerificationResult`` with all diagnostic fields populated.
    """
    now = int(current_time) if current_time is not None else int(time.time())

    blockchain_state: Dict[str, Any] = {}
    if owner_balance is not None:
        blockchain_state["owner_balance"] = owner_balance

    def _fail(
        status: VerificationStatus,
        message: str,
        error_details: Optional[Dict[str, Any]] = None,
    ) -> EVMVerificationResult:
        return EVMVerificationResult(
            status=status,
            is_valid=False,
            message=message,
            error_details=error_details,
            sender=owner,
            receiver=spender,
            authorized_amount=amount,
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

    allowance = await query_erc20_allowance(
        w3=w3, token_addr=token, owner=owner, spender=permit2_address
    )
    if allowance < int(amount):
        return _fail(
            VerificationStatus.INSUFFICIENT_ALLOWANCE,
            f"Insufficient allowance: current allowance={allowance} < amount={amount}.",
            {"allowance": allowance, "amount": amount},
        )
    
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
        sig_verified = await _verify_eip712_signature(
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
    return EVMVerificationResult(
        status=VerificationStatus.SUCCESS,
        is_valid=True,
        message="Permit valid: signer verified as owner.",
        sender=owner,
        receiver=spender,
        authorized_amount=amount,
        blockchain_state=blockchain_state or None,
    )


async def query_erc20_allowance(w3: AsyncWeb3, token_addr: str, owner: str, spender: str) -> int:
    """
    Retrieves the amount of tokens that an owner allowed a spender to withdraw.

    This function calls the 'allowance(address,address)' constant method of an ERC20 
    smart contract. It performs checksum address conversion and handles potential 
    exceptions during the RPC call.

    Args:
        w3 (AsyncWeb3): The Web3 instance connected to the target blockchain.
        token_addr (str): The contract address of the ERC20 token.
        owner (str): The address of the token holder.
        spender (str): The address authorized to spend the tokens.

    Returns:
        int: The remaining allowance amount in the token's base units (e.g., wei).

    Raises:
        ValueError: If any provided address is not a valid hex address.
        Web3Exception: If the contract call fails or the node returns an error.
        Exception: For any other unexpected errors during execution.
    """
    erc20_abi = get_allowance_abi()

    try:
        # Checksum conversion (raises ValueError if invalid)
        checksum_token = w3.to_checksum_address(token_addr)
        checksum_owner = w3.to_checksum_address(owner)
        checksum_spender = w3.to_checksum_address(spender)

        contract = w3.eth.contract(address=checksum_token, abi=erc20_abi)
        
        # Execute call (raises Web3Exception or specific RPC errors)
        allowance = await contract.functions.allowance(checksum_owner, checksum_spender).call()
        return int(allowance)

    except Web3Exception as e:
        # Detailed context for RPC/Contract errors
        raise Web3Exception(
            f"Failed to query allowance for token {token_addr}. "
            f"Owner: {owner}, Spender: {spender}. Error: {e}"
        )
    except Exception as e:
        # Catch-all for unexpected issues (e.g., encoding errors)
        raise RuntimeError(f"An unexpected error occurred: {e}")



# ---------------------------------------------------------------------------
# Universal verifier
# ---------------------------------------------------------------------------

async def verify_universal(
    *,
    # ---- Required: signature components --------------------------------
    v: int,
    r: str,
    s: str,
    # ---- Required: shared fields ----------------------------------------
    chain_id: int,
    token: str,
    sender: str,           # authorizer (ERC-3009) / owner (Permit2)
    receiver: str,         # recipient  (ERC-3009) / spender (Permit2)
    amount: int,
    deadline: int,         # valid_before (ERC-3009) / deadline (Permit2)
    nonce: Union[int, str],  # bytes32 hex / int accepted for both schemes
    # ---- Scheme discriminator -------------------------------------------
    # Providing domain_name selects ERC-3009; omitting it selects Permit2.
    scheme: Optional[Literal["erc3009", "permit2"]] = None,
    # ---- Optional overrides (sensible defaults provided) ----------------
    domain_name: Optional[str] = None,   # required for ERC-3009
    domain_version: str = "2",
    valid_after: int = 0,
    on_chain_nonce: Optional[str] = None,  # ERC-3009 replay detection only
    permit2_address: str = "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    # ---- Shared optional ------------------------------------------------
    owner_balance: Optional[int] = None,
    current_time: Optional[int] = None,
    w3=None,
) -> EVMVerificationResult:
    """
    Unified entry point for ERC-3009 and Permit2 signature verification.

    Uses the same homogeneous parameter names as ``sign_universal``:

    +-----------+-------------------+-----------+
    | Unified   | ERC-3009          | Permit2   |
    +===========+===================+===========+
    | sender    | authorizer        | owner     |
    +-----------+-------------------+-----------+
    | receiver  | recipient         | spender   |
    +-----------+-------------------+-----------+
    | amount    | value             | amount    |
    +-----------+-------------------+-----------+
    | deadline  | valid_before      | deadline  |
    +-----------+-------------------+-----------+
    | nonce     | bytes32 hex / int | int       |
    +-----------+-------------------+-----------+

    Scheme selection
    ----------------
    - ``domain_name`` provided, or ``scheme="erc3009"``  →  ERC-3009
    - ``domain_name`` absent,  or ``scheme="permit2"``   →  Permit2

    Parameters
    ----------
    v, r, s :        ECDSA signature components.
    chain_id :       EVM network ID.
    token :          ERC-20 token contract address.
    sender :         Signer / token owner address.
    receiver :       Destination / authorised spender address.
    amount :         Transfer amount in the token's smallest unit.
    deadline :       Expiry Unix timestamp (``valid_before`` for ERC-3009).
    nonce :          Replay-protection nonce — bytes32 hex string or int.
                     ERC-3009 uses ``str``; Permit2 uses ``int``;
                     both formats are accepted and normalised internally.
    scheme :         Optional explicit scheme override.
    domain_name :    EIP-712 domain name (required for ERC-3009).
    domain_version : EIP-712 domain version; defaults to ``"2"``.
    valid_after :    ERC-3009 start timestamp; defaults to ``0``.
    on_chain_nonce : ERC-3009 on-chain nonce for replay detection (optional).
    permit2_address: Permit2 singleton contract address.
    owner_balance :  Optional token balance for a sufficiency check.
    current_time :   Optional Unix timestamp (defaults to ``int(time.time())``).
    w3 :             Optional ``web3.Web3`` instance for ERC-1271 fallback.

    Returns
    -------
    ``EVMVerificationResult``.

    Raises
    ------
    ValueError
        If ERC-3009 is selected but ``domain_name`` is not provided.

    Examples
    --------
    ERC-3009::

        result = verify_universal(
            v=auth.signature.v, r=auth.signature.r, s=auth.signature.s,
            chain_id=1, token="0xA0b869...",
            sender="0xFrom", receiver="0xTo",
            amount=1_000_000, deadline=1_900_000_000,
            nonce=auth.nonce, domain_name="USD Coin",
        )

    Permit2::

        result = verify_universal(
            v=sig.v, r=sig.r, s=sig.s,
            chain_id=1, token="0xA0b869...",
            sender="0xOwner", receiver="0xSpender",
            amount=1_000_000, deadline=1_900_000_000,
            nonce=sig.nonce,
        )
    """
    resolved_scheme = scheme or ("erc3009" if domain_name is not None else "permit2")

    if resolved_scheme.lower() == "erc3009":
        if domain_name is None:
            raise ValueError(
                "ERC-3009 requires 'domain_name' (the EIP-712 domain name "
                "registered in the token contract, e.g. \"USD Coin\")."
            )

        # Normalise nonce → bytes32 hex string.
        erc3009_nonce: str
        if isinstance(nonce, int):
            erc3009_nonce = "0x" + nonce.to_bytes(32, "big").hex()
        else:
            erc3009_nonce = nonce

        return await verify_erc3009(
            token=token, chain_id=chain_id,
            authorizer=sender, recipient=receiver,
            value=amount, valid_after=valid_after, valid_before=deadline,
            nonce=erc3009_nonce, v=v, r=r, s=s,
            domain_name=domain_name, domain_version=domain_version,
            owner_balance=owner_balance, on_chain_nonce=on_chain_nonce,
            current_time=current_time, w3=w3,
        )

    # resolved_scheme == "permit2"
    # Normalise nonce → int.
    permit2_nonce: int
    if isinstance(nonce, str):
        permit2_nonce = int(nonce, 16) if nonce.startswith("0x") else int(nonce)
    else:
        permit2_nonce = nonce

    return await verify_permit2(
        owner=sender, spender=receiver, token=token,
        amount=amount, nonce=permit2_nonce, deadline=deadline,
        chain_id=chain_id, v=v, r=r, s=s,
        permit2_address=permit2_address, owner_balance=owner_balance,
        current_time=current_time, w3=w3,
    )
    
