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
import time
from typing import Literal, Optional, Union, Tuple
from web3.types import TxReceipt

from eth_account import Account
from web3 import AsyncWeb3

from .standards import (
    EIP712Domain,
    TransferWithAuthorizationMessage,
    ERC3009TypedData,
    Permit2TypedData,
)
from .schemas import ERC3009Authorization, EVMECDSASignature, Permit2Signature
from .ERC20_ABI import get_approve_abi

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
        ``Permit2Signature`` with all permit fields set and ``signature``
        populated.  Call ``.signature.to_packed_hex()`` to obtain the packed
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
        packed_sig = sig.signature.to_packed_hex()  # ready for on-chain submission
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
        owner=owner,
        spender=spender,
        token=token,
        amount=amount,
        nonce=nonce,
        deadline=deadline,
        chain_id=chain_id,
        permit2_address=permit2_address,
        signature=EVMECDSASignature(
            signature_type="Permit2",
            v=signed.v,
            r=hex(signed.r),
            s=hex(signed.s),
        ),
    )


# ---------------------------------------------------------------------------
# Universal signer
# ---------------------------------------------------------------------------

def sign_universal(
    *,
    # ---- Required --------------------------------------------------------
    private_key: str,
    chain_id: int,
    token: str,
    sender: str,           # authorizer (ERC-3009) / owner (Permit2)
    receiver: str,         # recipient  (ERC-3009) / spender (Permit2)
    amount: int,
    # ---- Scheme discriminator --------------------------------------------
    # Providing domain_name selects ERC-3009; omitting it selects Permit2.
    # Pass scheme= explicitly to override auto-detection.
    scheme: Optional[Literal["erc3009", "permit2"]] = None,
    # ---- Optional overrides (all have sensible defaults) -----------------
    domain_name: Optional[str] = None,   # required for ERC-3009
    domain_version: str = "2",
    deadline: Optional[int] = None,      # defaults to now + 1 hour
    valid_after: int = 0,
    nonce: Optional[Union[int, str]] = None,
    permit2_address: str = "0x000000000022D473030F116dDEE9F6B43aC78BA3",
) -> Union[ERC3009Authorization, Permit2Signature]:
    """
    Unified entry point for ERC-3009 and Permit2 signing.

    Callers supply only the five essential parameters
    (``private_key``, ``chain_id``, ``token``, ``sender``, ``receiver``,
    ``amount``); everything else is inferred or defaulted automatically:

    +-----------------+----------------------------------------------+
    | Parameter       | Default                                      |
    +=================+==============================================+
    | deadline        | ``int(time.time()) + 3600``  (now + 1 hour) |
    +-----------------+----------------------------------------------+
    | valid_after     | ``0``  (immediately valid)                   |
    +-----------------+----------------------------------------------+
    | domain_version  | ``"2"``                                      |
    +-----------------+----------------------------------------------+
    | nonce           | random bytes32 (ERC-3009) / ``0`` (Permit2)  |
    +-----------------+----------------------------------------------+

    Scheme selection
    ----------------
    - ``domain_name`` provided, or ``scheme="erc3009"``  →  ERC-3009
    - ``domain_name`` absent,  or ``scheme="permit2"``   →  Permit2

    Parameters
    ----------
    private_key :    Hex-encoded secp256k1 private key (with or without ``0x``).
    chain_id :       EVM network ID.
    token :          ERC-20 token contract address.
    sender :         Token owner / authorizer address.
    receiver :       Destination / authorised spender address.
    amount :         Transfer amount in the token's smallest unit.
    scheme :         Optional explicit scheme override.
    domain_name :    EIP-712 domain name (required for ERC-3009,
                     e.g. ``"USD Coin"`` for USDC).
    domain_version : EIP-712 domain version string; defaults to ``"2"``.
    deadline :       Expiry Unix timestamp; defaults to now + 3600 s.
    valid_after :    ERC-3009 start timestamp; defaults to ``0``.
    nonce :          Replay-protection nonce.  ERC-3009 accepts a bytes32 hex
                     string or an ``int`` (zero-padded); auto-generated when
                     ``None``.  Permit2 accepts an ``int``; defaults to ``0``.
    permit2_address: Permit2 singleton contract address.

    Returns
    -------
    ``ERC3009Authorization`` or ``Permit2Signature`` depending on scheme.

    Raises
    ------
    ValueError
        If ERC-3009 is selected but ``domain_name`` is not provided.

    Examples
    --------
    ERC-3009 (all defaults, only domain_name added)::

        auth = sign_universal(
            private_key="0xKEY", chain_id=1,
            token="0xA0b869...", sender="0xFrom", receiver="0xTo",
            amount=1_000_000, domain_name="USD Coin",
        )

    Permit2 (fully defaulted)::

        sig = sign_universal(
            private_key="0xKEY", chain_id=1,
            token="0xA0b869...", sender="0xOwner", receiver="0xSpender",
            amount=1_000_000,
        )
    """
    resolved_scheme = scheme or ("erc3009" if domain_name is not None else "permit2")
    resolved_deadline = deadline if deadline is not None else int(time.time()) + 3600

    if resolved_scheme.lower() == "erc3009":
        if domain_name is None:
            raise ValueError(
                "ERC-3009 requires 'domain_name' (the EIP-712 domain name "
                "registered in the token contract, e.g. \"USD Coin\")."
            )

        # Normalise nonce → bytes32 hex string or None (auto-generate inside).
        erc3009_nonce: Optional[str]
        if nonce is None:
            erc3009_nonce = None
        elif isinstance(nonce, int):
            erc3009_nonce = "0x" + nonce.to_bytes(32, "big").hex()
        else:
            erc3009_nonce = nonce

        return sign_erc3009_authorization(
            private_key=private_key, token=token, chain_id=chain_id,
            authorizer=sender, recipient=receiver, value=amount,
            valid_after=valid_after, valid_before=resolved_deadline,
            domain_name=domain_name, domain_version=domain_version,
            nonce=erc3009_nonce,
        )

    # resolved_scheme == "permit2"
    # Normalise nonce → int. Default: a time-based + random nonce to avoid reuse.
    permit2_nonce: int
    if nonce is None:
        # Use milliseconds timestamp shifted left and mix 16 random bits to reduce collision risk
        rand16 = int.from_bytes(os.urandom(2), "big")
        permit2_nonce = (int(time.time() * 1000) << 16) | rand16
    elif isinstance(nonce, str):
        permit2_nonce = int(nonce, 16) if nonce.startswith("0x") else int(nonce)
    else:
        permit2_nonce = nonce

    return sign_permit2(
        private_key=private_key, owner=sender, spender=receiver,
        token=token, amount=amount, nonce=permit2_nonce,
        deadline=resolved_deadline, chain_id=chain_id,
        permit2_address=permit2_address,
    )


async def approve_erc20(
    w3: AsyncWeb3, 
    token_addr: str, 
    private_key: str, 
    spender: str, 
    amount: int, 
    wait: bool = True
) -> Tuple[str, Optional[TxReceipt]]:
    """
    Asynchronously signs and broadcasts an ERC20 approve transaction.
    
    Args:
        w3: An instance of AsyncWeb3.
        token_addr: The contract address of the ERC20 token.
        private_key: The hex string private key of the sender.
        spender: The address authorized to spend the tokens.
        amount: The raw amount (in wei) to approve.
        wait: If True, waits for the transaction receipt before returning.

    Returns:
        A tuple of (transaction_hash_hex, transaction_receipt).
    """
    if not private_key:
        raise ValueError("Private key is required for signing.")

    approve_abi = get_approve_abi()
    
    # Setup account and contract
    account = Account.from_key(private_key)
    sender_addr = account.address
    token_checksum = w3.to_checksum_address(token_addr)
    spender_checksum = w3.to_checksum_address(spender)
    contract = w3.eth.contract(address=token_checksum, abi=approve_abi)

    # Build base transaction parameters
    nonce = await w3.eth.get_transaction_count(sender_addr)
    chain_id = await w3.eth.chain_id
    
    tx_params = {
        "chainId": chain_id,
        "from": sender_addr,
        "nonce": nonce,
    }

    # Gas estimation with 10% buffer for safety
    try:
        gas_estimate = await contract.functions.approve(
            spender_checksum, amount
        ).estimate_gas({"from": sender_addr})
        tx_params["gas"] = int(gas_estimate * 1.1)
    except Exception as e:
        # Fallback to a standard limit if estimation fails (common if balance is 0)
        tx_params["gas"] = 100000

    # Dynamic Gas Fee Handling (EIP-1559)
    try:
        fee_history = await w3.eth.fee_history(1, "latest", [25.0])
        base_fee = fee_history["baseFeePerGas"][-1]
        priority_fee = fee_history["reward"][0][0]
        
        # Max fee includes a buffer for base fee volatility (2x base + priority)
        tx_params["maxPriorityFeePerGas"] = priority_fee
        tx_params["maxFeePerGas"] = (base_fee * 2) + priority_fee
    except Exception:
        # Fallback to Legacy Gas Price
        tx_params["gasPrice"] = await w3.eth.gas_price

    # Build, Sign and Send
    transaction = await contract.functions.approve(
        spender_checksum, amount
    ).build_transaction(tx_params)
    
    signed_tx = w3.eth.account.sign_transaction(transaction, private_key)
    tx_hash = await w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_hex = tx_hash.hex()

    if wait:
        # Defaults to 120s timeout; raises TimeExhausted if not mined
        receipt = await w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] == 0:
            raise RuntimeError(f"Transaction failed: {tx_hex}")
        return tx_hex, receipt

    return tx_hex, None


def is_erc3009_currency(currency: str) -> bool:
    """
    Determines whether the given currency symbol natively supports ERC-3009.

    ERC-3009 (transferWithAuthorization) is primarily implemented by Circle's 
    stablecoins, allowing for gasless transfers via signed authorizations. 
    Tokens not on this list will typically fall back to the Permit2 protocol.

    Args:
        currency: Uppercase currency / token symbol (e.g., "USDC", "EURC").

    Returns:
        bool: True if the token natively supports ERC-3009; False otherwise.
    """
    # ERC-3009 is a standard for 'Transfer via Authorization'.
    # The most prominent implementations are by Circle (USDC/EURC).
    # Some other regulated stablecoins or newer tokens may also adopt this.
    
    erc3009_supported_symbols = {
        "USDC",  # USD Coin (Circle)
        "EURC",  # Euro Coin (Circle)
        "USDbC", # USDC on Base (bridged version often maintains compatibility)
        "AXLUSDC", # Axelar USDC
    }

    # Normalize input to uppercase to handle 'usdc' or 'Usdc'
    return currency.upper() in erc3009_supported_symbols
    # return False

