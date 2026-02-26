"""
EVM Blockchain Server Adapter

Provides server-side EVM blockchain operations for EIP2612 permit verification and execution.
Handles signature verification, token transfers, and on-chain state queries.

Key Features:
    - EIP2612 permit signature verification
    - On-chain permit validation (nonce, allowance, expiration)
    - Token transfer execution via permit
    - Balance and state queries

Dependencies:
    - web3.py: For blockchain RPC interaction
    - eth_account: For signature recovery and transaction signing
"""

from typing import Optional, Dict, Any, Union, Tuple, List
import time
import asyncio

from web3 import AsyncWeb3
from eth_account import Account
from web3.exceptions import TransactionNotFound
from web3.types import TxReceipt


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


from ...schemas.bases import (
    VerificationStatus,
    TransactionStatus,
)
from .schemas import (
    EVMPaymentComponent,
    EVMVerificationResult,
    EVMTransactionConfirmation,
    ERC3009Authorization,
    Permit2Signature,
)
from .signatures import sign_universal, approve_erc20, is_erc3009_currency
from .verifies import verify_universal, query_erc20_allowance
from ..bases import AdapterFactory
from .ERC20_ABI import get_balance_abi, get_erc3009_abi, get_permit2_abi
from .constants import get_rpc_url, get_private_key_from_env, get_infra_key_from_env, amount_to_value, value_to_amount, get_chain_config
from ...schemas.bases import BasePaymentComponent

# ---------------------------------------------------------------------------
# Module-level Permit2 constants
# ---------------------------------------------------------------------------

#: Canonical Uniswap Permit2 singleton address (same on all EVM networks).
_PERMIT2_ADDRESS: str = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

#: Allowance below this value triggers a fresh approval (2**128 ≈ 3.4×10^38).
#: Large enough to cover any realistic payment volume while avoiding continuous
#: re-approval transactions.
_LOW_ALLOWANCE_THRESHOLD: int = 500000

#: Maximum uint256 — used as the "infinite" approve amount.
_MAX_UINT256: int = 800000



class EVMAdapter(AdapterFactory):
    """
    EVM Blockchain Server Adapter Implementation.
    
    Provides complete server-side functionality for EVM blockchains including:
    - EIP2612 permit signature verification
    - On-chain state validation (nonce, allowance, balance, expiration)
    - Token transfer execution via signed permits
    - Balance and allowance queries
    
    This adapter validates all security constraints before executing any on-chain operations.
    All methods are designed to return clear, actionable error messages rather than raising exceptions.
    
    Key Design Features:
    - Dynamic RPC URL selection based on permit's chain_id
    - Environment-aware infrastructure key handling (evm_infra_key for premium RPC, falls back to public)
    - Private key loaded from environment (evm_private_key) during initialization
    - Lazy Web3 instance creation per blockchain interaction (ensures correct RPC endpoint)
    
    Attributes:
        account: Server's account object (initialized from evm_private_key environment variable)
        address: Checksum-formatted server account address
        _infra_key: Optional infrastructure API key for premium RPC endpoints
    
    Environment Variables:
        - evm_private_key: Server's EVM private key for signing transactions (required)
        - evm_infra_key: Optional infrastructure API key (e.g., Alchemy/Infura key)
                        If not set, falls back to public RPC endpoints
    
    Example:
        # Initialize with environment variables
        adapter = EVMServerAdapter()  # Loads evm_private_key automatically
        
        # Or explicitly provide private key (for testing)
        adapter = EVMServerAdapter(private_key="0x...")
        
        # Verify permit signature and on-chain state
        result = await adapter.verify_signature(permit, payment_requirement)
        if result.is_success():
            # Execute the permit on-chain
            confirmation = await adapter.settle(permit)
    """

    def __init__(self, private_key: Optional[str] = None, rpc_url: Optional[str] = None, request_timeout: int = 60):
        """
        Initialize EVM Server Adapter with environment-aware configuration.
        
        This constructor implements a flexible initialization pattern:
        1. Accepts optional private_key parameter (useful for testing)
        2. Falls back to evm_private_key environment variable if not provided
        3. Initializes server account from the resolved private key
        4. Loads optional infrastructure key from evm_infra_key environment variable
        
        Token address and RPC URL are NOT stored at initialization time. Instead, they are
        derived dynamically from the permit object during verify_signature() and settle() calls.
        This allows the adapter to handle multiple tokens and networks seamlessly.
        
        Args:
            private_key: Optional server's private key (0x-prefixed hex format) for explicit override.
                        If None, loads from evm_private_key environment variable.
        
        Raises:
            ValueError: If neither private_key parameter nor evm_private_key environment variable
                       are provided, or if the private key format is invalid.
        
        Note:
            The adapter stores the infra_key from environment but constructs RPC URLs dynamically
            based on chain_id from the permit. This enables efficient multi-chain support.
        """
        # Resolve private key: parameter takes precedence over environment variable
        self._resolved_pk = private_key if private_key else get_private_key_from_env()
        self._request_timeout = request_timeout
        
        if not self._resolved_pk:
            raise ValueError(
                "Private key not provided. Either pass 'private_key' parameter or "
                "set 'evm_private_key' environment variable."
            )
        
        # Initialize account from resolved private key
        self.account = Account.from_key(self._resolved_pk)
        self.wallet_address = AsyncWeb3.to_checksum_address(self.account.address)
        
        # Load optional infrastructure key for RPC endpoint construction
        self._infra_key = get_infra_key_from_env()
        self._rpc_url = rpc_url

    def _get_web3_instance(self, chain_id: int) -> AsyncWeb3:
        """
        Create and return an AsyncWeb3 instance for the specified blockchain.
        
        This method dynamically constructs the RPC URL based on:
        1. The chain_id (automatically routing to correct network)
        2. Configured infrastructure key (if available, uses premium endpoints)
        3. Fallback to public RPC endpoints (if no infrastructure key)
        
        The method handles RPC URL construction transparently, allowing the adapter
        to work with any EVM-compatible chain without storing chain-specific state.
        
        Args:
            chain_id: EVM chain ID as integer (1=Ethereum, 11155111=Sepolia, etc.)
        
        Returns:
            AsyncWeb3: Configured AsyncWeb3 instance connected to the appropriate RPC
        
        Raises:
            ValueError: If the chain_id is not supported or RPC URL cannot be determined
        
        Example:
            # Automatically uses evm_infra_key if configured
            web3 = self._get_web3_instance(1)  # Ethereum Mainnet
            balance = await web3.eth.get_balance("0x...")
        """
        # Get RPC URL with infrastructure key consideration
        rpc_url = self._rpc_url or get_rpc_url(chain_id, self._infra_key)
        
        if not rpc_url:
            raise ValueError(
                f"Unsupported chain_id: {chain_id}. "
                f"Supported chains: Ethereum (1), Sepolia (11155111)"
            )
        
        return AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(
            rpc_url,
            request_kwargs={"timeout": self._request_timeout}
        ))

    async def signature(
        self,
        payment_component: EVMPaymentComponent,
    ) -> Union[ERC3009Authorization, Permit2Signature]:
        """
        Generate a signed authorization for the given payment component.

        Scheme selection is based on the payment component's ``currency``:
        - USDC, EURC (and other ERC-3009 compatible tokens): ERC-3009
          ``transferWithAuthorization`` is preferred.
        - All other tokens: Permit2 ``permitTransferFrom`` is used as fallback.

        Signing is performed entirely in-process via ``sign_universal``.

        Args:
            payment_component: EVMPaymentComponent with token, chain, amount and
                metadata fields (``wallet_address``, ``decimals``, ``name``,
                ``version``).

        Returns:
            ``ERC3009Authorization`` when the currency supports ERC-3009;
            ``Permit2Signature`` otherwise.

        Raises:
            ValueError: If the chain is unsupported or parameters are invalid.
            TypeError: If the private key is not available.
        """
        if not self._resolved_pk:
            raise TypeError("Private key required for signing")

        # Extract permit parameters from payment component
        owner = self.wallet_address
        spender = AsyncWeb3.to_checksum_address(payment_component.metadata.get("wallet_address"))
        token = AsyncWeb3.to_checksum_address(payment_component.token)
        chain_id = int(payment_component.chain_id)
        decimals = int(payment_component.metadata.get("decimals"))

        # Validate chain support
        caip2_id = f"eip155:{chain_id}"
        chain_config = get_chain_config(caip2_id)
        if not chain_config:
            raise ValueError(f"Unsupported chain: {chain_id}")

        value = int(amount_to_value(amount=payment_component.amount, decimals=decimals))
        deadline = int(time.time()) + 600

        # Determine signing scheme based on currency
        currency = (payment_component.currency or "").upper()
        if is_erc3009_currency(currency):
            return sign_universal(
                private_key=self._resolved_pk,
                chain_id=chain_id,
                token=token,
                sender=owner,
                receiver=spender,
                amount=value,
                scheme="erc3009",
                domain_name=payment_component.metadata.get("name"),
                domain_version=str(payment_component.metadata.get("version", "2")),
                deadline=deadline,
            )
        else:
            return sign_universal(
                private_key=self._resolved_pk,
                chain_id=chain_id,
                token=token,
                sender=owner,
                receiver=spender,
                amount=value,
                scheme="permit2",
                deadline=deadline,
            )


    async def verify_signature(
        self,
        permit: Union[ERC3009Authorization, Permit2Signature],
        payment_requirement: EVMPaymentComponent,
    ) -> EVMVerificationResult:
        """
        Verify a signed authorization and validate payment constraints.

        Accepts the direct output of :meth:`signature` — either an
        ``ERC3009Authorization`` or a ``Permit2Signature`` — and verifies it
        using :func:`verify_universal`.

        Validation steps
        ----------------
        1. **Type check** - ``permit`` must be ``ERC3009Authorization`` or
           ``Permit2Signature``.
        2. **Receiver check** - the ``recipient`` / ``spender`` field must
           match the server's wallet address.
        3. **Amount check** - the authorized value (smallest token unit) must
           be ``>=`` the required amount derived from
           ``payment_requirement.amount`` (human-readable USDC).
        4. **Balance check** - the on-chain token balance of the sender must
           cover the required amount.
        5. **Signature + expiry** - delegates to :func:`verify_universal`,
           which reconstructs the EIP-712 struct, recovers the signer, and
           checks the time window / deadline.

        Amount conversion
        -----------------
        ``payment_requirement.amount`` is a human-readable USDC quantity
        (e.g. ``1.5`` for 1.5 USDC).  It is converted to the smallest token
        unit via :func:`amount_to_value` using ``payment_requirement.metadata
        ["decimals"]`` (defaults to ``6`` for USDC).

        Args:
            permit: ERC3009Authorization or Permit2Signature produced by
                :meth:`signature`.
            payment_requirement: EVMPaymentComponent describing the expected
                payment (human-readable ``amount``, ``decimals`` in metadata).

        Returns:
            EVMVerificationResult with ``is_valid=True`` and
            ``status=SUCCESS`` if all checks pass; otherwise a descriptive
            failure result.  No exceptions are raised.
        """
        # ----------------------------------------------------------------
        # 1. Type check
        # ----------------------------------------------------------------
        if not isinstance(permit, (ERC3009Authorization, Permit2Signature)):
            return EVMVerificationResult(
                status=VerificationStatus.UNKNOWN_ERROR,
                is_valid=False,
                message=(
                    f"Invalid permit type '{type(permit).__name__}'. "
                    "Expected ERC3009Authorization or Permit2Signature."
                ),
                error_details={"received_type": type(permit).__name__},
            )

        try:
            sig = permit.signature
            if sig is None:
                return EVMVerificationResult(
                    status=VerificationStatus.INVALID_SIGNATURE,
                    is_valid=False,
                    message="Permit has no signature attached.",
                    error_details={"permit_type": type(permit).__name__},
                )

            # Scheme-specific field extraction
            if isinstance(permit, ERC3009Authorization):
                sender   = permit.authorizer
                receiver = permit.recipient
                authorized_value = permit.value
                deadline  = permit.validBefore
                valid_after = permit.validAfter
                nonce     = permit.nonce          # bytes32 hex string
                scheme    = "erc3009"
                domain_name    = payment_requirement.metadata.get("name")
                domain_version = str(payment_requirement.metadata.get("version", "2"))
                permit2_address = _PERMIT2_ADDRESS
            else:  # Permit2Signature
                sender   = permit.owner
                receiver = permit.spender
                authorized_value = permit.amount
                deadline  = permit.deadline
                valid_after = 0
                nonce     = permit.nonce          # int
                scheme    = "permit2"
                domain_name    = None
                domain_version = "2"
                permit2_address = permit.permit2_address

            # ----------------------------------------------------------------
            # 2. Receiver must match server wallet
            # ----------------------------------------------------------------
            if receiver.lower() != self.wallet_address.lower():
                return EVMVerificationResult(
                    status=VerificationStatus.UNKNOWN_ERROR,
                    is_valid=False,
                    message="Receiver/spender does not match server wallet address.",
                    error_details={
                        "expected": self.wallet_address,
                        "provided": receiver,
                    },
                    sender=sender,
                    receiver=receiver,
                )

            # ----------------------------------------------------------------
            # 3. Authorized amount vs required payment amount
            #    payment_requirement.amount is human-readable USD (e.g. 1.5)
            #    authorized_value is in the token's smallest unit
            # ----------------------------------------------------------------
            decimals = int(payment_requirement.metadata.get("decimals", 6))
            required_value = int(
                amount_to_value(amount=payment_requirement.amount, decimals=decimals)
            )

            if authorized_value < required_value:
                return EVMVerificationResult(
                    status=VerificationStatus.INSUFFICIENT_ALLOWANCE,
                    is_valid=False,
                    message=(
                        f"Authorized amount ({authorized_value}) is less than "
                        f"required payment ({required_value} smallest units "
                        f"= {payment_requirement.amount} USD)."
                    ),
                    error_details={
                        "authorized_value": authorized_value,
                        "required_value": required_value,
                        "payment_amount": payment_requirement.amount,
                        "decimals": decimals,
                    },
                    sender=sender,
                    receiver=receiver,
                    authorized_amount=authorized_value,
                )

            # ----------------------------------------------------------------
            # 4. On-chain balance check
            # ----------------------------------------------------------------
            web3 = self._get_web3_instance(permit.chain_id)
            token_address = AsyncWeb3.to_checksum_address(permit.token)
            owner_balance = await self.get_balance(sender, token_address, web3)

            if owner_balance < required_value:
                return EVMVerificationResult(
                    status=VerificationStatus.INSUFFICIENT_BALANCE,
                    is_valid=False,
                    message=(
                        f"Insufficient token balance: owner has {owner_balance} "
                        f"but {required_value} smallest units are required."
                    ),
                    error_details={
                        "owner_balance": owner_balance,
                        "required_value": required_value,
                    },
                    sender=sender,
                    receiver=receiver,
                    authorized_amount=authorized_value,
                    blockchain_state={"owner_balance": owner_balance},
                )

            # ----------------------------------------------------------------
            # 5. Cryptographic signature + expiry via verify_universal
            # ----------------------------------------------------------------
            result = await verify_universal(
                v=sig.v,
                r=sig.r,
                s=sig.s,
                chain_id=permit.chain_id,
                token=token_address,
                sender=sender,
                receiver=receiver,
                amount=authorized_value,
                deadline=deadline,
                nonce=nonce,
                scheme=scheme,
                domain_name=domain_name,
                domain_version=domain_version,
                valid_after=valid_after,
                permit2_address=permit2_address,
                owner_balance=owner_balance,
                w3=web3,
            )

            return result

        except Exception as e:
            return EVMVerificationResult(
                status=VerificationStatus.BLOCKCHAIN_ERROR,
                is_valid=False,
                message=f"Verification error: {str(e)}",
                error_details={"exception": str(e)},
            )

    async def settle(
        self,
        permit: Union[ERC3009Authorization, Permit2Signature],
    ) -> EVMTransactionConfirmation:
        """
        Execute on-chain token transfer to settle a payment authorization.

        Dispatches to the appropriate settlement strategy based on permit type:

        * **ERC3009Authorization** → calls ``transferWithAuthorization`` directly
          on the token contract (ERC-3009 path, supported by USDC / EURC).
        * **Permit2Signature** → calls ``permitTransferFrom`` on the Uniswap
          Permit2 singleton contract.

        Both paths share the same receipt-polling and confirmation-building
        logic via :meth:`_send_and_confirm`.

        Chain handling is fully dynamic: the Web3 RPC instance is resolved from
        ``permit.chain_id`` at call time, with optional premium infra key.

        Args:
            permit: Signed authorization produced by :meth:`signature` — either
                ``ERC3009Authorization`` or ``Permit2Signature``.

        Returns:
            :class:`EVMTransactionConfirmation` with ``status=SUCCESS`` and
            populated receipt fields on success, or a descriptive failure result.
            No exceptions are raised; all errors are captured in the return value.
        """
        if isinstance(permit, ERC3009Authorization):
            if permit.signature is None:
                return EVMTransactionConfirmation(
                    status=TransactionStatus.INVALID_TRANSACTION,
                    tx_hash="0x",
                    error_message="ERC3009Authorization is missing signature",
                )
            try:
                web3 = self._get_web3_instance(permit.chain_id)
                tx_dict = await self._construct_erc3009_transaction(permit, web3)
                if "error" in tx_dict:
                    return EVMTransactionConfirmation(
                        status=TransactionStatus.INVALID_TRANSACTION,
                        tx_hash="0x",
                        error_message=tx_dict["error"],
                    )
                return await self._send_and_confirm(tx_dict["raw_transaction"], web3)
            except Exception as e:
                return EVMTransactionConfirmation(
                    status=TransactionStatus.NETWORK_ERROR,
                    tx_hash="0x",
                    error_message=f"ERC-3009 settlement error: {str(e)}",
                )

        elif isinstance(permit, Permit2Signature):
            try:
                web3 = self._get_web3_instance(permit.chain_id)
                tx_dict = await self._construct_permit2_transaction(permit, web3)
                if "error" in tx_dict:
                    return EVMTransactionConfirmation(
                        status=TransactionStatus.INVALID_TRANSACTION,
                        tx_hash="0x",
                        error_message=tx_dict["error"],
                    )
                return await self._send_and_confirm(tx_dict["raw_transaction"], web3)
            except Exception as e:
                return EVMTransactionConfirmation(
                    status=TransactionStatus.NETWORK_ERROR,
                    tx_hash="0x",
                    error_message=f"Permit2 settlement error: {str(e)}",
                )

        else:
            return EVMTransactionConfirmation(
                status=TransactionStatus.INVALID_TRANSACTION,
                tx_hash="0x",
                error_message=(
                    "Invalid permit type. Expected ERC3009Authorization or "
                    "Permit2Signature (the direct output of EVMAdapter.signature())"
                ),
            )


    async def get_balance(self, address: str, token_address: Optional[str] = None, web3: Optional[AsyncWeb3] = None) -> int:
        """
        Query token balance for an address on-chain.
        
        This method is designed to work in two modes:
        1. With explicit parameters (token_address and web3) - for internal use
        2. With just address - for external API use (not recommended without context)
        
        Args:
            address: Wallet address to query (0x-prefixed hex format)
            token_address: Token contract address (optional, for explicit chain/token context)
            web3: AsyncWeb3 instance (optional, created dynamically if not provided)
        
        Returns:
            int: Token balance in smallest units (0 if address has no balance or error occurs)
        
        Note:
            When called from external code without token_address and web3, the method
            cannot determine which chain to query. Consider refactoring external calls
            to provide these parameters explicitly.
        """
        try:
            address = AsyncWeb3.to_checksum_address(address)
            
            # If token_address is not provided, this method call is incomplete
            if not token_address:
                return 0
            
            token_address = AsyncWeb3.to_checksum_address(token_address)
            
            # If web3 is not provided, create a default instance (may not be correct chain)
            if not web3:
                web3 = self._get_web3_instance(1)  # Default to Ethereum mainnet
            
            contract = web3.eth.contract(
                address=token_address,
                abi=get_balance_abi()
            )
            balance = await contract.functions.balanceOf(address).call()
            return int(balance)
        except Exception:
            return 0

    def get_wallet_address(self) -> str:
        """
        Get server wallet address from private key.
        
        Returns:
            str: Server wallet address in checksum format
        """
        return self.wallet_address


    async def _construct_erc3009_transaction(
        self,
        permit: ERC3009Authorization,
        web3: AsyncWeb3,
    ) -> Dict[str, Any]:
        """
        Build and sign a ``transferWithAuthorization`` transaction (ERC-3009).

        Calls ``transferWithAuthorization(from, to, value, validAfter,
        validBefore, nonce, v, r, s)`` on the token contract using the fields
        from *permit* and the attached :class:`EVMECDSASignature`.

        Args:
            permit: :class:`ERC3009Authorization` with a populated ``signature``.
            web3:   Configured :class:`AsyncWeb3` instance for the target chain.

        Returns:
            ``{"raw_transaction": bytes}`` on success or ``{"error": str}``.
        """
        try:
            token_address = AsyncWeb3.to_checksum_address(permit.token)
            contract = web3.eth.contract(address=token_address, abi=get_erc3009_abi())

            sig = permit.signature
            r_hex = sig.r[2:] if sig.r.startswith("0x") else sig.r
            s_hex = sig.s[2:] if sig.s.startswith("0x") else sig.s
            r_bytes = bytes.fromhex(r_hex)
            s_bytes = bytes.fromhex(s_hex)

            # nonce is a bytes32 hex string in ERC-3009
            nonce_hex = permit.nonce[2:] if permit.nonce.startswith("0x") else permit.nonce
            nonce_bytes = bytes.fromhex(nonce_hex.zfill(64))

            tx_fn = contract.functions.transferWithAuthorization(
                AsyncWeb3.to_checksum_address(permit.authorizer),
                AsyncWeb3.to_checksum_address(permit.recipient),
                permit.value,
                permit.validAfter,
                permit.validBefore,
                nonce_bytes,
                sig.v,
                r_bytes,
                s_bytes,
            )

            gas_estimate = await tx_fn.estimate_gas({"from": self.wallet_address})
            gas_price = await web3.eth.gas_price
            tx_nonce = await web3.eth.get_transaction_count(self.wallet_address)

            tx_dict = await tx_fn.build_transaction({
                "from": self.wallet_address,
                "gas": int(gas_estimate * 1.1),
                "gasPrice": gas_price,
                "nonce": tx_nonce,
            })

            signed_tx = self.account.sign_transaction(tx_dict)
            return {"raw_transaction": signed_tx.raw_transaction}

        except Exception as e:
            return {"error": str(e)}

    async def _construct_permit2_transaction(
        self,
        permit: Permit2Signature,
        web3: AsyncWeb3,
    ) -> Dict[str, Any]:
        """
        Build and sign a ``permitTransferFrom`` transaction (Permit2).

        Calls Uniswap Permit2's ``permitTransferFrom(
        PermitTransferFrom permit, SignatureTransferDetails transferDetails,
        address owner, bytes signature)`` using the fields from *permit*.

        The packed bytes signature (r || s || v) is produced via
        :meth:`EVMECDSASignature.to_packed_hex` on the embedded signature.

        Args:
            permit: :class:`Permit2Signature` with all permit fields and v/r/s.
            web3:   Configured :class:`AsyncWeb3` instance for the target chain.

        Returns:
            ``{"raw_transaction": bytes}`` on success or ``{"error": str}``.
        """
        try:
            permit2_address = AsyncWeb3.to_checksum_address(permit.permit2_address)
            token_address = AsyncWeb3.to_checksum_address(permit.token)
            contract = web3.eth.contract(address=permit2_address, abi=get_permit2_abi())

            # Packed 65-byte signature: r (32) || s (32) || v (1)
            packed_hex = permit.signature.to_packed_hex()
            sig_bytes = bytes.fromhex(packed_hex[2:] if packed_hex.startswith("0x") else packed_hex)

            # PermitTransferFrom = { TokenPermissions { token, amount }, nonce, deadline }
            permit_struct = (
                (token_address, permit.amount),
                permit.nonce,
                permit.deadline,
            )
            # SignatureTransferDetails = { to, requestedAmount }
            transfer_details = (
                AsyncWeb3.to_checksum_address(permit.spender),
                permit.amount,
            )

            tx_fn = contract.functions.permitTransferFrom(
                permit_struct,
                transfer_details,
                AsyncWeb3.to_checksum_address(permit.owner),
                sig_bytes,
            )

            gas_estimate = await tx_fn.estimate_gas({"from": self.wallet_address})
            gas_price = await web3.eth.gas_price
            tx_nonce = await web3.eth.get_transaction_count(self.wallet_address)

            tx_dict = await tx_fn.build_transaction({
                "from": self.wallet_address,
                "gas": int(gas_estimate * 1.1),
                "gasPrice": gas_price,
                "nonce": tx_nonce,
            })

            signed_tx = self.account.sign_transaction(tx_dict)
            return {"raw_transaction": signed_tx.raw_transaction}

        except Exception as e:
            return {"error": str(e)}


    async def _send_and_confirm(
        self,
        raw_transaction: bytes,
        web3: AsyncWeb3,
        max_attempts: int = 60,
        poll_interval: float = 6.0,
    ) -> EVMTransactionConfirmation:
        """
        Broadcast a signed transaction and poll for its on-chain receipt.

        Sends *raw_transaction* via ``eth_sendRawTransaction``, then polls
        ``eth_getTransactionReceipt`` every *poll_interval* seconds for at
        most *max_attempts* rounds (~15 minutes at 6 s / 15 s block time).

        Args:
            raw_transaction: Signed transaction bytes from
                ``account.sign_transaction(...).raw_transaction``.
            web3:            ``AsyncWeb3`` instance for the target chain.
            max_attempts:    Maximum receipt poll attempts (default 60).
            poll_interval:   Seconds between polls (default 6).

        Returns:
            :class:`EVMTransactionConfirmation` with receipt data on success,
            or a ``TIMEOUT`` / ``NETWORK_ERROR`` / ``FAILED`` result.
        """
        try:
            tx_hash = await web3.eth.send_raw_transaction(raw_transaction)
            tx_hash_hex = tx_hash.hex()
        except Exception as e:
            return EVMTransactionConfirmation(
                status=TransactionStatus.NETWORK_ERROR,
                tx_hash="0x",
                error_message=f"Failed to broadcast transaction: {str(e)}",
            )

        # Poll for receipt
        receipt = None
        for _ in range(max_attempts):
            try:
                receipt = await web3.eth.get_transaction_receipt(tx_hash_hex)
                if receipt:
                    break
            except TransactionNotFound:
                pass  # still pending
            await self._sleep_async(poll_interval)

        if not receipt:
            return EVMTransactionConfirmation(
                status=TransactionStatus.TIMEOUT,
                tx_hash=tx_hash_hex,
                error_message="Transaction confirmation timed out",
            )

        current_block = await web3.eth.block_number
        confirmations = current_block - receipt["blockNumber"]
        transaction_fee = receipt["gasUsed"] * receipt.get("effectiveGasPrice", 0)

        if receipt.get("status") == 1:
            return EVMTransactionConfirmation(
                status=TransactionStatus.SUCCESS,
                is_valid=True,
                tx_hash=tx_hash_hex,
                block_number=receipt["blockNumber"],
                block_timestamp=int(time.time()),
                gas_used=receipt["gasUsed"],
                gas_limit=receipt.get("gas"),
                confirmations=confirmations,
                transaction_fee=transaction_fee,
                from_address=receipt.get("from"),
                to_address=receipt.get("to"),
                message="Transaction executed successfully",
            )
        else:
            return EVMTransactionConfirmation(
                status=TransactionStatus.FAILED,
                tx_hash=tx_hash_hex,
                block_number=receipt["blockNumber"],
                gas_used=receipt["gasUsed"],
                confirmations=confirmations,
                transaction_fee=transaction_fee,
                error_message="Transaction reverted on-chain",
            )

    @staticmethod
    async def _sleep_async(seconds: float):
        """Simple async sleep utility."""
        await asyncio.sleep(seconds)
        
    async def permit2_approve(
        self,
        chain_id: int,
        token_addr: str,
        values: int,
    ) -> Tuple[str, Optional[TxReceipt]]:
        """Asynchronously signs and broadcasts an ERC20 approve transaction.

        Args:
            chain_id (int): The EVM chain ID (e.g., 1 for Ethereum, 11155111 for Sepolia).
            token_addr (str): The contract address of the ERC20 token.
            values (int): The raw amount (in wei) to approve.
        """
        
        w3 = self._get_web3_instance(chain_id)
        return await approve_erc20(
            w3=w3,
            token_addr=token_addr,
            private_key=self._resolved_pk,
            spender=_PERMIT2_ADDRESS,  # Permit2 singleton address
            amount=values,
        )

    async def client_init(self, payment_components: List[BasePaymentComponent]) -> None:
        """
        EVM-specific client-side pre-signing initialisation.

        Iterates all registered EVMPaymentComponents and, for each currency
        that requires the Permit2 protocol (i.e. is NOT natively ERC-3009),
        queries the current ERC-20 allowance granted to the Permit2 singleton.
        If the allowance is below ``_LOW_ALLOWANCE_THRESHOLD``, an on-chain
        ``approve(permit2, uint256_max)`` transaction is broadcast and awaited
        before returning.

        This must be called once at startup (via AdapterHub.initialize()) before
        any signature() calls are made.  Skipped automatically for ERC-3009
        currencies (USDC, EURC, …) because those use gasless transferWithAuthorization
        and do not require a prior on-chain approval.

        Args:
            payment_components: All components returned by
                register_payment_methods().  Non-EVM items are silently skipped.

        Raises:
            RuntimeError: If any approval transaction is broadcast but reverts
                on-chain (propagated from approve_erc20).
            Web3Exception: If the RPC allowance query fails.
        """
        tasks = []
        
        for component in payment_components:
            # Skip non-EVM components (future SVM items, etc.)
            if not isinstance(component, EVMPaymentComponent):
                continue

            currency = (component.currency or "").upper()

            # ERC-3009 tokens (USDC, EURC …) use transferWithAuthorization —
            # no on-chain approval step is required for signing.
            if is_erc3009_currency(currency):
                continue

            # Permit2 path: the Permit2 contract must be approved to move
            # the token on the signer's behalf before the signature is valid.
            w3 = self._get_web3_instance(component.chain_id)
            allowance = await query_erc20_allowance(
                w3=w3,
                token_addr=component.token,
                owner=self.wallet_address,
                spender=_PERMIT2_ADDRESS,
            )

            if allowance < _LOW_ALLOWANCE_THRESHOLD:
                approval = self.permit2_approve(
                    chain_id=component.chain_id,
                    token_addr=component.token,
                    values=_MAX_UINT256,
                )
                tasks.append(approval)
                
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for tx_hash, receipt in results:
                if receipt is None or receipt.get("status") != 1:
                    raise RuntimeError(f"Approval transaction failed: {tx_hash}")
