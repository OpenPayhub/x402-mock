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

from typing import Optional, Dict, Any
import time
import asyncio
from web3 import AsyncWeb3
from eth_account import Account
from web3.exceptions import TransactionNotFound

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
    EIP2612Permit,
    EIP2612PermitSignature,
    EVMPaymentComponent,
    EVMVerificationResult,
    EVMTransactionConfirmation,
)
from ..bases import AdapterFactory
from .ERC20_ABI import get_balance_abi, get_verify_signature_abi, get_permit_abi
from .EIP2612_types import EIP712Domain, PermitMessage, EIP712TypedData
from .constants import get_rpc_url, get_private_key_from_env, get_infra_key_from_env, amount_to_value, value_to_amount, get_chain_config


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

    def __init__(self, private_key: Optional[str] = None):
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
        rpc_url = get_rpc_url(chain_id, self._infra_key)
        
        if not rpc_url:
            raise ValueError(
                f"Unsupported chain_id: {chain_id}. "
                f"Supported chains: Ethereum (1), Sepolia (11155111)"
            )
        
        return AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(rpc_url))

    async def signature(
        self,
        payment_component: EVMPaymentComponent,
    ) -> EIP2612Permit:
        """
        Generate complete signed EIP2612 permit from payment component.
        
        Args:
            payment_component: EVMPaymentComponent with permit parameters
        
        Returns:
            EIP2612Permit: Fully signed permit ready for server submission
        
        Raises:
            ValueError: If payment_component is invalid or signing fails
            TypeError: If private_key is not available
        """
        if not self._resolved_pk:
            raise TypeError("Private key required for signing")

        # Extract permit parameters from payment component
        owner = self.wallet_address
        spender = AsyncWeb3.to_checksum_address(payment_component.metadata.get("wallet_address"))
        token = AsyncWeb3.to_checksum_address(payment_component.token)
        chain_id = int(payment_component.chain_id)
        decimals = int(payment_component.metadata.get("decimals"))
        
        # Get chain config for additional context
        caip2_id = f"eip155:{chain_id}"
        chain_config = get_chain_config(caip2_id)
        if not chain_config:
            raise ValueError(f"Unsupported chain: {chain_id}")

        # Build EIP712 domain and message
        domain = EIP712Domain(
            name=payment_component.metadata.get("name"),
            version=payment_component.metadata.get("version"),
            chainId=chain_id,
            verifyingContract=token
        )
        web3 = self._get_web3_instance(chain_id)
        nonce = await self._get_on_chain_nonce(owner=owner, token_address=token, web3=web3)
        value = int(amount_to_value(amount=payment_component.amount, decimals=decimals))
        deadline = int(time.time()) + 600

        message = PermitMessage(
            owner=owner,
            spender=spender,
            value=value,
            nonce=nonce,
            deadline=deadline
        )

        typed_data = EIP712TypedData(domain=domain, message=message)

        # Sign the message
        account = Account.from_key(self._resolved_pk)
        encoded_data = encode_typed_data(typed_data.to_dict())
        signed_message = account.sign_message(encoded_data)

        # Create and return signed permit
        # Ensure r and s are 32-byte padded hex strings (EIP2612 standard)
        r_bytes = signed_message.r.to_bytes(32, "big")
        s_bytes = signed_message.s.to_bytes(32, "big")
        sig = EIP2612PermitSignature(
            signature_type="EIP2612",
            v=signed_message.v,
            r="0x" + r_bytes.hex(),
            s="0x" + s_bytes.hex()
        )

        return EIP2612Permit(
            permit_type="EIP2612",
            owner=owner,
            spender=spender,
            token=token,
            value=value,
            deadline=deadline,
            nonce=nonce,
            signature=sig,
            chain_id=chain_id
        )


    async def verify_signature(
        self,
        permit: EIP2612Permit,
        payment_requirement: EVMPaymentComponent,
    ) -> EVMVerificationResult:
        """
        Verify EIP2612 permit signature and validate all security constraints.
        
        Performs comprehensive validation:
        1. Verify permit data structure (EIP2612Permit format)
        2. Recover signer from ECDSA signature
        3. Verify recovered signer matches permit owner
        4. Check permit deadline has not expired
        5. Query on-chain nonce and verify no replay attack
        6. Query on-chain allowance and verify it covers required amount
        7. Query token balance and verify owner has sufficient funds
        8. Verify spender address matches server address
        
        Dynamic Chain Handling:
        - Automatically obtains Web3 instance for the correct blockchain using permit.chain_id
        - Constructs RPC URL with infrastructure key handling (premium RPC if available, fallback to public)
        - No chain configuration needed beyond what's in the permit
        
        Args:
            permit: BasePermit instance (must be EIP2612Permit with chain_id)
            payment_requirement: BasePaymentComponent specifying expected payment
        
        Returns:
            EVMVerificationResult: Comprehensive verification result including:
                - status: Overall verification status
                - is_valid: Boolean success indicator
                - permit_owner: Verified owner address if successful
                - authorized_amount: Verified authorized amount if successful
                - message: Human-readable status message
                - error_details: Specific error information if failed
                - on_chain_nonce: Current on-chain nonce
                - on_chain_allowance: Current on-chain allowance
                - owner_balance: Current token balance of owner
        
        Note:
            This method does NOT raise exceptions. All errors are returned in the result object.
            The chain_id and token address are extracted from the permit automatically.
        """
        # Type check - must be EIP2612Permit
        if not isinstance(permit, EIP2612Permit):
            return EVMVerificationResult(
                status=VerificationStatus.UNKNOWN_ERROR,
                is_valid=False,
                message="Invalid permit type. Expected EIP2612Permit",
                error_details={"received_type": type(permit).__name__}
            )

        try:
            # Get Web3 instance for the chain specified in permit
            web3 = self._get_web3_instance(permit.chain_id)
            token_address = AsyncWeb3.to_checksum_address(permit.token)
            
            # Validate permit structure
            try:
                permit.validate_structure()
            except ValueError as e:
                return EVMVerificationResult(
                    status=VerificationStatus.UNKNOWN_ERROR,
                    is_valid=False,
                    message=f"Invalid permit structure: {str(e)}",
                    error_details={"validation_error": str(e)}
                )

            # Verify spender address is server address
            if permit.spender.lower() != self.wallet_address.lower():
                return EVMVerificationResult(
                    status=VerificationStatus.UNKNOWN_ERROR,
                    is_valid=False,
                    message="Spender address does not match server address",
                    error_details={
                        "expected_spender": self.wallet_address,
                        "provided_spender": permit.spender
                    }
                )

            # Check permit expiration
            is_expired = permit.is_expired(int(time.time()))
            if is_expired:
                return EVMVerificationResult(
                    status=VerificationStatus.EXPIRED,
                    is_valid=False,
                    message="Permit has expired",
                    error_details={"deadline": permit.deadline, "current_time": int(time.time())}
                )

            # Recover signer from signature
            recovered_signer = await self._recover_signer_address(permit)
            if not recovered_signer:
                return EVMVerificationResult(
                    status=VerificationStatus.INVALID_SIGNATURE,
                    is_valid=False,
                    message="Failed to recover signer from signature",
                    error_details={"recovery_failed": True}
                )

            # Verify recovered signer matches permit owner
            if recovered_signer.lower() != permit.owner.lower():
                return EVMVerificationResult(
                    status=VerificationStatus.INVALID_SIGNATURE,
                    is_valid=False,
                    message="Recovered signer does not match permit owner",
                    error_details={
                        "recovered_signer": recovered_signer,
                        "permit_owner": permit.owner
                    }
                )

            # Query on-chain state
            on_chain_nonce = await self._get_on_chain_nonce(permit.owner, token_address, web3)
            on_chain_allowance = await self._get_on_chain_allowance(permit.owner, self.wallet_address, token_address, web3)
            owner_balance = await self.get_balance(permit.owner, token_address, web3)

            # Verify nonce matches (prevents replay attacks)
            if on_chain_nonce != permit.nonce:
                return EVMVerificationResult(
                    status=VerificationStatus.REPLAY_ATTACK,
                    is_valid=False,
                    message="Permit nonce does not match on-chain nonce",
                    error_details={
                        "on_chain_nonce": on_chain_nonce,
                        "permit_nonce": permit.nonce
                    },
                    on_chain_nonce=on_chain_nonce
                )

            # Verify permit allowance covers required payment
            required_value = amount_to_value(amount=payment_requirement.amount, decimals=payment_requirement.metadata.get("decimals", 6))
            if permit.value < required_value:
                return EVMVerificationResult(
                    status=VerificationStatus.INSUFFICIENT_ALLOWANCE,
                    is_valid=False,
                    message="Permit authorized amount is less than required payment",
                    error_details={
                        "permit_value": permit.value,
                        "required_value": required_value
                    },
                    on_chain_allowance=on_chain_allowance,
                    owner_balance=owner_balance
                )

            # Verify owner has sufficient balance
            if owner_balance < required_value:
                return EVMVerificationResult(
                    status=VerificationStatus.INSUFFICIENT_BALANCE,
                    is_valid=False,
                    message="Owner does not have sufficient token balance",
                    error_details={
                        "owner_balance": owner_balance,
                        "required_value": required_value
                    },
                    on_chain_nonce=on_chain_nonce,
                    on_chain_allowance=on_chain_allowance,
                    owner_balance=owner_balance
                )

            # All validations passed
            return EVMVerificationResult(
                status=VerificationStatus.SUCCESS,
                is_valid=True,
                permit_owner=permit.owner,
                authorized_amount=permit.value,
                message="Permit signature verified and all conditions met",
                on_chain_nonce=on_chain_nonce,
                on_chain_allowance=on_chain_allowance,
                owner_balance=owner_balance,
                blockchain_state={
                    "nonce": on_chain_nonce,
                    "allowance": on_chain_allowance,
                    "balance": owner_balance,
                    "chain_id": permit.chain_id
                }
            )

        except Exception as e:
            return EVMVerificationResult(
                status=VerificationStatus.BLOCKCHAIN_ERROR,
                is_valid=False,
                message=f"Blockchain interaction error: {str(e)}",
                error_details={"exception": str(e)}
            )

    async def settle(
        self,
        permit: EIP2612Permit,
    ) -> EVMTransactionConfirmation:
        """
        Execute permit transaction on-chain to settle token transfer.
        
        This method:
        1. Constructs permit() call with signature components
        2. Builds transaction with gas estimation
        3. Signs transaction with server private key
        4. Broadcasts to blockchain network
        5. Waits for confirmation
        6. Returns transaction receipt information
        
        Dynamic Chain Handling:
        - Automatically obtains Web3 instance for the correct blockchain using permit.chain_id
        - Constructs RPC URL with infrastructure key handling (premium RPC if available, fallback to public)
        - No chain configuration needed beyond what's in the permit
        
        Note: This method should only be called after verify_signature() confirms validity.
        No additional validation is performed here to avoid redundant blockchain queries.
        
        Args:
            permit: EIP2612Permit instance with valid signature (EIP2612Permit)
        
        Returns:
            EVMTransactionConfirmation: Transaction execution result with:
                - status: Transaction execution status (SUCCESS, FAILED, etc.)
                - tx_hash: Transaction hash on blockchain
                - block_number: Block containing transaction
                - block_timestamp: Block timestamp
                - gas_used: Actual gas consumed
                - confirmations: Number of block confirmations
                - error_message: Error details if execution failed
                - transaction_fee: Fee paid in wei
        
        Note:
            All errors are returned in the result object, no exceptions raised.
        """
        if not isinstance(permit, EIP2612Permit):
            return EVMTransactionConfirmation(
                status=TransactionStatus.INVALID_TRANSACTION,
                tx_hash="0x",
                error_message="Invalid permit type. Expected EIP2612Permit"
            )

        try:
            # Get Web3 instance and token address from permit
            web3 = self._get_web3_instance(permit.chain_id)
            token_address = AsyncWeb3.to_checksum_address(permit.token)
            
            # Construct and sign permit transaction
            tx_dict = await self._construct_permit_transaction(permit, token_address, web3)
            if "error" in tx_dict:
                return EVMTransactionConfirmation(
                    status=TransactionStatus.INVALID_TRANSACTION,
                    tx_hash="0x",
                    error_message=tx_dict["error"]
                )

            # Send transaction to blockchain
            tx_hash = await web3.eth.send_raw_transaction(tx_dict["raw_transaction"])
            tx_hash_hex = tx_hash.hex()

            # Wait for transaction receipt (configurable confirmations)
            max_attempts = 60  # ~15 minutes for Ethereum 15s blocks
            attempt = 0
            receipt = None
            
            while attempt < max_attempts:
                try:
                    receipt = await web3.eth.get_transaction_receipt(tx_hash_hex)
                    if receipt:
                        break
                except TransactionNotFound:
                    pass # still pending

                await self._sleep_async(6)
                attempt += 1

            if not receipt:
                return EVMTransactionConfirmation(
                    status=TransactionStatus.TIMEOUT,
                    tx_hash=tx_hash_hex,
                    error_message="Transaction confirmation timed out"
                )

            # Extract confirmation details
            current_block = await web3.eth.block_number
            confirmations = current_block - receipt["blockNumber"]
            transaction_fee = receipt["gasUsed"] * receipt.get("effectiveGasPrice", 0)

            # Check transaction status
            tx_status = receipt.get("status")
            if tx_status == 1:
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
                    message="Transaction executed successfully"
                )
            else:
                return EVMTransactionConfirmation(
                    status=TransactionStatus.FAILED,
                    tx_hash=tx_hash_hex,
                    block_number=receipt["blockNumber"],
                    gas_used=receipt["gasUsed"],
                    confirmations=confirmations,
                    transaction_fee=transaction_fee,
                    error_message="Transaction reverted on-chain"
                )

        except Exception as e:
            return EVMTransactionConfirmation(
                status=TransactionStatus.NETWORK_ERROR,
                tx_hash="0x",
                error_message=f"Network error: {str(e)}"
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

    # ========================================================================
    # Private Helper Methods
    # ========================================================================

    async def _recover_signer_address(self, permit: EIP2612Permit) -> Optional[str]:
        """
        Recover signer address from EIP2612 permit signature.
        
        Constructs EIP712 typed data and recovers the signer address using
        cryptographic signature verification.
        
        Args:
            permit: EIP2612Permit with signature components
        
        Returns:
            Optional[str]: Recovered signer address (checksum format), or None if recovery fails
        """
        domain = EIP712Domain(
            name="USDC",
            version="2",
            chainId=permit.chain_id,
            verifyingContract=permit.token
        )
        message = PermitMessage(
            owner=permit.owner,
            spender=permit.spender,
            value=permit.value,
            nonce=permit.nonce,
            deadline=permit.deadline
        )
        typed_data = EIP712TypedData(domain=domain, message=message)

        # Encode and recover
        encoded_data = encode_typed_data(typed_data.to_dict())
        recovered_address = Account.recover_message(
            encoded_data,
            vrs=(permit.signature.v, int(permit.signature.r, 16), int(permit.signature.s, 16))
        )
        return AsyncWeb3.to_checksum_address(recovered_address)


    async def _get_on_chain_nonce(self, owner: str, token_address: str, web3: AsyncWeb3) -> int:
        """
        Query current on-chain nonce counter for owner address.
        
        Args:
            owner: Token owner address
            token_address: Token contract address (checksum format)
            web3: AsyncWeb3 instance for the correct blockchain
        
        Returns:
            int: Current nonce value, or -1 if query fails
        """
        try:
            owner = AsyncWeb3.to_checksum_address(owner)
            contract = web3.eth.contract(
                address=token_address,
                abi=get_verify_signature_abi()
            )
            nonce = await contract.functions.nonces(owner).call()
            return int(nonce)
        except Exception:
            return -1

    async def _get_on_chain_allowance(self, owner: str, spender: str, token_address: str, web3: AsyncWeb3) -> int:
        """
        Query current on-chain allowance amount.
        
        Args:
            owner: Token owner address
            spender: Authorized spender address
            token_address: Token contract address (checksum format)
            web3: AsyncWeb3 instance for the correct blockchain
        
        Returns:
            int: Current allowance amount, or 0 if query fails
        """
        try:
            owner = AsyncWeb3.to_checksum_address(owner)
            spender = AsyncWeb3.to_checksum_address(spender)
            contract = web3.eth.contract(
                address=token_address,
                abi=get_verify_signature_abi()
            )
            allowance = await contract.functions.allowance(owner, spender).call()
            return int(allowance)
        except Exception:
            return 0

    async def _construct_permit_transaction(self, permit: EIP2612Permit, token_address: str, web3: AsyncWeb3) -> Dict[str, Any]:
        """
        Construct and sign permit transaction for on-chain execution.
        
        This method performs the following steps:
        1. Builds the permit() function call with signature components
        2. Estimates gas requirements for the transaction
        3. Constructs the transaction dictionary with proper nonce and gas settings
        4. Signs the transaction with the server's private key
        5. Returns the signed transaction ready for broadcasting
        
        Args:
            permit: EIP2612Permit with signature components
            token_address: Token contract address (checksum format)
            web3: AsyncWeb3 instance for the correct blockchain
        
        Returns:
            Dict with keys:
                - "raw_transaction": Signed transaction ready to send (bytes)
                - OR "error": Error message if construction failed (str)
        
        Note:
            This is an internal method and should only be called after
            permit verification in settle() method.
        """
        try:
            contract = web3.eth.contract(
                address=token_address,
                abi=get_permit_abi()
            )

            # Build permit transaction
            # Convert hex signature strings to bytes for smart contract call
            r_bytes = bytes.fromhex(permit.signature.r[2:])  # Remove '0x' prefix
            s_bytes = bytes.fromhex(permit.signature.s[2:])  # Remove '0x' prefix
            
            tx = contract.functions.permit(
                permit.owner,
                permit.spender,
                permit.value,
                permit.deadline,
                permit.signature.v,
                r_bytes,
                s_bytes
            )

            # Estimate gas
            gas_estimate = await tx.estimate_gas({"from": self.wallet_address})
            gas_price = await web3.eth.gas_price
            nonce = await web3.eth.get_transaction_count(self.wallet_address)

            # Build transaction dict with 10% gas buffer for safety
            tx_dict = await tx.build_transaction({
                "from": self.wallet_address,
                "gas": int(gas_estimate * 1.1),
                "gasPrice": gas_price,
                "nonce": nonce
            })

            # Sign transaction with server's private key
            signed_tx = self.account.sign_transaction(tx_dict)
            return {"raw_transaction": signed_tx.raw_transaction}

        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    async def _sleep_async(seconds: float):
        """Simple async sleep utility."""
        await asyncio.sleep(seconds)
