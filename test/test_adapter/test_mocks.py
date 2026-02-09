"""
EVM Adapter Test Mocks Module

Provides comprehensive mock data and utilities for testing EVM adapter functionality.
This module contains all mock objects, constants, and helper functions needed to test
the EVMAdapter without requiring actual blockchain connectivity.

Key Components:
    - Mock EVM addresses, private keys, and chain configurations
    - Mock EIP2612 permit signatures and permits with valid cryptographic data
    - Mock Web3 instances with simulated RPC responses
    - Mock smart contract objects and function calls
    - Mock transaction receipts and blockchain state
    - Helper functions to generate test data dynamically

Usage:
    from test_mocks import (
        create_mock_permit,
        create_mock_payment_component,
        MockWeb3Provider
    )
    
    permit = create_mock_permit()
    payment = create_mock_payment_component()
    web3_mock = MockWeb3Provider()
"""

import time
import asyncio
from typing import Optional, Dict, Any
from unittest.mock import AsyncMock, Mock, MagicMock
from eth_account import Account
from web3 import AsyncWeb3

# Import schemas from the main codebase
import sys
from pathlib import Path
src_path = Path(__file__).parent.parent.parent / "src"
sys.path.insert(0, str(src_path))

from x402_mock.adapters.evm.schemas import (
    EIP2612Permit,
    EIP2612PermitSignature,
    EVMPaymentComponent,
    EVMVerificationResult,
    EVMTransactionConfirmation,
)
from x402_mock.schemas.bases import (
    VerificationStatus,
    TransactionStatus,
)


# ========================================================================
# Mock Blockchain Constants
# ========================================================================

# Test wallet addresses (valid EVM format)
# Generate matching private keys first
_temp_owner_account = Account.from_key("0x1234567890123456789012345678901234567890123456789012345678901234")
_temp_server_account = Account.from_key("0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd")

MOCK_OWNER_ADDRESS = AsyncWeb3.to_checksum_address(_temp_owner_account.address)
MOCK_SPENDER_ADDRESS = "0x1234567890123456789012345678901234567890"
MOCK_SERVER_ADDRESS = AsyncWeb3.to_checksum_address(_temp_server_account.address)

# Test private keys (do not use in production!)
MOCK_OWNER_PRIVATE_KEY = "0x1234567890123456789012345678901234567890123456789012345678901234"
MOCK_SERVER_PRIVATE_KEY = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"

# Token contract addresses (USDC on different chains)
MOCK_USDC_SEPOLIA = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"  # Sepolia USDC
MOCK_USDC_MAINNET = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"  # Mainnet USDC

# Chain IDs
MOCK_CHAIN_ID_SEPOLIA = 11155111
MOCK_CHAIN_ID_MAINNET = 1

# Token metadata
MOCK_TOKEN_NAME = "USDC"
MOCK_TOKEN_VERSION = "2"
MOCK_TOKEN_DECIMALS = 6

# Time constants
MOCK_CURRENT_TIME = int(time.time())
MOCK_DEADLINE_FUTURE = MOCK_CURRENT_TIME + 3600  # 1 hour from now
MOCK_DEADLINE_PAST = MOCK_CURRENT_TIME - 3600  # 1 hour ago

# Transaction and block data
MOCK_BLOCK_NUMBER = 12345678
MOCK_BLOCK_TIMESTAMP = MOCK_CURRENT_TIME
MOCK_GAS_PRICE = 20000000000  # 20 Gwei
MOCK_GAS_USED = 50000
MOCK_GAS_LIMIT = 100000
MOCK_TX_HASH = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

# Token amounts (in smallest units, 1 USDC = 1,000,000 units)
MOCK_AMOUNT_1_USDC = 1000000
MOCK_AMOUNT_10_USDC = 10000000
MOCK_AMOUNT_100_USDC = 100000000

# Nonce values
MOCK_NONCE_ZERO = 0
MOCK_NONCE_ONE = 1
MOCK_NONCE_FIVE = 5


# ========================================================================
# Mock Signature Data
# ========================================================================

def create_mock_signature(
    v: int = 27,
    r: Optional[str] = None,
    s: Optional[str] = None
) -> EIP2612PermitSignature:
    """
    Create a mock EIP2612 permit signature with valid format.
    
    Generates signature components (v, r, s) that follow EIP2612 standards.
    Default values are valid hex strings that can be used for structural testing.
    
    Args:
        v: Recovery ID (27 or 28). Defaults to 27.
        r: Signature r component (64 hex chars with 0x prefix). Auto-generated if None.
        s: Signature s component (64 hex chars with 0x prefix). Auto-generated if None.
    
    Returns:
        EIP2612PermitSignature: Valid signature object for testing
    
    Example:
        sig = create_mock_signature()
        sig = create_mock_signature(v=28, r="0x" + "a" * 64)
    """
    if r is None:
        r = "0x" + "a1b2c3d4" * 8  # Exactly 64 hex chars (8 * 8 = 64)
    if s is None:
        s = "0x" + "e5f6a7b8" * 8  # Exactly 64 hex chars (8 * 8 = 64)
    
    return EIP2612PermitSignature(
        signature_type="EIP2612",
        v=v,
        r=r,
        s=s
    )


def create_real_signature(
    private_key: str,
    owner: str,
    spender: str,
    token: str,
    value: int,
    nonce: int,
    deadline: int,
    chain_id: int,
    token_name: str = MOCK_TOKEN_NAME,
    token_version: str = MOCK_TOKEN_VERSION
) -> EIP2612PermitSignature:
    """
    Create a cryptographically valid EIP2612 signature using actual signing.
    
    This function performs real EIP712 signing to generate authentic signature
    components. Use this when testing signature verification logic.
    
    Args:
        private_key: Private key to sign with (0x-prefixed hex)
        owner: Token owner address
        spender: Authorized spender address
        token: Token contract address
        value: Amount to authorize (smallest units)
        nonce: Current nonce value
        deadline: Permit expiration timestamp
        chain_id: EVM chain ID
        token_name: Token name for EIP712 domain
        token_version: Token version for EIP712 domain
    
    Returns:
        EIP2612PermitSignature: Cryptographically valid signature
    
    Example:
        sig = create_real_signature(
            private_key=MOCK_OWNER_PRIVATE_KEY,
            owner=MOCK_OWNER_ADDRESS,
            spender=MOCK_SPENDER_ADDRESS,
            token=MOCK_USDC_SEPOLIA,
            value=1000000,
            nonce=0,
            deadline=MOCK_DEADLINE_FUTURE,
            chain_id=MOCK_CHAIN_ID_SEPOLIA
        )
    """
    from eth_account.messages import encode_typed_data
    
    # Build EIP712 typed data structure
    typed_data = {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"}
            ]
        },
        "primaryType": "Permit",
        "domain": {
            "name": token_name,
            "version": token_version,
            "chainId": chain_id,
            "verifyingContract": token
        },
        "message": {
            "owner": owner,
            "spender": spender,
            "value": value,
            "nonce": nonce,
            "deadline": deadline
        }
    }
    
    # Sign the typed data
    account = Account.from_key(private_key)
    encoded_data = encode_typed_data(full_message=typed_data)
    signed_message = account.sign_message(encoded_data)
    
    # Convert signature components to proper format
    r_bytes = signed_message.r.to_bytes(32, "big")
    s_bytes = signed_message.s.to_bytes(32, "big")
    
    return EIP2612PermitSignature(
        signature_type="EIP2612",
        v=signed_message.v,
        r="0x" + r_bytes.hex(),
        s="0x" + s_bytes.hex()
    )


# ========================================================================
# Mock Permit Objects
# ========================================================================

def create_mock_permit(
    owner: str = MOCK_OWNER_ADDRESS,
    spender: str = MOCK_SPENDER_ADDRESS,
    token: str = MOCK_USDC_SEPOLIA,
    value: int = MOCK_AMOUNT_1_USDC,
    nonce: int = MOCK_NONCE_ZERO,
    deadline: int = MOCK_DEADLINE_FUTURE,
    chain_id: int = MOCK_CHAIN_ID_SEPOLIA,
    signature: Optional[EIP2612PermitSignature] = None,
    use_real_signature: bool = False
) -> EIP2612Permit:
    """
    Create a mock EIP2612 permit for testing.
    
    Generates a complete permit object with all required fields.
    Can create either a mock signature or a cryptographically valid signature.
    
    Args:
        owner: Token owner wallet address
        spender: Authorized spender address
        token: Token contract address
        value: Authorized amount (smallest units)
        nonce: Nonce for replay protection
        deadline: Permit expiration timestamp
        chain_id: EVM chain ID
        signature: Pre-created signature object (optional)
        use_real_signature: If True, generates cryptographically valid signature
    
    Returns:
        EIP2612Permit: Complete permit object ready for testing
    
    Example:
        # Mock signature (for structural testing)
        permit = create_mock_permit()
        
        # Real signature (for verification testing)
        permit = create_mock_permit(use_real_signature=True)
    """
    # Generate signature if not provided
    if signature is None:
        if use_real_signature:
            signature = create_real_signature(
                private_key=MOCK_OWNER_PRIVATE_KEY,
                owner=owner,
                spender=spender,
                token=token,
                value=value,
                nonce=nonce,
                deadline=deadline,
                chain_id=chain_id
            )
        else:
            signature = create_mock_signature()
    
    return EIP2612Permit(
        permit_type="EIP2612",
        owner=owner,
        spender=spender,
        token=token,
        value=value,
        nonce=nonce,
        deadline=deadline,
        chain_id=chain_id,
        signature=signature
    )


# ========================================================================
# Mock Payment Components
# ========================================================================

def create_mock_payment_component(
    amount: float = 1.0,
    token: str = MOCK_USDC_SEPOLIA,
    chain_id: int = MOCK_CHAIN_ID_SEPOLIA,
    currency: str = "USD",
    metadata: Optional[Dict[str, Any]] = None
) -> EVMPaymentComponent:
    """
    Create a mock EVM payment component for testing.
    
    Generates a payment requirement object that specifies the expected payment
    amount and blockchain details.
    
    Args:
        amount: Payment amount (human-readable, e.g., 1.0 for 1 USDC)
        token: Token contract address
        chain_id: EVM chain ID
        currency: Currency code (e.g., "USD")
        metadata: Additional payment metadata (auto-generated if None)
    
    Returns:
        EVMPaymentComponent: Complete payment component for testing
    
    Example:
        payment = create_mock_payment_component(amount=10.0)
        payment = create_mock_payment_component(
            amount=5.0,
            metadata={"wallet_address": MOCK_SPENDER_ADDRESS}
        )
    """
    # Generate default metadata if not provided
    if metadata is None:
        metadata = {
            "name": MOCK_TOKEN_NAME,
            "version": MOCK_TOKEN_VERSION,
            "decimals": MOCK_TOKEN_DECIMALS,
            "wallet_address": MOCK_SPENDER_ADDRESS
        }
    
    return EVMPaymentComponent(
        payment_type="evm",
        amount=amount,
        currency=currency,
        token=token,
        chain_id=chain_id,
        metadata=metadata
    )


# ========================================================================
# Mock Web3 Provider Classes
# ========================================================================

class MockContract:
    """
    Mock Web3 contract object for simulating smart contract interactions.
    
    Provides mock implementations of common contract methods used in EVM adapter:
    - balanceOf: Query token balance
    - nonces: Query permit nonce counter
    - allowance: Query approved allowance
    - permit: Execute permit transaction
    
    Attributes:
        mock_balance: Balance to return from balanceOf()
        mock_nonce: Nonce to return from nonces()
        mock_allowance: Allowance to return from allowance()
        mock_permit_success: Whether permit() should succeed
    """
    
    def __init__(
        self,
        mock_balance: int = MOCK_AMOUNT_100_USDC,
        mock_nonce: int = MOCK_NONCE_ZERO,
        mock_allowance: int = 0,
        mock_permit_success: bool = True
    ):
        """
        Initialize mock contract with configurable return values.
        
        Args:
            mock_balance: Balance to return from balanceOf()
            mock_nonce: Nonce to return from nonces()
            mock_allowance: Allowance to return from allowance()
            mock_permit_success: Whether permit() should succeed or raise
        """
        self.mock_balance = mock_balance
        self.mock_nonce = mock_nonce
        self.mock_allowance = mock_allowance
        self.mock_permit_success = mock_permit_success
        
        # Create mock functions object
        self.functions = self._create_functions_mock()
    
    def _create_functions_mock(self) -> Mock:
        """Create mock functions object with contract methods."""
        functions = Mock()
        
        # Mock balanceOf function
        balance_mock = Mock()
        balance_mock.call = AsyncMock(return_value=self.mock_balance)
        functions.balanceOf = Mock(return_value=balance_mock)
        
        # Mock nonces function
        nonce_mock = Mock()
        nonce_mock.call = AsyncMock(return_value=self.mock_nonce)
        functions.nonces = Mock(return_value=nonce_mock)
        
        # Mock allowance function
        allowance_mock = Mock()
        allowance_mock.call = AsyncMock(return_value=self.mock_allowance)
        functions.allowance = Mock(return_value=allowance_mock)
        
        # Mock permit function with transaction building
        async def permit_estimate_gas(*args, **kwargs):
            if self.mock_permit_success:
                return MOCK_GAS_LIMIT
            raise Exception("Gas estimation failed")
        
        async def permit_build_transaction(tx_params):
            return {
                "from": tx_params.get("from"),
                "gas": tx_params.get("gas"),
                "gasPrice": tx_params.get("gasPrice"),
                "nonce": tx_params.get("nonce"),
                "to": MOCK_USDC_SEPOLIA,
                "data": "0x" + "ab" * 100  # Mock transaction data
            }
        
        permit_mock = Mock()
        permit_mock.estimate_gas = AsyncMock(side_effect=permit_estimate_gas)
        permit_mock.build_transaction = AsyncMock(side_effect=permit_build_transaction)
        functions.permit = Mock(return_value=permit_mock)
        
        return functions


class MockWeb3Provider:
    """
    Mock AsyncWeb3 provider for simulating blockchain RPC interactions.
    
    Provides mock implementations of all AsyncWeb3 methods used in EVM adapter:
    - eth.get_balance: Query ETH balance
    - eth.block_number: Get current block number
    - eth.gas_price: Get current gas price
    - eth.get_transaction_count: Get account nonce
    - eth.send_raw_transaction: Broadcast transaction
    - eth.get_transaction_receipt: Query transaction receipt
    - eth.contract: Create contract instance
    
    This class allows comprehensive testing without actual blockchain connectivity.
    
    Attributes:
        mock_block_number: Block number to return
        mock_gas_price: Gas price to return (wei)
        mock_tx_count: Transaction count to return
        mock_tx_receipt: Transaction receipt to return
        contracts: Dictionary of mock contracts by address
    """
    
    def __init__(
        self,
        mock_block_number: int = MOCK_BLOCK_NUMBER,
        mock_gas_price: int = MOCK_GAS_PRICE,
        mock_tx_count: int = 0,
        mock_balance: int = MOCK_AMOUNT_100_USDC,
        mock_nonce: int = MOCK_NONCE_ZERO,
        mock_allowance: int = 0
    ):
        """
        Initialize mock Web3 provider with configurable responses.
        
        Args:
            mock_block_number: Current block number
            mock_gas_price: Current gas price (wei)
            mock_tx_count: Transaction count for address
            mock_balance: Token balance to return
            mock_nonce: Permit nonce to return
            mock_allowance: Allowance to return
        """
        self.mock_block_number = mock_block_number
        self.mock_gas_price = mock_gas_price
        self.mock_tx_count = mock_tx_count
        self.mock_balance = mock_balance
        self.mock_nonce = mock_nonce
        self.mock_allowance = mock_allowance
        
        # Create mock eth object
        self.eth = self._create_eth_mock()
        
        # Store contracts created via eth.contract()
        self.contracts = {}
    
    def _create_eth_mock(self) -> Mock:
        """Create mock eth object with common Web3 methods."""
        eth = Mock()
        
        # Mock async methods
        eth.get_balance = AsyncMock(return_value=1000000000000000000)  # 1 ETH
        eth.gas_price = AsyncMock(return_value=self.mock_gas_price)
        eth.get_transaction_count = AsyncMock(return_value=self.mock_tx_count)
        
        # Mock send_raw_transaction - return HexBytes-like object
        async def send_raw_tx(raw_tx):
            # Create a mock HexBytes object with hex() method
            tx_hash_bytes = bytes.fromhex(MOCK_TX_HASH[2:])
            
            class MockHexBytes(bytes):
                def hex(self):
                    return MOCK_TX_HASH
            
            return MockHexBytes(tx_hash_bytes)
        
        eth.send_raw_transaction = AsyncMock(side_effect=send_raw_tx)
        
        # Mock get_transaction_receipt
        async def get_tx_receipt(tx_hash):
            return {
                "transactionHash": tx_hash,
                "blockNumber": self.mock_block_number,
                "blockHash": "0x" + "12" * 32,
                "status": 1,  # Success
                "gasUsed": MOCK_GAS_USED,
                "effectiveGasPrice": self.mock_gas_price,
                "from": MOCK_SERVER_ADDRESS,
                "to": MOCK_USDC_SEPOLIA,
                "logs": []
            }
        eth.get_transaction_receipt = AsyncMock(side_effect=get_tx_receipt)
        
        # Mock contract creation
        def create_contract(address, abi):
            if address not in self.contracts:
                self.contracts[address] = MockContract(
                    mock_balance=self.mock_balance,
                    mock_nonce=self.mock_nonce,
                    mock_allowance=self.mock_allowance
                )
            return self.contracts[address]
        eth.contract = Mock(side_effect=create_contract)
        
        return eth
    
    @staticmethod
    def to_checksum_address(address: str) -> str:
        """Mock checksum address conversion (returns input as-is)."""
        return AsyncWeb3.to_checksum_address(address)


# ========================================================================
# Mock Verification and Transaction Results
# ========================================================================

def create_mock_verification_result(
    status: VerificationStatus = VerificationStatus.SUCCESS,
    is_valid: bool = True,
    permit_owner: Optional[str] = MOCK_OWNER_ADDRESS,
    authorized_amount: Optional[int] = MOCK_AMOUNT_1_USDC,
    on_chain_nonce: Optional[int] = MOCK_NONCE_ZERO,
    on_chain_allowance: Optional[int] = 0,
    owner_balance: Optional[int] = MOCK_AMOUNT_100_USDC,
    message: str = "Permit verified successfully",
    error_details: Optional[Dict[str, Any]] = None
) -> EVMVerificationResult:
    """
    Create a mock verification result for testing.
    
    Generates a complete verification result object with configurable status
    and blockchain state data.
    
    Args:
        status: Verification status enum value
        is_valid: Whether verification succeeded
        permit_owner: Verified owner address
        authorized_amount: Verified authorized amount
        on_chain_nonce: Current on-chain nonce
        on_chain_allowance: Current on-chain allowance
        owner_balance: Token balance of owner
        message: Human-readable status message
        error_details: Error details dictionary
    
    Returns:
        EVMVerificationResult: Complete verification result for testing
    
    Example:
        # Success result
        result = create_mock_verification_result()
        
        # Failure result
        result = create_mock_verification_result(
            status=VerificationStatus.INSUFFICIENT_BALANCE,
            is_valid=False,
            message="Insufficient balance"
        )
    """
    return EVMVerificationResult(
        verification_type="evm",
        status=status,
        is_valid=is_valid,
        permit_owner=permit_owner,
        authorized_amount=authorized_amount,
        on_chain_nonce=on_chain_nonce,
        on_chain_allowance=on_chain_allowance,
        owner_balance=owner_balance,
        message=message,
        error_details=error_details,
        blockchain_state={
            "nonce": on_chain_nonce,
            "allowance": on_chain_allowance,
            "balance": owner_balance
        } if on_chain_nonce is not None else None
    )


def create_mock_transaction_confirmation(
    status: TransactionStatus = TransactionStatus.SUCCESS,
    tx_hash: str = MOCK_TX_HASH,
    block_number: Optional[int] = MOCK_BLOCK_NUMBER,
    block_timestamp: Optional[int] = MOCK_BLOCK_TIMESTAMP,
    gas_used: Optional[int] = MOCK_GAS_USED,
    gas_limit: Optional[int] = MOCK_GAS_LIMIT,
    transaction_fee: Optional[int] = None,
    confirmations: int = 12,
    error_message: Optional[str] = None
) -> EVMTransactionConfirmation:
    """
    Create a mock transaction confirmation for testing.
    
    Generates a complete transaction confirmation object with blockchain
    execution details.
    
    Args:
        status: Transaction status enum value
        tx_hash: Transaction hash (0x-prefixed hex)
        block_number: Block containing transaction
        block_timestamp: Block timestamp
        gas_used: Actual gas consumed
        gas_limit: Gas limit specified
        transaction_fee: Fee paid (auto-calculated if None)
        confirmations: Number of confirmations
        error_message: Error message if failed
    
    Returns:
        EVMTransactionConfirmation: Complete confirmation for testing
    
    Example:
        # Success confirmation
        confirmation = create_mock_transaction_confirmation()
        
        # Failed confirmation
        confirmation = create_mock_transaction_confirmation(
            status=TransactionStatus.FAILED,
            error_message="Transaction reverted"
        )
    """
    if transaction_fee is None and gas_used is not None:
        transaction_fee = gas_used * MOCK_GAS_PRICE
    
    return EVMTransactionConfirmation(
        confirmation_type="evm",
        status=status,
        tx_hash=tx_hash,
        block_number=block_number,
        block_timestamp=block_timestamp,
        gas_used=gas_used,
        gas_limit=gas_limit,
        transaction_fee=transaction_fee,
        confirmations=confirmations,
        error_message=error_message,
        from_address=MOCK_SERVER_ADDRESS if status == TransactionStatus.SUCCESS else None,
        to_address=MOCK_USDC_SEPOLIA if status == TransactionStatus.SUCCESS else None
    )


# ========================================================================
# Utility Functions
# ========================================================================


def get_mock_account_for_address(address: str) -> Account:
    """
    Get a mock Account object for a specific address.
    
    This is useful for testing purposes when you need an Account instance
    that corresponds to one of the mock addresses.
    
    Args:
        address: Wallet address (should match a mock constant)
    
    Returns:
        Account: eth_account Account object
    
    Example:
        account = get_mock_account_for_address(MOCK_OWNER_ADDRESS)
    """
    if address.lower() == MOCK_OWNER_ADDRESS.lower():
        return Account.from_key(MOCK_OWNER_PRIVATE_KEY)
    elif address.lower() == MOCK_SERVER_ADDRESS.lower():
        return Account.from_key(MOCK_SERVER_PRIVATE_KEY)
    else:
        # Generate a random account
        return Account.create()


def create_expired_permit() -> EIP2612Permit:
    """
    Create a permit that has already expired.
    
    Useful for testing expiration validation logic.
    
    Returns:
        EIP2612Permit: Permit with past deadline
    
    Example:
        expired_permit = create_expired_permit()
        assert expired_permit.is_expired(int(time.time()))
    """
    return create_mock_permit(deadline=MOCK_DEADLINE_PAST)


def create_permit_with_wrong_nonce(wrong_nonce: int = 999) -> EIP2612Permit:
    """
    Create a permit with a nonce that doesn't match on-chain state.
    
    Useful for testing replay attack prevention.
    
    Args:
        wrong_nonce: Nonce value that doesn't match expected state
    
    Returns:
        EIP2612Permit: Permit with incorrect nonce
    
    Example:
        bad_permit = create_permit_with_wrong_nonce(nonce=5)
    """
    return create_mock_permit(nonce=wrong_nonce)


def create_permit_with_insufficient_allowance(small_value: int = 1) -> EIP2612Permit:
    """
    Create a permit with value less than required payment.
    
    Useful for testing insufficient allowance validation.
    
    Args:
        small_value: Small value that won't cover payment requirement
    
    Returns:
        EIP2612Permit: Permit with insufficient value
    
    Example:
        bad_permit = create_permit_with_insufficient_allowance(value=1)
    """
    return create_mock_permit(value=small_value)


__all__ = [
    # Constants
    "MOCK_OWNER_ADDRESS",
    "MOCK_SPENDER_ADDRESS",
    "MOCK_SERVER_ADDRESS",
    "MOCK_OWNER_PRIVATE_KEY",
    "MOCK_SERVER_PRIVATE_KEY",
    "MOCK_USDC_SEPOLIA",
    "MOCK_USDC_MAINNET",
    "MOCK_CHAIN_ID_SEPOLIA",
    "MOCK_CHAIN_ID_MAINNET",
    "MOCK_TOKEN_NAME",
    "MOCK_TOKEN_VERSION",
    "MOCK_TOKEN_DECIMALS",
    "MOCK_CURRENT_TIME",
    "MOCK_DEADLINE_FUTURE",
    "MOCK_DEADLINE_PAST",
    "MOCK_AMOUNT_1_USDC",
    "MOCK_AMOUNT_10_USDC",
    "MOCK_AMOUNT_100_USDC",
    "MOCK_NONCE_ZERO",
    "MOCK_TX_HASH",
    "MOCK_BLOCK_NUMBER",
    "MOCK_GAS_USED",
    
    # Factory functions
    "create_mock_signature",
    "create_real_signature",
    "create_mock_permit",
    "create_mock_payment_component",
    "create_mock_verification_result",
    "create_mock_transaction_confirmation",
    
    # Mock classes
    "MockContract",
    "MockWeb3Provider",
    
    # Utility functions
    "get_mock_account_for_address",
    "create_expired_permit",
    "create_permit_with_wrong_nonce",
    "create_permit_with_insufficient_allowance",
]
