"""
EVM Adapter Test Suite

Comprehensive tests for EVMAdapter functionality including:
- Signature verification with various valid and invalid permits
- On-chain state validation (nonce, allowance, balance)
- Transaction settlement and execution
- Error handling and edge cases
- Multi-chain support

Test Structure:
    - Test fixtures and setup in test_mocks.py
    - Unit tests for individual adapter methods
    - Integration tests for complete workflows
    - Edge case and error condition tests

Usage:
    pytest test_evm_adapter.py -v
    pytest test_evm_adapter.py::TestEVMAdapter::test_verify_signature_success -v
"""

import pytest
import asyncio
import os
from unittest.mock import AsyncMock, Mock, patch
from web3 import AsyncWeb3

# Import mock utilities and test data
from test_mocks import (
    # Mock constants
    MOCK_OWNER_ADDRESS,
    MOCK_SPENDER_ADDRESS,
    MOCK_SERVER_ADDRESS,
    MOCK_OWNER_PRIVATE_KEY,
    MOCK_SERVER_PRIVATE_KEY,
    MOCK_USDC_SEPOLIA,
    MOCK_CHAIN_ID_SEPOLIA,
    MOCK_AMOUNT_1_USDC,
    MOCK_AMOUNT_100_USDC,
    MOCK_NONCE_ZERO,
    MOCK_DEADLINE_FUTURE,
    
    # Factory functions
    create_mock_permit,
    create_mock_payment_component,
    create_mock_signature,
    create_real_signature,
    create_mock_verification_result,
    create_mock_transaction_confirmation,
    
    # Mock classes
    MockWeb3Provider,
    MockContract,
    
    # Utility functions
    create_expired_permit,
    create_permit_with_wrong_nonce,
    create_permit_with_insufficient_allowance,
)

# Import schemas and enums
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

# Import the adapter to test
from x402_mock.adapters.evm.adapter import EVMAdapter


# ========================================================================
# Test Fixtures
# ========================================================================

@pytest.fixture
def mock_web3():
    """Provide a mock Web3 instance for testing."""
    return MockWeb3Provider()


@pytest.fixture
def evm_adapter():
    """Provide an EVMAdapter instance with mock private key."""
    return EVMAdapter(private_key=MOCK_SERVER_PRIVATE_KEY)


@pytest.fixture
def valid_permit():
    """Provide a valid mock permit for testing."""
    return create_mock_permit(
        owner=MOCK_OWNER_ADDRESS,
        spender=MOCK_SERVER_ADDRESS,
        use_real_signature=True
    )


@pytest.fixture
def valid_payment_component():
    """Provide a valid payment component for testing."""
    return create_mock_payment_component(amount=1.0)


# ========================================================================
# Test Classes
# ========================================================================

class TestEVMAdapterInitialization:
    """Test EVMAdapter initialization and configuration."""
    
    def test_init_with_private_key(self):
        """Test adapter initialization with explicit private key."""
        adapter = EVMAdapter(private_key=MOCK_SERVER_PRIVATE_KEY)
        assert adapter.wallet_address == MOCK_SERVER_ADDRESS
    
    def test_init_without_private_key_raises(self):
        """Test that initialization without private key raises ValueError."""
        # Mock environment to ensure no key is loaded from env
        with patch.dict(os.environ, {}, clear=False):
            # Remove evm_private_key if exists
            os.environ.pop('evm_private_key', None)
            with pytest.raises(ValueError, match="Private key not provided"):
                EVMAdapter(private_key=None)
    
    def test_get_wallet_address(self, evm_adapter):
        """Test getting wallet address from adapter."""
        address = evm_adapter.get_wallet_address()
        assert address == MOCK_SERVER_ADDRESS


class TestSignatureGeneration:
    """Test permit signature generation."""
    
    @pytest.mark.asyncio
    async def test_signature_success(self, evm_adapter):
        """Test successful permit signature generation."""
        payment = create_mock_payment_component(amount=1.0)
        
        # Mock Web3 to return nonce
        with patch.object(evm_adapter, '_get_web3_instance') as mock_get_web3:
            mock_web3 = MockWeb3Provider(mock_nonce=MOCK_NONCE_ZERO)
            mock_get_web3.return_value = mock_web3
            
            # Generate signed permit
            permit = await evm_adapter.signature(payment)
            
            # Verify permit structure - owner should be server address (who signs)
            assert permit.permit_type == "EIP2612"
            assert permit.owner == evm_adapter.wallet_address
            assert permit.spender == AsyncWeb3.to_checksum_address(payment.metadata.get("wallet_address"))
            assert permit.token == payment.token
            assert permit.chain_id == payment.chain_id
            assert permit.nonce == MOCK_NONCE_ZERO
            assert permit.signature is not None
    
    @pytest.mark.asyncio
    async def test_signature_creates_valid_signature(self, evm_adapter):
        """Test that generated signature passes validation."""
        payment = create_mock_payment_component(amount=1.0)
        
        with patch.object(evm_adapter, '_get_web3_instance') as mock_get_web3:
            mock_web3 = MockWeb3Provider(mock_nonce=MOCK_NONCE_ZERO)
            mock_get_web3.return_value = mock_web3
            
            permit = await evm_adapter.signature(payment)
            
            # Signature should have valid format
            assert permit.signature.v in (27, 28)
            assert len(permit.signature.r) == 66  # 0x + 64 hex chars
            assert len(permit.signature.s) == 66


class TestSignatureVerification:
    """Test permit signature verification logic."""
    
    @pytest.mark.asyncio
    async def test_verify_signature_success(self, evm_adapter):
        """Test successful permit verification with valid signature."""
        # Create permit with real signature
        permit = create_mock_permit(
            owner=MOCK_OWNER_ADDRESS,
            spender=MOCK_SERVER_ADDRESS,
            value=MOCK_AMOUNT_1_USDC,
            use_real_signature=True
        )
        payment = create_mock_payment_component(amount=1.0)
        
        # Mock Web3 with successful on-chain state
        with patch.object(evm_adapter, '_get_web3_instance') as mock_get_web3:
            mock_web3 = MockWeb3Provider(
                mock_balance=MOCK_AMOUNT_100_USDC,
                mock_nonce=MOCK_NONCE_ZERO,
                mock_allowance=0
            )
            mock_get_web3.return_value = mock_web3
            
            # Mock the signature recovery to return owner address
            with patch.object(evm_adapter, '_recover_signer_address') as mock_recover:
                mock_recover.return_value = MOCK_OWNER_ADDRESS
                
                result = await evm_adapter.verify_signature(permit, payment)
                
                # Verify success
                assert result.is_valid is True
                assert result.status == VerificationStatus.SUCCESS
                assert result.permit_owner == MOCK_OWNER_ADDRESS
                assert result.authorized_amount == MOCK_AMOUNT_1_USDC
                assert result.on_chain_nonce == MOCK_NONCE_ZERO
                assert result.owner_balance == MOCK_AMOUNT_100_USDC
    
    @pytest.mark.asyncio
    async def test_verify_signature_expired_permit(self, evm_adapter):
        """Test verification fails with expired permit."""
        expired_permit = create_expired_permit()
        expired_permit.spender = MOCK_SERVER_ADDRESS
        payment = create_mock_payment_component(amount=1.0)
        
        with patch.object(evm_adapter, '_get_web3_instance') as mock_get_web3:
            mock_web3 = MockWeb3Provider()
            mock_get_web3.return_value = mock_web3
            
            # No need to mock signature recovery for expired permit
            result = await evm_adapter.verify_signature(expired_permit, payment)
            
            # Verify failure due to expiration
            assert result.is_valid is False
            assert result.status == VerificationStatus.EXPIRED
            assert "expired" in result.message.lower()
    
    @pytest.mark.asyncio
    async def test_verify_signature_wrong_nonce(self, evm_adapter):
        """Test verification fails with mismatched nonce."""
        permit = create_permit_with_wrong_nonce(wrong_nonce=5)
        permit.spender = MOCK_SERVER_ADDRESS
        payment = create_mock_payment_component(amount=1.0)
        
        with patch.object(evm_adapter, '_get_web3_instance') as mock_get_web3:
            # On-chain nonce is 0, but permit has nonce 5
            mock_web3 = MockWeb3Provider(mock_nonce=MOCK_NONCE_ZERO)
            mock_get_web3.return_value = mock_web3
            
            # Mock signature recovery
            with patch.object(evm_adapter, '_recover_signer_address') as mock_recover:
                mock_recover.return_value = MOCK_OWNER_ADDRESS
                
                result = await evm_adapter.verify_signature(permit, payment)
                
                # Verify failure due to nonce mismatch
                assert result.is_valid is False
                assert result.status == VerificationStatus.REPLAY_ATTACK
                assert result.on_chain_nonce == MOCK_NONCE_ZERO
    
    @pytest.mark.asyncio
    async def test_verify_signature_insufficient_balance(self, evm_adapter):
        """Test verification fails when owner has insufficient balance."""
        permit = create_mock_permit(
            owner=MOCK_OWNER_ADDRESS,
            spender=MOCK_SERVER_ADDRESS,
            value=MOCK_AMOUNT_100_USDC,
            use_real_signature=True
        )
        payment = create_mock_payment_component(amount=100.0)  # Requires 100 USDC
        
        with patch.object(evm_adapter, '_get_web3_instance') as mock_get_web3:
            # Owner only has 1 USDC
            mock_web3 = MockWeb3Provider(
                mock_balance=MOCK_AMOUNT_1_USDC,
                mock_nonce=MOCK_NONCE_ZERO
            )
            mock_get_web3.return_value = mock_web3
            
            # Mock signature recovery
            with patch.object(evm_adapter, '_recover_signer_address') as mock_recover:
                mock_recover.return_value = MOCK_OWNER_ADDRESS
                
                result = await evm_adapter.verify_signature(permit, payment)
                
                # Verify failure due to insufficient balance
                assert result.is_valid is False
                assert result.status == VerificationStatus.INSUFFICIENT_BALANCE
                assert result.owner_balance == MOCK_AMOUNT_1_USDC
    
    @pytest.mark.asyncio
    async def test_verify_signature_wrong_spender(self, evm_adapter):
        """Test verification fails when spender doesn't match server address."""
        permit = create_mock_permit(
            spender=MOCK_SPENDER_ADDRESS,  # Wrong spender
            use_real_signature=True  # Use real signature with correct format
        )
        payment = create_mock_payment_component(amount=1.0)
        
        with patch.object(evm_adapter, '_get_web3_instance') as mock_get_web3:
            mock_web3 = MockWeb3Provider()
            mock_get_web3.return_value = mock_web3
            
            result = await evm_adapter.verify_signature(permit, payment)
            
            # Verify failure due to wrong spender (checked before signature validation)
            assert result.is_valid is False
            assert "spender" in result.message.lower()


class TestPermitSettlement:
    """Test permit transaction settlement and execution."""
    
    @pytest.mark.asyncio
    async def test_settle_success(self, evm_adapter):
        """Test successful permit settlement with transaction confirmation."""
        permit = create_mock_permit(
            owner=MOCK_OWNER_ADDRESS,
            spender=MOCK_SERVER_ADDRESS,
            value=MOCK_AMOUNT_1_USDC,
            use_real_signature=True
        )
        
        with patch.object(evm_adapter, '_get_web3_instance') as mock_get_web3:
            mock_web3 = MockWeb3Provider()
            
            # Add mock for block_number property (used in settle)
            async def get_block_number():
                return mock_web3.mock_block_number
            mock_web3.eth.block_number = get_block_number()
            
            mock_get_web3.return_value = mock_web3
            
            # Mock the entire transaction construction to return success
            with patch.object(evm_adapter, '_construct_permit_transaction') as mock_construct:
                mock_construct.return_value = {"raw_transaction": b'\x00' * 100}
                
                result = await evm_adapter.settle(permit)
                
                # Verify successful settlement
                assert result.status == TransactionStatus.SUCCESS
                assert result.tx_hash is not None
                assert result.block_number is not None
                assert result.gas_used is not None
    
    @pytest.mark.asyncio
    async def test_settle_invalid_permit_type(self, evm_adapter):
        """Test settlement fails with invalid permit type."""
        # Pass a non-EIP2612Permit object (dict)
        invalid_permit = {"permit_type": "invalid"}
        
        result = await evm_adapter.settle(invalid_permit)
        
        # Verify failure
        assert result.status == TransactionStatus.INVALID_TRANSACTION
        assert "Invalid permit type" in result.error_message
    
    @pytest.mark.asyncio
    async def test_settle_transaction_construction_error(self, evm_adapter):
        """Test settlement fails when transaction construction fails."""
        permit = create_mock_permit(
            owner=MOCK_OWNER_ADDRESS,
            spender=MOCK_SERVER_ADDRESS,
            use_real_signature=True
        )
        
        with patch.object(evm_adapter, '_get_web3_instance') as mock_get_web3:
            mock_web3 = MockWeb3Provider()
            
            # Make contract methods raise error during gas estimation
            def create_failing_contract(address, abi):
                contract = MockContract()
                # Override permit function to fail
                permit_mock = Mock()
                permit_mock.estimate_gas = AsyncMock(side_effect=Exception("Gas estimation failed"))
                contract.functions.permit = Mock(return_value=permit_mock)
                return contract
            
            mock_web3.eth.contract = Mock(side_effect=create_failing_contract)
            mock_get_web3.return_value = mock_web3
            
            result = await evm_adapter.settle(permit)
            
            # Verify failure
            assert result.status == TransactionStatus.INVALID_TRANSACTION
            assert "Gas estimation failed" in result.error_message


class TestBalanceQuery:
    """Test token balance query functionality."""
    
    @pytest.mark.asyncio
    async def test_get_balance_success(self, evm_adapter):
        """Test successful balance query."""
        mock_web3 = MockWeb3Provider(mock_balance=MOCK_AMOUNT_100_USDC)
        
        balance = await evm_adapter.get_balance(
            address=MOCK_OWNER_ADDRESS,
            token_address=MOCK_USDC_SEPOLIA,
            web3=mock_web3
        )
        
        assert balance == MOCK_AMOUNT_100_USDC
    
    @pytest.mark.asyncio
    async def test_get_balance_error_returns_zero(self, evm_adapter):
        """Test that balance query returns 0 on error."""
        mock_web3 = MockWeb3Provider()
        
        # Mock contract to raise exception
        with patch.object(mock_web3.eth, 'contract') as mock_contract:
            mock_contract.side_effect = Exception("Network error")
            
            balance = await evm_adapter.get_balance(
                address=MOCK_OWNER_ADDRESS,
                token_address=MOCK_USDC_SEPOLIA,
                web3=mock_web3
            )
            
            assert balance == 0


# ========================================================================
# Main Entry Point
# ========================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
