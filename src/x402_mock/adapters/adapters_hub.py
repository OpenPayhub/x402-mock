"""
Adapter Hub - Unified Blockchain Adapter Gateway

This module serves as the main entry point for all blockchain adapter operations.
It provides a unified interface that:
1. Routes requests to appropriate blockchain adapters (EVM, Solana, etc.) automatically
2. Manages payment component registration and retrieval
3. Provides factory methods for creating adapter instances

The hub acts as a facade pattern, simplifying interactions with different blockchain
implementations by detecting the blockchain type and delegating to appropriate adapters.

Key Features:
    - Automatic blockchain type detection (detector.py)
    - Unified payment component management (registry.py)
    - Consistent interface across different blockchains
    - Easy extensibility for new blockchain types

Architecture:
    AdapterHub (you are here)
        ├── PaymentRegistry (payment component management)
        ├── BlockchainDetector (blockchain type detection)
        ├── EVM Adapters (server.py, client.py)
        └── Solana Adapters (server.py, client.py)
"""

from typing import List, Optional, Union, Any, Dict

from .registry import PaymentRegistry
from .unions import PermitTypes, PaymentComponentTypes, get_adapter_type
from .bases import AdapterFactory
from .evm.adapter import EVMAdapter


class AdapterHub:
    """
    Unified Blockchain Adapter Hub.
    
    Provides core blockchain adapter operations with automatic type detection and routing.
    Manages payment component registration and delegates to blockchain-specific adapters.
    """
    
    def __init__(self, evm_private_key: str = None):
        """
        Initialize AdapterHub with registry and adapter mappings.
        
        Sets up payment registry and registers EVM adapter with BlockchainDetector.
        """
        self._registry = PaymentRegistry()
        
        # Mapping of blockchain types to adapter classes
        self._adapter_factories: dict[str, AdapterFactory] = {
            "evm": EVMAdapter(private_key=evm_private_key),
            # "svm": SolanaAdapter(),
            # Placeholder for future blockchain types # TODO add more blockchain types
        }
    
    # =========================================================================
    # Payment Component Management Methods
    # =========================================================================
    
    def register_payment_methods(
        self,
        chain_id: str,
        amount: float,
        currency: str,
    ) -> None:
        """
        Register payment methods for a specific chain.
        
        Automatically detects blockchain type from chain_id and obtains wallet address.
        
        Args:
            chain_id: Chain ID in CAIP-2 format (e.g., "eip155:1" for EVM)
            amount: Payment amount
            currency: Currency code (e.g., "USD")
        """
        # Detect blockchain type from chain_id format
        if chain_id.startswith("eip155:"):
            blockchain_type = "evm"
        else:
            raise ValueError(f"Unknown blockchain type for chain_id: {chain_id}")
        
        # Get wallet address from appropriate server adapter
        adapter: AdapterFactory = self._adapter_factories[blockchain_type]
        wallet_address = adapter.get_wallet_address()
        
        self._registry.method_register(chain_id, amount, currency, wallet_address)
    
    def get_payment_methods(self) -> List[PaymentComponentTypes]:
        """
        Get all registered payment methods.
        
        Returns:
            List of registered payment components
        """
        return self._registry.get_support_list()
    
    async def verify_signature(
        self,
        permit_payload: Union[PermitTypes, Dict[str, Any]],
    ) -> Optional[Any]:
        """
        Verify permit signature with automatic blockchain detection and component matching.
        
        Converts permit payload to typed model, matches token with registered components,
        and calls corresponding adapter to verify signature.
        
        Args:
            permit_payload: Permit data (PermitTypes or dict)
        
        Returns:
            Verification result from adapter
        
        Raises:
            TypeError: If blockchain type cannot be determined
            ValueError: If payload conversion or token matching fails
        """
        # Convert permit payload to typed model
        permit = PermitTypes.model_validate(permit_payload)
        if not permit:
            raise ValueError("Failed to convert permit payload")
        
        # Detect blockchain type
        blockchain_type = get_adapter_type(permit)
        if not blockchain_type:
            raise TypeError("Unknown blockchain type for permit")
        
        # Match with registered payment components by token
        registered_components = self._registry.get_support_list()
        matched_component = None
        for comp in registered_components:
            if comp.token.lower() == permit.token.lower():
                matched_component = comp
                break
        
        if not matched_component:
            raise ValueError(
                f"Payment component not registered for token: {permit.token}"
            )
        
        # Get adapter and verify signature
        adapters = self._adapter_factories.get(blockchain_type)
        if not adapters:
            raise TypeError(f"No adapter for blockchain type: {blockchain_type}")
        
        return await adapters.verify_signature(permit, matched_component)
    
    async def settle(
        self,
        permit_payload: Union[PermitTypes, Dict[str, Any]],
    ) -> Optional[Any]:
        """
        Execute permit settlement with automatic type conversion.
        
        Converts permit payload to typed model and calls corresponding adapter.
        
        Args:
            permit_payload: Permit data (PermitTypes or dict)
        
        Returns:
            Transaction confirmation from server adapter
        
        Raises:
            TypeError: If blockchain type cannot be determined
            ValueError: If payload conversion fails
        """
        # Convert payload to typed model
        permit = PermitTypes.model_validate(permit_payload)
        if not permit:
            raise ValueError("Failed to convert permit payload")
        
        # Detect blockchain type
        blockchain_type = get_adapter_type(permit)
        if not blockchain_type:
            raise TypeError(f"Unknown blockchain type for permit")
        
        # Get adapter and settle
        adapters: AdapterFactory = self._adapter_factories.get(blockchain_type)
        if not adapters:
            raise TypeError(f"No adapter for blockchain type: {blockchain_type}")
        
        return await adapters.settle(permit)

    async def signature(self, list_components: List[Union[PaymentComponentTypes, Dict[str, Any]]]) -> PermitTypes:
        """
        Generate signed permit from remote payment components.
        
        Matches remote components against local support list, converts to typed model,
        and delegates to blockchain-specific adapter for signing.
        
        Args:
            list_components: Remote payment components (typed or dict) to match
        
        Returns:
            Signed permit from adapter
        
        Raises:
            ValueError: If no matching component found or conversion fails
            TypeError: If blockchain type cannot be determined
        """
        # Match remote component with local support list
        local_components = self.get_payment_methods()
        matched_component = match_payment_component(list_components, local_components)
        
        if not matched_component:
            raise ValueError(
                "No matching payment component found among remote components"
            )
        
        # Convert to typed payment component
        typed_component = PaymentComponentTypes.model_validate(matched_component)
        if not typed_component:
            raise ValueError("Failed to convert matched component to typed model")
        
        # Detect blockchain type and get adapter
        blockchain_type = get_adapter_type(typed_component)
        if not blockchain_type:
            raise TypeError("Unknown blockchain type for matched component")
        
        adapter = self._adapter_factories.get(blockchain_type)
        if not adapter:
            raise TypeError(f"No adapter for blockchain type: {blockchain_type}")
        
        # Sign permit
        return await adapter.signature(typed_component)


def match_payment_component(
    remote_components: List[Union[PaymentComponentTypes, Dict[str, Any]]],
    local_components: List[PaymentComponentTypes],
) -> Optional[Union[PaymentComponentTypes, Dict[str, Any]]]:
    """
    Match payment component: return first remote component matching a local one.
    
    Criteria: same payment_type, same token (case-insensitive), remote amount <= local amount.
    """
    for remote in remote_components:
        for local in local_components:
            # Extract attributes (handle both dict and object)
            r_type = remote.get('payment_type') if isinstance(remote, dict) else remote.payment_type
            r_token = remote.get('token') if isinstance(remote, dict) else remote.token
            r_amount = remote.get('amount') if isinstance(remote, dict) else remote.amount
            
            # Check match criteria
            if (
                r_type == local.payment_type
                and str(r_token).lower() == local.token.lower()
                and float(r_amount) <= float(local.amount)
            ):
                return remote
    
    return None

