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
from pydantic import TypeAdapter

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
    
    def __init__(self, evm_private_key: str = None, request_timeout: int = 60):
        """
        Initialize the hub with a payment registry and chain-specific adapter instances.

        Args:
            evm_private_key: Private key used by the EVM adapter for on-chain operations.
            request_timeout: HTTP request timeout (seconds) forwarded to each adapter.
        """
        self._registry = PaymentRegistry()

        # Mapping of blockchain types to adapter classes
        self._adapter_factories: dict[str, AdapterFactory] = {
            "evm": EVMAdapter(private_key=evm_private_key, request_timeout=request_timeout),
            # "svm": SolanaAdapter(),
            # Placeholder for future blockchain types # TODO add more blockchain types
        }

        # Tracks whether initialize() has been called for the client role.
        # signature() refuses to proceed until this flag is set.
        self._client_initialized: bool = False
    
    # =========================================================================
    # Payment Component Management Methods
    # =========================================================================
    
    def register_payment_methods(
        self,
        payment_component: Union[PaymentComponentTypes, Dict[str, Any]],
        client_role: bool = False,
    ) -> None:
        """
        Register a payment component into the hub under the given role.

        **Server role** (``client_role=False``, default): if ``pay_to`` is not set on
        the component, it is automatically filled with the wallet address returned by
        the matching chain adapter.  Use this when the hub acts as the receiving party.

        **Client role** (``client_role=True``): ``pay_to`` is left untouched.  Use this
        when the hub acts as the signing/paying party and the recipient address will
        come from the remote server's payment requirements.

        Args:
            payment_component: A ``PaymentComponentTypes`` instance or a plain dict
                               that will be coerced into the correct type.
            client_role: ``False`` (default) for server role; ``True`` for client role.

        Raises:
            TypeError: If the blockchain type cannot be determined from the component,
                       or if no adapter is registered for that type.
            ValueError: If the component cannot be parsed or fails chain validation.
        """
        # Coerce dict to a typed payment component early so we can inspect its fields.
        if isinstance(payment_component, dict):
            payment_component = TypeAdapter(PaymentComponentTypes).validate_python(payment_component)

        if not client_role:
            # Server role: detect the chain type and resolve the receiving wallet address.
            blockchain_type = get_adapter_type(payment_component)
            if not blockchain_type:
                raise TypeError("Unknown blockchain type for payment component")
            adapter: AdapterFactory = self._adapter_factories.get(blockchain_type)
            if not adapter:
                raise TypeError(f"No adapter registered for blockchain type: {blockchain_type}")
            if not payment_component.pay_to:
                payment_component.pay_to = adapter.get_wallet_address()

        self._registry.method_register(payment_component)
    
    def get_payment_methods(self) -> List[PaymentComponentTypes]:
        """
        Get all registered payment methods.

        Returns:
            List of registered payment components
        """
        return self._registry.get_support_list()

    async def initialize(self, client_role: bool = False) -> None:
        """
        One-time startup initialisation gated by caller role.

        Must be called once before signature() when operating as the signing
        party (client).  For each registered adapter, the chain-specific
        ``client_init()`` hook is invoked so it can ensure any required
        on-chain state is in place (e.g. Permit2 ERC-20 allowances for EVM).

        Server-side roles (verify_signature / settle) do not require this call
        and may pass ``client_role=False`` to skip the adapter hooks while still
        marking the hub as initialised for completeness.

        Args:
            client_role: ``True`` triggers adapter pre-signing setup;
                         ``False`` (default) skips the hooks (no on-chain writes needed).

        Raises:
            RuntimeError: If any adapter's client_init() fails.
        """
        if client_role:
            payment_components = self._registry.get_support_list()
            for adapter in self._adapter_factories.values():
                await adapter.client_init(payment_components)

        self._client_initialized = True
    
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
        permit = TypeAdapter(PermitTypes).validate_python(permit_payload)
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
        permit = TypeAdapter(PermitTypes).validate_python(permit_payload)
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
                             against locally registered ones.

        Returns:
            Signed permit produced by the matching chain adapter.

        Raises:
            ValueError: If no matching component is found or type conversion fails.
            TypeError: If the blockchain type cannot be determined.
        """
        if not self._client_initialized:
            # Auto-initialize in client role if not done explicitly beforehand.
            await self.initialize(client_role=True)
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

