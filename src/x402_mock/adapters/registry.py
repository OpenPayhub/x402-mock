"""
Blockchain Adapter Registry

Manages registration and routing of payment components across different blockchain types.
"""

from typing import List, Union, Dict, Any

from pydantic import TypeAdapter

from .evm.schemas import EVMPaymentComponent
from .evm.registors import EVMRegistry
from .unions import PaymentComponentTypes


class PaymentRegistry:
    """
    Central registry that aggregates payment components across all supported blockchain types.

    Routes each submitted payment component to the appropriate chain-specific registry
    (e.g. EVM, and future chains such as Solana) and maintains a unified support list.
    """

    def __init__(self) -> None:
        # Per-chain registry instances; extend this dict when new chain types are introduced.
        self._registries: Dict[str, Any] = {
            "evm": EVMRegistry(),
        }
        self._support_list: List[PaymentComponentTypes] = []

    def method_register(
        self,
        payment_component: Union[PaymentComponentTypes, Dict[str, Any]],
    ) -> None:
        """
        Register a payment component into the appropriate chain-specific registry.

        Accepts either a validated payment component instance or a raw dict that will
        be coerced into the correct type via Pydantic's discriminated union.

        Args:
            payment_component: A ``PaymentComponentTypes`` instance or a plain dict
                               with the necessary fields to construct one.

        Raises:
            ValueError: If the dict cannot be parsed into a known payment component type,
                        or if the component fails chain-specific validation.
        """
        if isinstance(payment_component, dict):
            payment_component = TypeAdapter(PaymentComponentTypes).validate_python(payment_component)

        if isinstance(payment_component, EVMPaymentComponent):
            self._registries["evm"].payment_method_register(payment_component=payment_component)
            self._support_list.append(payment_component)
        # Placeholder for future blockchain types (e.g. Solana).

    def get_support_list(self) -> List[PaymentComponentTypes]:
        """
        Return all registered payment components across all supported chain types.

        Returns:
            An ordered list of every payment component that has been successfully registered.
        """
        return self._support_list
