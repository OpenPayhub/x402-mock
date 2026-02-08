"""
Blockchain Adapter Registry

Manages registration and creation of payment components for different blockchains.
"""

from typing import List

from .evm.schemas import EVMPaymentComponent
from .evm.constants import get_chain_config, ChainConfig
from .unions import PaymentComponentTypes


class PaymentRegistry:
    """
    Registry for creating blockchain-specific payment components.
    
    Maps blockchain types to their payment component factories and manages
    creation of payment components for different chains.
    """
    
    # Component factory functions by blockchain type # TODO add more methods
    _component_factories = {
        "evm": "EVMPaymentComponent",
    }
    def __init__(self):
        self._support_list = []

    def method_register(
        self,
        chain_id: str,
        amount: float,
        currency: str,
        wallet_address: str
    ) -> None:
        """
        Create payment components for a specific chain.
        
        Args:
            chain_id: Chain identifier in CAIP-2 format (e.g., "eip155:1", "eip155:11155111")
            amount: Payment amount in smallest units (e.g., 1.0 USDC)
            currency: Currency code (e.g., "USD", "EUR")
            wallet_address: Wallet address for permit signing
        
        Returns:
            List of initialized payment components, or None if chain not supported
        
        Raises:
            ValueError: If input parameters are invalid
        
        Example:
            components = BlockchainPaymentRegistry.create_payment_components(
                chain_id="eip155:1",
                amount=1.0,
                currency="USD"
            )
            # Returns: [EVMPaymentComponent(...), ...]
        """
        if not isinstance(amount, float) or amount < 0:
            raise ValueError("Amount must be a non-negative float")
        
        if not isinstance(currency, str) or not currency.strip():
            raise ValueError("Currency must be a non-empty string")
        
        # Get chain configuration
        config = get_chain_config(chain_id)
        if not config:
            raise KeyError(f"Unsupport chain_id for {chain_id}, please check and change for CAIP-2 format eg: 'eip155:1'")
        
        # Create components based on blockchain type
        if config.type == "evm":
            self._support_list.extend(self._create_evm_components(chain_id, config, amount, currency, wallet_address))

        # Placeholder for future blockchain types (Solana, etc.)
        

    def get_support_list(self) -> List[PaymentComponentTypes]:
        """
        Get all registered payment components.
        
        Returns:
            List of all registered payment components
        
        Example:
            registry = PaymentRegistry()
            registry.method_register("eip155:1", 1.0, "USD")
            components = registry.get_support_list()
            # Returns: [EVMPaymentComponent(...), ...]
        """
        return self._support_list

    @classmethod
    def _create_evm_components(
        cls,
        chain_id: str,
        config: ChainConfig,
        amount: float,
        currency: str,
        wallet_address: str
    ) -> List[PaymentComponentTypes]:
        """
        Create EVM payment components for supported assets.
        
        Args:
            chain_id: Chain identifier in CAIP-2 format
            config: Chain configuration object
            amount: Payment amount
            currency: Currency code (e.g., "USD", "EUR")
            wallet_address: Wallet address for permit signing
        
        Returns:
            List of EVMPaymentComponent objects
        """
        components = []
        
        # Extract numeric chain ID from CAIP-2 format (e.g., "eip155:1" -> 1)
        numeric_chain_id = int(chain_id.split(":")[-1])
        
        # Create component for each supported asset
        for symbol, asset in config.assets.items():
            component = EVMPaymentComponent(
                payment_type='evm',
                amount=amount,
                token=asset.address,
                currency=currency,
                chain_id=numeric_chain_id,
                metadata={
                    "symbol": symbol,
                    "name": asset.name,
                    "decimals": asset.decimals,
                    "network": config.network,
                    "version": asset.version,
                    "wallet_address": wallet_address
                }
            )
            components.append(component)
        
        return components
