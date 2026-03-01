from typing import List, Literal, Optional
from string import Template

from ..bases import AdapterRegistry
from .schemas import EVMPaymentComponent
from .constants import (
    EvmChainInfoFromEthereumLists,
    EvmPublicRpcFromChainList,
    EvmTokenListFromUniswap,
    fetch_erc20_name_version_decimals,
    get_rpc_key_from_env
)


class EVMRegistry(AdapterRegistry):
    payment_components: List[EVMPaymentComponent] = []

    def __init__(self) -> None:
        self._chain_info_fetcher = EvmChainInfoFromEthereumLists()
        self._public_rpc_fetcher = EvmPublicRpcFromChainList()
        self._token_list_fetcher = EvmTokenListFromUniswap()

    def payment_method_register(
        self,
        *,
        payment_component: EVMPaymentComponent,
        rpc_url_start_with: Literal["https:", "wss:"] = "https:",
        private_rpc_type: Literal["Infura", "Alchemy"] = "Infura",
    ) -> None:
        """
        Register a payment method by processing and validating the payment component.

        Performs the following steps in order:
        1. If RPC URL is missing, resolves it via the preferred private RPC provider
           (Infura or Alchemy) or falls back to a public RPC URL.
        2. If token address is missing, looks it up from the Uniswap token list.
        3. If token name is missing, fetches name, version, and decimals on-chain.
        4. Validates the completed payment component.
        5. Appends the validated component to the registry.

        Args:
            payment_component: The EVM payment component to register.
            rpc_url_start_with: Preferred RPC URL protocol ("https:" or "wss:").
            private_rpc_type: Preferred private RPC provider ("Infura" or "Alchemy").

        Raises:
            ValueError: If payment_component is not an EVMPaymentComponent instance,
                        or if the component fails validation after processing.
        """
        if not isinstance(payment_component, EVMPaymentComponent):
            raise ValueError("payment_component must be an instance of EVMPaymentComponent")

        self._process_rpc_url(payment_component, rpc_url_start_with, private_rpc_type)
        self._process_token_address(payment_component)
        self._process_token_info(payment_component)
        self._validate_payment_component(payment_component)
        self._add_to_registry(payment_component)

    def _process_rpc_url(
        self,
        payment_component: EVMPaymentComponent,
        rpc_url_start_with: Literal["https:", "wss:"],
        private_rpc_type: Literal["Infura", "Alchemy"],
    ) -> None:
        """
        Resolve and set the RPC URL on the payment component if not already present.

        Resolution order:
        1. Attempt to obtain the preferred private RPC URL (Infura or Alchemy).
        2. If none is available, fall back to the first matching public RPC URL.

        Args:
            payment_component: The payment component to update.
            rpc_url_start_with: Protocol prefix used to filter candidate URLs.
            private_rpc_type: Preferred infrastructure provider.
        """
        if payment_component.rpc_url:
            return

        caip2 = payment_component.caip2

        if private_rpc_type == "Infura":
            raw_url: Optional[str] = self._chain_info_fetcher.get_infura_rpc_url(
                caip2, start_with=rpc_url_start_with
            )
            infura_key = get_rpc_key_from_env("EVM_INFURA_KEY")
            if not infura_key:
                raise ValueError("Infura key not found in environment variables")
            
            url = Template(raw_url).substitute(INFURA_API_KEY=infura_key)
        else:
            raw_url = self._chain_info_fetcher.get_alchemy_rpc_url(
                caip2, start_with=rpc_url_start_with
            )
            alchemy_key = get_rpc_key_from_env("EVM_ALCHEMY_KEY")
            if not alchemy_key:
                raise ValueError("Alchemy key not found in environment variables")
            
            url = Template(raw_url).substitute(ALCHEMY_API_KEY=alchemy_key)

        if url is None:
            # Fall back to a public RPC URL from Chainlist.org.
            # pick_public_rpc expects "https://" / "wss://" (with double slash).
            chainlist_prefix = rpc_url_start_with + "//"  # e.g. "https:" -> "https://"
            try:
                url = self._public_rpc_fetcher.pick_public_rpc(
                    caip2, start_with=chainlist_prefix  # type: ignore[arg-type]
                )
            except ValueError:
                raise ValueError(
                    f"No RPC URL found for chain {caip2} with preferred protocol {rpc_url_start_with}"
                )

        payment_component.rpc_url = url

    def _process_token_address(self, payment_component: EVMPaymentComponent) -> None:
        """
        Resolve and set the token address and decimals if not already present.

        Looks up the token in the Uniswap token list using the payment component's
        CAIP-2 identifier and currency symbol.

        Args:
            payment_component: The payment component to update.
        """
        if payment_component.token:
            return

        address, decimals = self._token_list_fetcher.get_token_address_and_decimals(
            payment_component.caip2,
            payment_component.currency,
        )
        payment_component.token = address
        payment_component.token_decimals = decimals

    def _process_token_info(self, payment_component: EVMPaymentComponent) -> None:
        """
        Fetch and set the token name, EIP-712 version, and decimals if not already present.

        Calls the ERC-20 contract on-chain to retrieve the values.

        Args:
            payment_component: The payment component to update.
        """
        # Only skip if all three fields are already populated.
        # token_decimals is checked with 'is not None' to allow a valid value of 0.
        if (
            payment_component.token_name
            and payment_component.token_version
            and payment_component.token_decimals is not None
        ):
            return

        token_name, token_version, token_decimals = fetch_erc20_name_version_decimals(
            rpc_url=payment_component.rpc_url,
            token_address=payment_component.token,
        )
        payment_component.token_name = token_name
        payment_component.token_version = token_version
        payment_component.token_decimals = token_decimals

    def _validate_payment_component(self, payment_component: EVMPaymentComponent) -> None:
        """
        Assert that the payment component passes its built-in validation.

        Args:
            payment_component: The payment component to validate.

        Raises:
            ValueError: If validation fails.
        """
        if not payment_component.validate_payment():
            raise ValueError(f"Invalid payment component: {payment_component}")

    def _add_to_registry(self, payment_component: EVMPaymentComponent) -> None:
        """
        Append a validated payment component to the registry list.

        Args:
            payment_component: The validated payment component to add.
        """
        self.payment_components.append(payment_component)

    @classmethod
    def get_rpc_url_by_caip2(cls, caip2: str) -> str:
        """
        Retrieve the RPC URL for the payment component matching the given CAIP-2 identifier.

        Args:
            caip2: The CAIP-2 chain identifier (e.g. "eip155:1") to look up.

        Returns:
            The RPC URL string associated with the matching payment component.

        Raises:
            ValueError: If no payment component with the given CAIP-2 is found,
                        or if the matching component has an empty RPC URL.
        """
        for component in cls.payment_components:
            if component.caip2.lower() == caip2.lower():
                if not component.rpc_url:
                    raise ValueError(
                        f"Payment component for chain {caip2} has no RPC URL configured."
                    )
                return component.rpc_url
        raise ValueError(
            f"No payment component found for chain {caip2}."
        )

    def clear(self) -> None:
        """
        Clear all cached data held by the internal fetcher instances.

        Forces subsequent lookups to fetch fresh data from the network.
        """
        self._chain_info_fetcher.clear()
        self._public_rpc_fetcher.clear()
        self._token_list_fetcher.clear()
