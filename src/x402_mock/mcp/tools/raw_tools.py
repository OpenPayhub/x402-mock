from typing import Any, Dict, List, Literal, Optional, Tuple

from mcp.server.fastmcp import FastMCP

from ...adapters import (
    AdapterHub,
    PermitTypes,
    PaymentComponentTypes,
    VerificationResultTypes,
    TransactionConfirmationTypes,
)
from ...adapters.evm import (
    EvmChainInfo,
    EvmChainList,
    EvmPublicRpcFromChainList,
    EvmTokenListFromUniswap,
    EvmChainInfoFromEthereumLists,
    get_private_key_from_env,
    get_rpc_key_from_env,
    fetch_erc20_name_version_decimals,
)


class AdapterHubTools:
    """
    MCP tool provider that wraps AdapterHub methods as callable MCP tools.

    Registers each AdapterHub operation with a FastMCP server instance so that
    LLM agents can invoke blockchain adapter functionality over the MCP protocol.

    Usage::

        hub = AdapterHub(evm_private_key="0x...")
        tools = AdapterHubTools(mcp=mcp_server, hub=hub)
    """

    def __init__(self, mcp: FastMCP, hub: AdapterHub) -> None:
        """
        Initialize the tool provider and register all tools with the MCP server.

        Args:
            mcp: The FastMCP server instance to register tools on.
            hub: The AdapterHub instance whose methods will be exposed as tools.
        """
        self._hub = hub
        self._mcp = mcp
        self._register()

    def _register(self) -> None:
        """Register all AdapterHub methods as MCP tools on the server."""
        hub = self._hub
        mcp = self._mcp

        @mcp.tool()
        def register_payment_methods(
            payment_component: PaymentComponentTypes,
            client_role: bool = False,
        ) -> None:
            """
            Register a payment component with the adapter hub.

            In server role (client_role=False), the hub automatically fills the
            ``pay_to`` field with the wallet address from the matching chain adapter.
            In client role (client_role=True), the ``pay_to`` field is left untouched.

            Args:
                payment_component: A typed PaymentComponentTypes instance
                    (e.g. EVMPaymentComponent) containing at least
                    ``payment_type``, ``token``, and ``amount``.
                client_role: False (default) for the receiving/server side;
                    True for the signing/paying client side.

            Returns:
                None

            Raises:
                TypeError: If the blockchain type cannot be determined from the
                    component, or if no adapter is registered for that type.
                ValueError: If the component fails chain validation.
            """
            hub.register_payment_methods(payment_component, client_role)

        @mcp.tool()
        async def verify_signature(
            permit_payload: PermitTypes,
        ) -> Optional[VerificationResultTypes]:
            """
            Verify a permit signature using automatic blockchain type detection.

            Converts the permit payload to the appropriate typed model, matches its
            token against registered payment components, and delegates verification
            to the corresponding chain adapter.

            Args:
                permit_payload: A PermitTypes instance (e.g. ERC3009Authorization or
                    Permit2Signature) containing the signed authorization data.

            Returns:
                A VerificationResultTypes instance (e.g. EVMVerificationResult)
                with the verification outcome, or None if the adapter returns nothing.

            Raises:
                TypeError: If the blockchain type cannot be determined from the payload.
                ValueError: If no matching payment component is registered for the
                    given token, or if the permit payload is invalid.
            """
            return await hub.verify_signature(permit_payload)

        @mcp.tool()
        async def settle(
            permit_payload: PermitTypes,
        ) -> Optional[TransactionConfirmationTypes]:
            """
            Execute on-chain settlement for a signed permit.

            Converts the permit payload to the appropriate typed model and delegates
            the settlement transaction to the corresponding chain adapter.

            Args:
                permit_payload: A PermitTypes instance (e.g. ERC3009Authorization or
                    Permit2Signature) representing the signed permit to settle.

            Returns:
                A TransactionConfirmationTypes instance (e.g. EVMTransactionConfirmation)
                containing the transaction receipt, or None if the adapter returns nothing.

            Raises:
                TypeError: If the blockchain type cannot be determined from the payload.
                ValueError: If the permit payload cannot be converted to a typed model.
            """
            return await hub.settle(permit_payload)

        @mcp.tool()
        async def signature(
            list_components: List[PaymentComponentTypes],
        ) -> PermitTypes:
            """
            Generate a signed permit from a list of remote payment components.

            Matches the remote components against the locally registered payment
            methods, selects the first compatible one, and delegates signing to
            the appropriate chain adapter.  ``initialize(client_role=True)`` is
            called automatically if it has not been called already.

            Args:
                list_components: A list of PaymentComponentTypes instances
                    (e.g. EVMPaymentComponent) offered by the remote server.
                    Each entry must contain at least ``payment_type``, ``token``,
                    and ``amount``.

            Returns:
                A signed PermitTypes instance (e.g. Permit2Signature or
                ERC3009Authorization) produced by the matching chain adapter.

            Raises:
                ValueError: If no matching payment component is found among the
                    remote components, or if type conversion fails.
                TypeError: If the blockchain type cannot be determined.
            """
            return await hub.signature(list_components)


class EvmTools:
    """
    MCP tool provider that exposes EVM utility functions as callable MCP tools.

    Wraps three stateful helper classes (EvmPublicRpcFromChainList,
    EvmTokenListFromUniswap, EvmChainInfoFromEthereumLists) and three
    stateless helpers (get_private_key_from_env, get_rpc_key_from_env,
    fetch_erc20_name_version_decimals).

    Every class-based tool calls ``clear()`` on its helper instance before
    executing, so each invocation always fetches fresh data from the network.

    Usage::

        tools = EvmTools(mcp=mcp_server)
    """

    def __init__(self, mcp: FastMCP) -> None:
        """
        Initialize the tool provider and register all tools with the MCP server.

        Args:
            mcp: The FastMCP server instance to register tools on.
        """
        self._chainlist = EvmPublicRpcFromChainList()
        self._uniswap = EvmTokenListFromUniswap()
        self._eth_lists = EvmChainInfoFromEthereumLists()
        self._mcp = mcp
        self._register()

    def _register(self) -> None:
        """Register all EVM utility functions as MCP tools on the server."""
        mcp = self._mcp
        chainlist = self._chainlist
        uniswap = self._uniswap
        eth_lists = self._eth_lists

        # ── Standalone helpers ────────────────────────────────────────────────

        @mcp.tool()
        def evm_get_private_key_from_env() -> Optional[str]:
            """
            Load the EVM server private key from the process environment.

            Reads the ``EVM_PRIVATE_KEY`` environment variable, which must be
            set to a 0x-prefixed hex private key.

            Returns:
                The raw private key string, or None if ``EVM_PRIVATE_KEY`` is
                not set.
            """
            return get_private_key_from_env()

        @mcp.tool()
        def evm_get_rpc_key_from_env(
            env_variable_name: str = "EVM_INFURA_KEY",
        ) -> Optional[str]:
            """
            Load an EVM infrastructure API key from the process environment.

            Reads the named environment variable, which should hold an Infura
            or Alchemy API key.  If not set, the adapter falls back to public
            (rate-limited) RPC endpoints.

            Args:
                env_variable_name: Name of the environment variable to read.
                    Defaults to ``"EVM_INFURA_KEY"``.

            Returns:
                The API key string, or None if the variable is not set.
            """
            return get_rpc_key_from_env(env_variable_name)

        @mcp.tool()
        def evm_fetch_erc20_info(
            rpc_url: str,
            token_address: str,
        ) -> Dict[str, Any]:
            """
            Fetch the name, EIP-712 version, and decimals of an ERC-20 token.

            Calls the token contract's ``name()``, ``version()`` (optional),
            and ``decimals()`` view functions via the given RPC.

            Args:
                rpc_url: JSON-RPC endpoint for the chain that hosts the token
                    (e.g. ``"https://mainnet.infura.io/v3/<key>"``).
                token_address: Checksum or lowercase EVM contract address
                    (0x-prefixed, 42 chars).

            Returns:
                A dict with keys:
                    - ``name`` (``str | None``): ERC-20 ``name()`` value, or
                      None if the call fails.
                    - ``version`` (``str``): EIP-712 ``version()`` value,
                      defaults to ``"0"`` when the contract does not expose it.
                    - ``decimals`` (``int``): ERC-20 ``decimals()`` value.
            """
            name, version, decimals = fetch_erc20_name_version_decimals(
                rpc_url=rpc_url, token_address=token_address
            )
            return {"name": name, "version": version, "decimals": decimals}

        # ── EvmPublicRpcFromChainList ─────────────────────────────────────────

        @mcp.tool()
        def chainlist_fetch_data() -> List[Dict[str, Any]]:
            """
            Fetch the raw chain list from Chainlist.org.

            Clears the in-memory cache before every call, then makes a live
            HTTP request to ensure the returned data is always up to date.

            Returns:
                A list of chain-entry dicts as returned by Chainlist.org.

            Raises:
                ValueError: If the response is not a list.
                httpx.HTTPStatusError: If the HTTP request fails.
                RuntimeError: If the response is not valid JSON.
            """
            result = chainlist.fetch_data_from_chainlist()
            chainlist.clear()
            return result

        @mcp.tool()
        def chainlist_get_chain(caip2: str) -> Optional[EvmChainList]:
            """
            Resolve the public RPC list for a specific chain from Chainlist.org.

            Clears the in-memory cache before every call so that the data is
            always fetched fresh from the network.

            Args:
                caip2: CAIP-2 chain identifier (e.g. ``"eip155:1"``).

            Returns:
                An EvmChainList instance for the chain, or None if the chain
                is not found on Chainlist.org.
            """
            result = chainlist.get_specific_chain_public_rpcs(caip2)
            chainlist.clear()
            return result

        @mcp.tool()
        def chainlist_pick_rpc(
            caip2: str,
            start_with: Literal["https://", "wss://"] = "https://",
            tracking_type: Optional[Literal["none", "limited", "yes"]] = None,
        ) -> Optional[str]:
            """
            Pick a single public RPC URL for a chain from Chainlist.org.

            Clears the in-memory cache before every call, then filters
            available RPCs by protocol prefix and optional tracking policy.

            Args:
                caip2: CAIP-2 chain identifier (e.g. ``"eip155:1"``).
                start_with: Protocol prefix to filter by.  ``"https://"``
                    (default) returns HTTP endpoints; ``"wss://"`` returns
                    WebSocket endpoints.
                tracking_type: Tracking policy filter.  ``"none"`` selects
                    privacy-preserving nodes; ``"limited"`` or ``"yes"`` allow
                    varying degrees of tracking.  None (default) accepts any.

            Returns:
                A matching RPC URL string, or None if no suitable endpoint is
                found.
            """
            result = chainlist.pick_public_rpc(caip2, start_with, tracking_type)
            chainlist.clear()
            return result

        # ── EvmTokenListFromUniswap ───────────────────────────────────────────

        @mcp.tool()
        def uniswap_fetch_tokens() -> List[Dict[str, Any]]:
            """
            Fetch the official Uniswap ERC-20 token list.

            Clears the in-memory cache before every call, then makes a live
            HTTP request to ensure the returned data is always up to date.

            Returns:
                A list of token-metadata dicts from the Uniswap token list.

            Raises:
                ValueError: If the response is empty or the ``tokens`` key is
                    missing.
                httpx.HTTPError: If the network request fails.
            """
            result = uniswap.fetch_token_list()
            uniswap.clear()
            return result

        @mcp.tool()
        def uniswap_get_token(
            caip2: str,
            symbol: str,
        ) -> Dict[str, Any]:
            """
            Look up the contract address and decimals of a token on a specific chain.

            Clears the in-memory cache before every call, then searches the
            freshly fetched Uniswap token list for a token matching both the
            CAIP-2 chain identifier and the ticker symbol (case-sensitive).

            Args:
                caip2: CAIP-2 chain identifier (e.g. ``"eip155:1"``).
                symbol: Token ticker symbol (e.g. ``"USDC"``, ``"WETH"``).

            Returns:
                A dict with keys:
                    - ``address`` (``str``): ERC-20 contract address.
                    - ``decimals`` (``int``): Token precision (e.g. ``6`` for USDC).

            Raises:
                ValueError: If the token is not found on the specified chain, or
                    if the found entry contains invalid data.
            """
            address, decimals = uniswap.get_token_address_and_decimals(caip2, symbol)
            uniswap.clear()
            return {"address": address, "decimals": decimals}

        # ── EvmChainInfoFromEthereumLists ─────────────────────────────────────

        @mcp.tool()
        def eth_lists_fetch_chain_info(caip2: str) -> EvmChainInfo:
            """
            Fetch full chain metadata from the ethereum-lists repository.

            Clears the per-chain cache before every call so that data is
            always retrieved fresh from the network.

            Args:
                caip2: CAIP-2 chain identifier (e.g. ``"eip155:1"``).

            Returns:
                An EvmChainInfo Pydantic model with the chain's full metadata.

            Raises:
                httpx.HTTPError: If the upstream file is not found or
                    unavailable.
                TypeError: If the payload does not conform to EvmChainInfo.
            """
            result = eth_lists.fetch_chain_info(caip2)
            eth_lists.clear()
            return result

        @mcp.tool()
        def eth_lists_get_infura_rpc(
            caip2: str,
            start_with: Literal["https:", "wss:"] = "https:",
        ) -> Optional[str]:
            """
            Return the first Infura RPC URL (with API-key placeholder) for a chain.

            Clears the per-chain cache before every call.  The placeholder
            token in the returned URL must be substituted with a real Infura
            project key before use.

            Args:
                caip2: CAIP-2 chain identifier (e.g. ``"eip155:1"``).
                start_with: Protocol prefix to filter by.  ``"https:"``
                    (default) returns HTTPS; ``"wss:"`` returns WebSocket.

            Returns:
                An Infura RPC URL string containing the API-key placeholder,
                or None if Infura is not available for this chain.
            """
            result = eth_lists.get_infura_rpc_url(caip2, start_with)
            eth_lists.clear()
            return result

        @mcp.tool()
        def eth_lists_get_alchemy_rpc(
            caip2: str,
            start_with: Literal["https:", "wss:"] = "https:",
        ) -> Optional[str]:
            """
            Return the first Alchemy RPC URL (with API-key placeholder) for a chain.

            Clears the per-chain cache before every call.  The placeholder
            token in the returned URL must be substituted with a real Alchemy
            API key before use.

            Args:
                caip2: CAIP-2 chain identifier (e.g. ``"eip155:1"``).
                start_with: Protocol prefix to filter by.  ``"https:"``
                    (default) returns HTTPS; ``"wss:"`` returns WebSocket.

            Returns:
                An Alchemy RPC URL string containing the API-key placeholder,
                or None if Alchemy is not available for this chain.
            """
            result = eth_lists.get_alchemy_rpc_url(caip2, start_with)
            eth_lists.clear()
            return result

        @mcp.tool()
        def eth_lists_get_public_rpcs(caip2: str) -> List[str]:
            """
            Return all public (keyless) RPC URLs for a chain from ethereum-lists.

            Clears the per-chain cache before every call.  Public RPCs require
            no API key but may be subject to rate limits.

            Args:
                caip2: CAIP-2 chain identifier (e.g. ``"eip155:1"``).

            Returns:
                A list of RPC URL strings available without an API key.  May
                be empty if no public endpoints are listed for the chain.
            """
            result = eth_lists.get_public_rpc_urls(caip2)
            eth_lists.clear()
            return result