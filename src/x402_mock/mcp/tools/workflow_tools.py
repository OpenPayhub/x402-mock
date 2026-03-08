"""
Server Workflow MCP Tools

Exposes the X402 payment server workflows as MCP-callable tools, built
directly on top of AdapterHub, EventBus, and Dependencies — with no
dependency on Http402Server.

MCP tools (callable by agents over the protocol):
    - verify_request : Validate the Authorization header token.
                       Returns Http402PaymentEvent (payment required) or
                       AuthorizationSuccessEvent (access granted).
    - issue_token    : Verify a signed payment permit and issue an access token.
                       Returns TokenIssuedEvent (success) or
                       VerifyFailedEvent (failure).

Direct Python methods (set-up time only, not MCP tools):
    - subscribe(event_class, handler) : Register an event handler.
    - add_hook(event_class, hook)     : Register a side-effect hook.
    - hook(event_class)               : Decorator form of add_hook.
"""

from typing import Callable, Dict, Optional, Union

from mcp.server.fastmcp import FastMCP

from ...adapters.adapters_hub import AdapterHub, PaymentComponentTypes
from ...clients.http_client import Http402Client
from ...engine.events import (
    BaseEvent,
    Dependencies,
    EventBus,
    EventHandlerFunc,
    EventHookFunc,
    RequestInitEvent,
    RequestTokenEvent,
    Http402PaymentEvent,
    AuthorizationSuccessEvent,
    TokenIssuedEvent,
    VerifyFailedEvent,
)
from ...adapters.unions import PermitTypes
from ...engine.executors import EventChain
from ...servers.flows import setup_event_bus


class ServerWorkflowTools:
    """
    MCP tool provider that drives X402 payment workflows.

    Owns all required infrastructure (AdapterHub, EventBus, Dependencies)
    directly, with no coupling to Http402Server.  The two MCP tools mirror
    the two request paths of the X402 protocol:

    1. ``verify_request``  — checks whether the caller already holds a valid
       access token, or responds with a 402 payment scheme.
    2. ``issue_token``     — accepts a signed payment permit, verifies it on
       chain, and returns a fresh Bearer token on success.

    Usage::

        hub   = AdapterHub(evm_private_key="0x...")
        tools = ServerWorkflowTools(
            mcp=mcp_server,
            adapter_hub=hub,
            token_key="secret",
        )

        # Register side-effect hooks at setup time (Python API)
        @tools.hook(TokenIssuedEvent)
        async def on_token(event, deps):
            await analytics.record(event)
    """

    def __init__(
        self,
        mcp: FastMCP,
        adapter_hub: AdapterHub,
        token_key: str,
        token_endpoint: str = "/token",
        token_expires_in: int = 3600,
        enable_auto_settlement: bool = True,
    ) -> None:
        """
        Build the provider, wire up infrastructure, and register MCP tools.

        Args:
            mcp: FastMCP server instance to register tools on.
            adapter_hub: AdapterHub instance used for payment verification
                and settlement.
            token_key: Secret key for signing and verifying Bearer tokens.
            token_endpoint: URL path returned to clients inside Http402PaymentEvent
                so they know where to submit payment.  Defaults to ``"/token"``.
            token_expires_in: Lifetime of issued Bearer tokens in seconds.
                Defaults to 3600.
            enable_auto_settlement: When True the event chain automatically
                settles the payment on-chain after successful verification.
                Defaults to True.
        """
        self._adapter_hub = adapter_hub
        self._token_endpoint = token_endpoint

        self._deps = Dependencies(
            adapters_hub=adapter_hub,
            token_key=token_key,
            token_expires_in=token_expires_in,
        )
        self._event_bus: EventBus = setup_event_bus(
            enable_auto_settlement=enable_auto_settlement
        )

        self._mcp = mcp
        self._register()

    # =========================================================================
    # Internal: register MCP tools
    # =========================================================================

    def _register(self) -> None:
        """Register the two workflow tools on the FastMCP server."""
        deps = self._deps
        token_endpoint = self._token_endpoint
        event_bus = self._event_bus

        @self._mcp.tool()
        async def verify_request(
            token: Optional[str],
        ) -> Union[Http402PaymentEvent, AuthorizationSuccessEvent]:
            """
            Validate the caller's Authorization header token.

            Runs the RequestInitEvent chain through the event bus.

            * If ``token`` is absent, expired, or malformed the chain
              produces an Http402PaymentEvent containing the payment scheme
              the caller must fulfill before retrying.
            * If ``token`` is a valid Bearer token, the chain produces an
              AuthorizationSuccessEvent with the decoded payload.

            Args:
                token: Raw value of the HTTP ``Authorization`` header
                    (e.g. ``"Bearer eyJ..."``), or None when the header is
                    missing.

            Returns:
                Http402PaymentEvent when payment is required or the token is
                invalid; AuthorizationSuccessEvent when access is granted.
            """
            event_chain = EventChain(event_bus, deps)
            async for event in event_chain.execute(
                RequestInitEvent(token=token, token_endpoint=token_endpoint)
            ):
                if isinstance(event, (Http402PaymentEvent, AuthorizationSuccessEvent)):
                    return event

        @self._mcp.tool()
        async def issue_token(
            permit: PermitTypes,
        ) -> Union[TokenIssuedEvent, VerifyFailedEvent]:
            """
            Verify a signed payment permit and issue an access token.

            Runs the RequestTokenEvent chain through the event bus.

            The chain verifies the permit signature on-chain via AdapterHub.
            When auto-settlement is enabled, settlement runs as a background
            side-effect and does not block the returned event.

            * On success a TokenIssuedEvent is returned containing a signed
              Bearer token the caller can use for subsequent requests.
            * On failure a VerifyFailedEvent is returned with an error
              message and verification status.

            Args:
                permit: A typed PermitTypes instance (e.g. Permit2Signature or
                    ERC3009Authorization) containing the signed authorization
                    data. Must include at minimum ``permit_type``, ``token``,
                    ``amount``, and the chain-specific signature fields.

            Returns:
                TokenIssuedEvent when verification succeeds; VerifyFailedEvent
                when the permit signature is invalid or verification fails.
            """
            event_chain = EventChain(event_bus, deps)
            async for event in event_chain.execute(
                RequestTokenEvent(permit=permit)
            ):
                if isinstance(event, (TokenIssuedEvent, VerifyFailedEvent)):
                    return event

    # =========================================================================
    # Python API: event bus management (not exposed as MCP tools)
    # =========================================================================

    def subscribe(
        self,
        event_class: type[BaseEvent],
        handler: EventHandlerFunc,
    ) -> None:
        """
        Register an async event handler on the internal event bus.

        Handlers receive the event and dependencies and may return an
        Optional[BaseEvent] to continue the chain.  Multiple handlers on
        the same event type run in parallel.

        This is a Python-only API and is intentionally not exposed as an MCP
        tool: async callables cannot be serialised over the MCP JSON protocol.

        Args:
            event_class: The event type to subscribe to.
            handler: Async function ``(event, deps) -> Optional[BaseEvent]``.

        Raises:
            TypeError: If handler is not a coroutine function.

        Example::

            async def on_auth(event: AuthorizationSuccessEvent, deps):
                await log_access(event.payload)

            tools.subscribe(AuthorizationSuccessEvent, on_auth)
        """
        self._event_bus.subscribe(event_class, handler)

    def add_hook(
        self,
        event_class: type[BaseEvent],
        hook: EventHookFunc,
    ) -> None:
        """
        Register an async side-effect hook on the internal event bus.

        Hooks run before subscribers on each dispatch and are intended for
        pure side effects (logging, metrics, notifications).  They do not
        influence the event chain flow.

        This is a Python-only API and is intentionally not exposed as an MCP
        tool: async callables cannot be serialised over the MCP JSON protocol.

        Args:
            event_class: The event type to hook into.
            hook: Async function ``(event, deps) -> None``.

        Raises:
            TypeError: If hook is not a coroutine function.

        Example::

            async def log_event(event, deps):
                print(f"[hook] {event!r}")

            tools.add_hook(TokenIssuedEvent, log_event)
        """
        self._event_bus.hook(event_class, hook)

    def hook(self, event_class: type[BaseEvent]) -> Callable:
        """
        Decorator that registers an async side-effect hook.

        Convenience wrapper around add_hook for use at module set-up time.

        Args:
            event_class: The event type to hook into.

        Returns:
            A decorator that registers the decorated coroutine as a hook and
            returns it unchanged.

        Example::

            @tools.hook(SettleSuccessEvent)
            async def on_settle(event: SettleSuccessEvent, deps):
                await notify_settlement(event.settlement_result)
        """
        def decorator(hook_func: EventHookFunc) -> EventHookFunc:
            self._event_bus.hook(event_class, hook_func)
            return hook_func
        return decorator


class ClientWorkflowTools:
    """
    MCP tool provider that drives X402 client payment workflows.

    Acts as the paying party in the X402 protocol.  Wraps ``Http402Client``
    so that an AI agent can register payment methods once and then make
    ordinary HTTP requests — 402 responses are handled transparently.

    The two MCP tools mirror the two client-side actions of the X402 protocol:

    1. ``add_payment_method`` — register a local payment capability so the
       client knows how to sign permits when a 402 is received.
    2. ``make_request``       — issue an HTTP request; if the server returns
       402 the client automatically generates a permit, exchanges it for a
       Bearer token, and retries the original request.

    Usage::

        hub   = AdapterHub(evm_private_key="0x...")
        tools = ClientWorkflowTools(mcp=mcp_server, adapter_hub=hub)

        # MCP tool calls from the agent:
        # 1. add_payment_method(payment_component={...})
        # 2. make_request(method="GET", url="https://api.example.com/data")
    """

    def __init__(
        self,
        mcp: FastMCP,
        adapter_hub: Optional[AdapterHub] = None,
    ) -> None:
        """
        Build the provider and register MCP tools.

        Args:
            mcp: FastMCP server instance to register tools on.
            adapter_hub: Shared ``AdapterHub`` used to generate payment
                permits.  A fresh hub (with no payment methods) is created
                when omitted; payment methods must then be registered via
                the ``add_payment_method`` MCP tool before making requests.
        """
        self._adapter_hub = adapter_hub or AdapterHub()
        self._http_client = Http402Client(adapter_hub=self._adapter_hub)
        self._mcp = mcp
        self._register()

    # =========================================================================
    # Internal: register MCP tools
    # =========================================================================

    def _register(self) -> None:
        """Register the two workflow tools on the FastMCP server."""
        http_client = self._http_client

        @self._mcp.tool()
        async def add_payment_method(
            payment_component: PaymentComponentTypes,
        ) -> str:
            """
            Register a local payment method for automatic 402 handling.

            Adds a signed payment capability to the client so it can
            automatically fulfil 402 Payment Required responses.  Must be
            called at least once before ``make_request`` is used against a
            402-protected endpoint.

            Args:
                payment_component: A ``PaymentComponentTypes`` instance
                    describing the payment method — chain, token, amount,
                    and the private key used for signing permits.

            Returns:
                A confirmation string on success.
            """
            http_client.add_payment_method(payment_component)
            return "Payment method registered successfully."

        @self._mcp.tool()
        async def make_request(
            method: str,
            url: str,
            headers: Optional[Dict[str, str]] = None,
            body: Optional[str] = None,
        ) -> Dict:
            """
            Make an HTTP request with automatic 402 payment handling.

            Sends the request and, if the server responds with 402 Payment
            Required, transparently completes the full payment cycle:

            1. Parses the server's payment requirements from the 402 body.
            2. Generates a signed permit via the registered payment methods.
            3. Exchanges the permit for a Bearer token at the server's token
               endpoint.
            4. Retries the original request with the ``Authorization`` header.

            Args:
                method: HTTP method (``GET``, ``POST``, ``PUT``, etc.).
                url: Full URL to request (including scheme and host).
                headers: Optional HTTP headers as a ``{name: value}`` dict.
                body: Optional request body as a plain string.

            Returns:
                A dict with three keys:

                - ``status_code`` (int)  — Final HTTP status code.
                - ``headers``     (dict) — Response headers as a flat dict.
                - ``body``        (str)  — Response body decoded as text.
            """
            kwargs: Dict = {}
            if headers:
                kwargs["headers"] = headers
            if body:
                kwargs["content"] = body.encode()

            response = await http_client.request(method, url, **kwargs)
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response.text,
            }