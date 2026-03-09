from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel
from mcp.server.fastmcp import FastMCP

from ..adapters import AdapterHub
from ..adapters.unions import PermitTypes, PaymentComponentTypes
from ..engine import EventBus, EventChain
from ..engine.events import (
    Dependencies,
    RequestTokenEvent,
    VerifySuccessEvent,
    VerifyFailedEvent,
    SettleSuccessEvent,
    SettleFailedEvent,
)
from ..servers.flows import handle_request_token, handle_settlement
from ..clients.http_client import Http402Client

class SpecificRequest(BaseModel):
    """Example of a specific request type that might be used in the FacilitorTools event flow."""

    payload: List[PaymentComponentTypes]


class FacilitorTools:
    """
    FacilitorTools exposes exactly two MCP tools:

    1. ``signature``         — generate a signed permit from a list of remote
                               payment components (client-side signing).
    2. ``verify_and_settle`` — verify a permit signature and settle on-chain
                               in a single workflow (no token issuance).                        
    """

    def __init__(self, adapter_hub: AdapterHub, mcp: FastMCP, client_role: bool = False) -> None:
        self._adapter_hub = adapter_hub
        self._mcp = mcp
        self._deps = Dependencies(adapters_hub=adapter_hub)
        self._event_bus = self._setup_event_bus()
        if not client_role:
            self._server_register()
        else:
            self._client_register()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _setup_event_bus(self) -> EventBus:
        """Build a minimal event bus that only verifies and settles (no token issue)."""
        event_bus = EventBus()
        event_bus.subscribe(RequestTokenEvent, handle_request_token)
        event_bus.subscribe(VerifySuccessEvent, handle_settlement)
        return event_bus

    def _server_register(self) -> None:
        """Register MCP tools on the provided FastMCP instance."""
        
        deps = self._deps
        event_bus = self._event_bus

        @self._mcp.tool()
        async def verify_and_settle(
            permit: PermitTypes,
        ) -> Union[SettleSuccessEvent, SettleFailedEvent, VerifyFailedEvent]:
            """
            Verify a payment permit signature and settle on-chain in one workflow step.

            Event flow:
                RequestTokenEvent → (verify) → VerifySuccessEvent
                                             → (settle) → SettleSuccessEvent | SettleFailedEvent
                                  → (verify fail) → VerifyFailedEvent

            Args:
                permit: Signed payment permit (dict or typed PermitTypes).

            Returns:
                SettleSuccessEvent  — permit valid, settlement confirmed.
                SettleFailedEvent   — permit valid, settlement failed on-chain.
                VerifyFailedEvent   — permit signature invalid.
            """
            event_chain = EventChain(event_bus, deps)
            async for event in event_chain.execute(RequestTokenEvent(permit=permit)):
                if isinstance(event, (SettleSuccessEvent, SettleFailedEvent, VerifyFailedEvent)):
                    return event
                
    def _client_register(self) -> None:
        """Register client-side tools (e.g. signature generation) on the provided FastMCP instance."""
        adapter_hub = self._adapter_hub
        
        @self._mcp.tool()
        async def signature(
            list_components: List[PaymentComponentTypes],
        ) -> PermitTypes:
            """
            Generate a signed payment permit from a list of remote payment components.

            Selects a compatible local payment method by matching payment_type, token,
            and amount against the server-advertised options, then produces a signed
            permit ready to be submitted to the server's token endpoint.

            Args:
                list_components: A List[PaymentComponentTypes] wrapping the payment components
                                 advertised by the server in its 402 Payment Required
                                 response. Each component specifies payment_type,
                                 token address, amount, and chain information for a
                                 supported payment method.

            Returns:
                A signed PermitTypes object ready to be sent to the server's
                token endpoint for verification and settlement.
            """
            return await adapter_hub.signature(list_components)
        
        @self._mcp.tool()
        async def source_request(
            url: str,
            method: str = "GET",
            headers: Optional[Dict[str, str]] = None,
            timeout: float = 30.0,
        ) -> Dict[str, Any]:
            """
            Access an x402-mock payment-protected resource with automatic payment signing and retry.

            Sends the initial request to the target URL. If the server responds with
            HTTP 402 Payment Required, the client automatically:
              1. Parses the payment components from the 402 response.
              2. Signs a payment permit using the configured local adapter.
              3. Retries the original request with the signed permit attached.

            Args:
                url: Target URL of the x402-mock payment-protected resource.
                method: HTTP method (default: GET).
                headers: Optional additional request headers.
                timeout: Request timeout in seconds (default: 30).

            Returns:
                Dict with keys: status_code (int), headers (dict), body (str),
                representing the final response after successful payment and retry.
            """
            async with Http402Client(adapter_hub=adapter_hub, timeout=timeout) as client:
                response = await client.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                )
                return {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text,
                }