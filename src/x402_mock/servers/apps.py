"""
X402 Payment Protocol Server - Event-driven FastAPI wrapper.

Provides a simple interface for building X402 payment servers with typed events.
"""

import asyncio
from typing import Optional, Callable, Union, Dict, Any
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from ..engine.events import (
    EventBus,
    Dependencies,
    BaseEvent,
    RequestInitEvent,
    RequestTokenEvent,
    TokenIssuedEvent,
    VerifyFailedEvent,
    AuthorizationSuccessEvent,
    Http402PaymentEvent,
)
from ..engine.executors import EventChain
from ..adapters.adapters_hub import AdapterHub, PaymentComponentTypes
from ..schemas.https import ClientTokenRequest
from .flows import setup_event_bus


class Http402Server(FastAPI):
    """FastAPI server with X402 payment protocol support."""
    
    def __init__(
        self,
        token_key: str,
        adapter_hub: Optional[AdapterHub] = None,
        token_expires_in: int = 3600,
        enable_auto_settlement: bool = True,
        token_endpoint: str = "/token",
        **fastapi_kwargs
    ):
        """Initialize X402 payment server.
        
        Args:
            token_key: Secret key for signing access tokens
            adapter_hub: Payment adapter hub (default: new instance)
            token_expires_in: Token lifetime in seconds (default: 3600)
            enable_auto_settlement: Auto-settle after verification (default: True)
            token_endpoint: Token endpoint path (default: /token)
            **fastapi_kwargs: FastAPI arguments (title, version, etc.)
        """
        # Setup dependencies and event bus before FastAPI init
        self.adapter_hub = adapter_hub or AdapterHub()
        self.depends = Dependencies(
            adapters_hub=self.adapter_hub,
            token_key=token_key,
            token_expires_in=token_expires_in
        )
        self.event_bus: EventBus = setup_event_bus(enable_auto_settlement=enable_auto_settlement)

        # Initialize FastAPI with lifespan
        super().__init__(**fastapi_kwargs)
        
        self.token_endpoint = token_endpoint
        
        # Setup token endpoint
        self._setup_token_endpoint(token_endpoint)
    
    def add_payment_method(self, payment_component: Union[PaymentComponentTypes, Dict[str, Any]]) -> None:
        """Register a payment method.
        
        Args:
            payment_component: A ``PaymentComponentTypes`` instance or a plain dict
                               that will be coerced into the correct type.
        """
        self.adapter_hub.register_payment_methods(payment_component=payment_component, client_role=False)
    
    def subscribe(self, event_class: type[BaseEvent], handler: Callable) -> None:
        """Register event handler.
        
        Args:
            event_class: Event type to handle
            handler: Async function(event, deps) -> Optional[BaseEvent]
        
        Example:
            ```python
            async def my_handler(event: TokenIssuedEvent, deps: Dependencies):
                # Custom logic
                return None  # or return another event
            
            app.subscribe(TokenIssuedEvent, my_handler)
            ```
        """
        self.event_bus.subscribe(event_class, handler)
    
    def add_hook(self, event_class: type[BaseEvent], hook: Callable) -> None:
        """Register event hook for side effects.
        
        Args:
            event_class: Event type to hook into
            hook: Async function(event, deps) -> None
        
        Example:
            ```python
            async def log_event(event, deps):
                print(f"Event: {event}")
            
            app.add_hook(TokenIssuedEvent, log_event)
            ```
        """
        self.event_bus.hook(event_class, hook)
    
    def hook(self, event_class: type[BaseEvent]) -> Callable:
        """Decorator for registering event hooks.
        
        Args:
            event_class: Event type to hook into
        
        Example:
            @app.hook(TokenIssuedEvent)
            async def on_token_issued(event, deps):
                await send_analytics(event)
        """
        def decorator(hook_func: Callable) -> Callable:
            self.event_bus.hook(event_class, hook_func)
            return hook_func
        return decorator
    
    def payment_required(self, route_handler):
        """Decorator to protect routes with payment verification.
        
        Returns 402 response if payment required, otherwise executes handler with verified payload.
        
        Example:
            ```python
            @app.payment_required
            @app.get("/data")
            async def get_data(payload):
                return {"user": payload["address"]}
            ```
        """
        async def wrapper(authorization: str = Header(None)):
            # Execute payment verification chain
            event_chain = EventChain(
                self.event_bus, 
                self.depends, 
            )
            executor = event_chain.execute(
                    initial_event=RequestInitEvent(
                    token=authorization,
                    token_endpoint=self.token_endpoint
                )
            )
            async for event in executor:
                if isinstance(event, Http402PaymentEvent):
                    return JSONResponse(
                        status_code=402,
                        content=event.model_dump(mode="json")
                    )
                    
                if isinstance(event, AuthorizationSuccessEvent):
                    return await route_handler(event.payload)
            
            return JSONResponse(
                status_code=500,
                content={"error": "Payment verification failed"}
            )

        return wrapper
    
    def _setup_token_endpoint(self, path: str = "/token") -> None:
        """Setup token exchange endpoint.
        
        Args:
            path: Endpoint path (default: /token)
        """
        @self.post(path)
        async def token_accessor(request: Request):
            """Token endpoint to exchange payment permit for access token."""
            payload = await request.json()
            client_request = ClientTokenRequest.model_validate(payload)
            if client_request:
                event_chain = EventChain(
                    self.event_bus, 
                    self.depends
                )
                
                executor = event_chain.execute(RequestTokenEvent(
                    permit=payload.get("permit"),
                ))
                
                async for event in executor:
                    if isinstance(event, TokenIssuedEvent):

                        return JSONResponse(
                            status_code=200,
                            content=event.token_response.model_dump(mode="json")
                        )
                    if isinstance(event, VerifyFailedEvent):
                        return JSONResponse(
                            status_code=400,
                            content={"error": event.error_message}
                        )

            return JSONResponse(
                status_code=500,
                content={"error": "Token issuance failed"}
            )
