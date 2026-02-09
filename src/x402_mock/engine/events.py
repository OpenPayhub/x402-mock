"""
Event-driven system with typed events and clear data flow.

Events carry their own data, handlers return next events, and dependencies
are injected separately from business data.
"""

import asyncio
import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Callable, Optional, List, Awaitable, AsyncGenerator

from pydantic import BaseModel, ConfigDict

from ..adapters.adapters_hub import AdapterHub
from ..adapters.unions import PermitTypes, TransactionConfirmationTypes, VerificationResultTypes
from ..schemas.https import ServerTokenResponse, ServerPaymentScheme

# ==================== Base Event ====================

class BaseEvent(ABC):
    """Base class for all events in the system."""
    
    @abstractmethod
    def __repr__(self) -> str:
        """String representation of the event."""
        pass


# ==================== Trigger Events (External) ====================

class RequestInitEvent(BaseModel, BaseEvent):
    """External trigger: Initialize request with token."""
    token: Optional[str]
    token_endpoint: str = "/token"  # Access token endpoint path
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __repr__(self) -> str:
        return f"RequestInitEvent(token=***)"


class RequestTokenEvent(BaseModel, BaseEvent):
    """External trigger: Request access token with payment permit."""
    permit: PermitTypes
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __repr__(self) -> str:
        return f"RequestTokenEvent(permit={self.permit})"


# ==================== Result Events ====================

class AuthorizationSuccessEvent(BaseModel, BaseEvent):
    """Result: Authorization succeeded with verified payload."""
    payload: Dict[str, Any]
    status_code: int = 200
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __repr__(self) -> str:
        return f"AuthorizationSuccessEvent(payload_keys={list(self.payload.keys())})"


class Http402PaymentEvent(BaseModel, BaseEvent):
    """Result: Payment required - 402 response payload."""
    reason: str
    access_token_endpoint: str
    payment_scheme: ServerPaymentScheme
    payment_instruction: Optional[str] = None
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __repr__(self) -> str:
        return f"Http402PaymentEvent(endpoint={self.access_token_endpoint})"


class VerifySuccessEvent(BaseModel, BaseEvent):
    """Result: Payment verification succeeded."""
    verification_result: VerificationResultTypes
    permit: PermitTypes  # Pass to settlement
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __repr__(self) -> str:
        return f"VerifySuccessEvent(permit={self.permit})"


class VerifyFailedEvent(BaseModel, BaseEvent):
    """Result: Payment verification failed."""
    error_message: str
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __repr__(self) -> str:
        return f"VerifyFailedEvent(error={self.error_message})"


class SettleSuccessEvent(BaseModel, BaseEvent):
    """Result: Settlement succeeded."""
    settlement_result: TransactionConfirmationTypes
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __repr__(self) -> str:
        return f"SettleSuccessEvent(result={self.settlement_result})"


class SettleFailedEvent(BaseModel, BaseEvent):
    """Result: Settlement failed."""
    error_message: str
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __repr__(self) -> str:
        return f"SettleFailedEvent(error={self.error_message})"


class TokenIssuedEvent(BaseModel, BaseEvent):
    """Result: Access token issued after successful verification."""
    token_response: ServerTokenResponse
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __repr__(self) -> str:
        return f"TokenIssuedEvent(token=***)"


class BreakEvent(BaseModel, BaseEvent):
    """Internal event to break the event chain."""
    break_reason: str = ""
    
    model_config = ConfigDict(arbitrary_types_allowed=True)
    
    def __repr__(self) -> str:
        return "BreakEvent()"


# ==================== Dependencies Container ====================

@dataclass(frozen=True)
class Dependencies:
    """Container for infrastructure dependencies (read-only)."""
    adapters_hub: Optional[AdapterHub] = None
    token_key: Optional[str] = None
    token_expires_in: Optional[int] = 3600


# ==================== Event Bus ====================

EventHandlerFunc = Callable[[BaseEvent, Dependencies], Awaitable[Optional[BaseEvent]]]
EventHookFunc = Callable[[BaseEvent, Dependencies], Awaitable[None]]


class EventBus:
    """Event dispatcher for publishing and subscribing to events."""
    
    def __init__(self) -> None:
        """Initialize with empty subscribers and hooks."""
        self._subscribers: Dict[type, list[EventHandlerFunc]] = {}
        self._hooks: Dict[type, list[EventHookFunc]] = {}
    
    def subscribe(self, event_class: type[BaseEvent], handler: EventHandlerFunc) -> None:
        """
        Register an async handler for the given event class.
        Multiple handlers can be subscribed to the same event type and run in parallel.
        
        Args:
            event_class: The event class to subscribe to.
            handler: The async handler function to call when the event is published.
            
        Raises:
            TypeError: If handler is not a coroutine function.
        """
        if not inspect.iscoroutinefunction(handler):
            raise TypeError(f"Handler must be a coroutine function, got {type(handler).__name__}")
        
        if event_class not in self._subscribers:
            self._subscribers[event_class] = []
        self._subscribers[event_class].append(handler)
    
    def hook(self, event_class: type[BaseEvent], hook_func: EventHookFunc) -> None:
        """
        Register a hook for the given event class.
        Hooks are executed before subscribers when the event is dispatched.
        
        Args:
            event_class: The event class to hook into.
            hook_func: The hook function to call when the event is published.
        """
        if not inspect.iscoroutinefunction(hook_func):
            raise TypeError(f"Handler must be a coroutine function, got {type(hook_func).__name__}")
        
        if event_class not in self._hooks:
            self._hooks[event_class] = []
        self._hooks[event_class].append(hook_func)
    
    async def dispatch(self, event: BaseEvent, deps: Dependencies) -> AsyncGenerator[Optional[BaseEvent], None]:
        """
        Dispatch an event to all registered hooks and subscribers.
        Hooks run first (synchronously in order), then all subscribers run in parallel.
        
        Args:
            event: The event to dispatch.
            deps: Dependencies container with injected services.
            
        Yields:
            Results from all subscribers as they complete. Yields nothing if no subscribers are registered.
        """
        # Execute hooks first
        hooks = self._hooks.get(type(event), [])
        await asyncio.gather(*(hook(event, deps) for hook in hooks))
        
        # Execute all subscribers in parallel
        handlers = self._subscribers.get(type(event), [])
        if not handlers:
            return
        
        tasks = [handler(event, deps) for handler in handlers]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            yield result
        

