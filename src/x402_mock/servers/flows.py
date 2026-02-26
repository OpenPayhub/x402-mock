"""
Built-in event handlers for X402 payment protocol workflow.

Implements the core payment flow: token verification → payment verification → settlement.
"""

import asyncio

from ..engine.events import (
    EventBus,
    Dependencies,
    RequestInitEvent,
    RequestTokenEvent,
    Http402PaymentEvent,
    VerifySuccessEvent,
    AuthorizationSuccessEvent,
    VerifyFailedEvent,
    SettleSuccessEvent,
    SettleFailedEvent,
    TokenIssuedEvent,
    BreakEvent
)
from ..adapters.unions import VerificationResultTypes, TransactionConfirmationTypes
from ..schemas.https import ServerTokenResponse, ServerPaymentScheme
from ..schemas.versions import ProtocalVersion
from .security import verify_token, generate_token
from ..engine.exceptions import (
    InvalidTokenError,
    TokenExpiredError,
    SignatureVerificationError,
    PaymentVerificationError,
    TransactionExecutionError,
)


# ==================== Event Handlers ====================

async def handle_request_init(
    event: RequestInitEvent,
    deps: Dependencies
) -> AuthorizationSuccessEvent | Http402PaymentEvent:
    """Verify access token and extract payload."""
    # Parse token from Authorization header (handles Bearer format, empty, etc.)
    if not event.token:
        return Http402PaymentEvent(
            reason="Missing authorization token",
            access_token_endpoint=event.token_endpoint,
            payment_scheme=ServerPaymentScheme(
                payment_components=deps.adapters_hub.get_payment_methods(), # TODO 解决格式转换的问题。
                protocol_version=ProtocalVersion.Version0_1.value
                ),
            payment_instruction="Payment required to access this resource. Submit payment to the access_token_endpoint using methods specified in payment_scheme."
        )
        
    parts = event.token.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return Http402PaymentEvent(
            reason="Invalid authorization header format",
            access_token_endpoint=event.token_endpoint,
            payment_scheme=ServerPaymentScheme(
                payment_components=deps.adapters_hub.get_payment_methods(),
                protocol_version=ProtocalVersion.Version0_1.value
                ),
            payment_instruction="Payment required to access this resource. Submit payment to the access_token_endpoint using methods specified in payment_scheme."
        )
    token = parts[1]
    try:
        payload = verify_token(token=token, private_key=deps.token_key)
        return AuthorizationSuccessEvent(
            payload=payload
        )
    except (InvalidTokenError, TokenExpiredError) as e:
        return Http402PaymentEvent(
            reason=str(e),
            access_token_endpoint=event.token_endpoint,
            payment_scheme=ServerPaymentScheme(
                payment_components=deps.adapters_hub.get_payment_methods(),
                protocol_version=ProtocalVersion.Version0_1.value
                ),
            payment_instruction="Payment required to access this resource. Submit payment to the access_token_endpoint using methods specified in payment_scheme."
        )


async def handle_request_token(
    event: RequestTokenEvent,
    deps: Dependencies
) -> VerifySuccessEvent | VerifyFailedEvent:
    """Verify payment permit signature."""
    try:
        result: VerificationResultTypes = await deps.adapters_hub.verify_signature(event.permit)
        
        if result.is_success():
            return VerifySuccessEvent(
                verification_result=result,
                permit=event.permit
            )

        else:
            return VerifyFailedEvent(error_message=result.get_error_message(), status=result.status)
    
    except (SignatureVerificationError, PaymentVerificationError, Exception) as e:
        return VerifyFailedEvent(error_message=f"Signature verification failed: {e}", status=result.status)


async def handle_verify_success(
    event: VerifySuccessEvent,
    deps: Dependencies
) -> TokenIssuedEvent:
    """Generate access token immediately after successful verification."""
    access_token = generate_token(
        private_key=deps.token_key,
        expires_in=deps.token_expires_in
    )
    
    return TokenIssuedEvent(
        token_response=ServerTokenResponse(
            access_token=access_token,
            token_type="Bearer",
            expires_in=deps.token_expires_in,
            metadata={"Token Instruction": "Use this token to access the protected resource in the Authorization header as a Bearer token."}
        )
    )
    

async def handle_settlement(
    event: VerifySuccessEvent,
    deps: Dependencies
) -> SettleFailedEvent | SettleSuccessEvent:
    """Execute settlement in background and dispatch result to settlement event bus."""
    # Execute settlement
    try:
        settlement: TransactionConfirmationTypes = await deps.adapters_hub.settle(event.permit)
        
        if settlement.is_success():
            return SettleSuccessEvent(settlement_result=settlement)
        
        else:
            return SettleFailedEvent(error_message=settlement.error_message, status=settlement.status)
    
    except (TransactionExecutionError, PaymentVerificationError, Exception) as e:
        return SettleFailedEvent(error_message=f"Transaction failed: {e}", status=settlement.status)


# ==================== Event Bus Setup ====================

def setup_event_bus(enable_auto_settlement: bool = True) -> EventBus:
    """Initialize event bus with built-in handlers.
    
    Args:
        enable_auto_settlement: If True, settlement runs automatically in background after verification.
    """
    event_bus = EventBus()
    
    # Register core handlers
    event_bus.subscribe(RequestInitEvent, handle_request_init)
    event_bus.subscribe(RequestTokenEvent, handle_request_token)
    event_bus.subscribe(VerifySuccessEvent, handle_verify_success)

    if enable_auto_settlement:
        event_bus.subscribe(VerifySuccessEvent, handle_settlement)
    # Register background settlement hook (runs async, doesn't block token response)
    
    # event_bus.add_hook(VerifySuccessEvent, handle_background_settlement)
    
    return event_bus
    
    
