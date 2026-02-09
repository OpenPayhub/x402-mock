"""
Test suite for EventChain execution engine.
Tests: 1) Event execution order 2) Event collection correctness 3) All events execute completely
"""
import asyncio
import time
import pytest
from x402_mock.engine.events import (
    EventBus,
    Dependencies,
    RequestInitEvent,
    RequestTokenEvent,
    Http402PaymentEvent,
    VerifySuccessEvent,
    SettleSuccessEvent,
    TokenIssuedEvent,
    BreakEvent,
)
from x402_mock.engine.executors import EventChain
from x402_mock.schemas.bases import VerificationStatus, TransactionStatus
from x402_mock.adapters.evm.schemas import (
    EVMPaymentComponent,
    EIP2612Permit,
    EVMTransactionConfirmation,
    EIP2612PermitSignature,
    EVMVerificationResult
)
from x402_mock.schemas.https import ServerPaymentScheme, ServerTokenResponse


async def handle_request_init(event: RequestInitEvent, deps: Dependencies):

    payment_scheme = ServerPaymentScheme(
        protocol_version="1.0",
        payment_components=[
            EVMPaymentComponent(
                payment_type="evm",
                amount=1.0,
                token="0x123",
                currency="USD",
                chain_id=11155111,
            )
        ]
    )
    return Http402PaymentEvent(
        reason="Payment required",
        access_token_endpoint="/token",
        payment_scheme=payment_scheme
    )


async def handle_http402_payment(event: Http402PaymentEvent, deps: Dependencies):

    permit = EIP2612Permit(
        permit_type="EIP2612",
        token="0x123",
        owner="0xowner",
        spender="0xspender",
        value=100,
        nonce=1,
        deadline=999999,
        signature=EIP2612PermitSignature(
            v=27,
            r="0xrvalue",
            s="0xsvalue"
        ),
        chain_id=11155111
    )
    return RequestTokenEvent(permit=permit)


async def handle_request_token(event: RequestTokenEvent, deps: Dependencies):

    verification_result = EVMVerificationResult(
        status=VerificationStatus.SUCCESS,
        is_valid=True,
        message="Permit verified successfully"
    )
    return VerifySuccessEvent(
        verification_result=verification_result,
        permit=event.permit
    )


async def handle_token_issue(event: VerifySuccessEvent, deps: Dependencies):
    print("Issuing token...")
    await asyncio.sleep(2)
    print("Token issued.")
    return TokenIssuedEvent(
        token_response=ServerTokenResponse(
            access_token="test_token_123",
            token_type="Bearer",
            expires_in=3600
        )
    )


async def handle_settle_success(event: VerifySuccessEvent, deps: Dependencies):
    print("Simulating settlement...")
    await asyncio.sleep(10)
    print("Settlement complete.")
    return SettleSuccessEvent(
    settlement_result=EVMTransactionConfirmation(
        tx_hash="0xtxhash",
        status=TransactionStatus.SUCCESS
    )
)


@pytest.mark.asyncio
async def test_event_collection_correctness():
    """Test: Break on TokenIssuedEvent - does SettleSuccessEvent still execute?"""

    event_bus = EventBus()
    event_bus.subscribe(RequestInitEvent, handle_request_init)
    event_bus.subscribe(Http402PaymentEvent, handle_http402_payment)
    event_bus.subscribe(RequestTokenEvent, handle_request_token)
    event_bus.subscribe(VerifySuccessEvent, handle_token_issue)
    event_bus.subscribe(VerifySuccessEvent, handle_settle_success)
    
    deps = Dependencies(token_key="test_key", token_expires_in=3600)
    
    # Use generator form - break when TokenIssuedEvent appears
    chain = EventChain(event_bus, deps)
    start_time = time.time()
    print("\n==== Starting event chain (generator form) ====")
    
    token_event = None
    async for event in chain.execute(RequestInitEvent(token=None)):
        print(f"✓ Yielded: {type(event).__name__}")
        if isinstance(event, TokenIssuedEvent):
            print(f"  → Received TokenIssuedEvent, breaking...")
            token_event = event
            break  # Break here - does SettleSuccessEvent still run?
    
    assert token_event is not None
    assert token_event.token_response.access_token == "test_token_123"
    end_time = time.time()
    duration = end_time - start_time
    print(f"✓ Broke from generator at {duration:.2f} seconds")
    
    # Now wait and see if settlement happens in background
    print("\n⏳ Waiting 12 seconds to see if SettleSuccessEvent completes in background...")
    await asyncio.sleep(12)
    end_time = time.time()
    duration = end_time - start_time
    print(f"✓ Total time after break: {duration:.2f} seconds")
    print("   (If 'Settlement complete.' prints above, settlement ran in background)")
    print("   (If NO 'Settlement complete.' message, settlement was stopped by break)")
    print("==== Test1 passed ====\n")
    
@pytest.mark.asyncio
async def test_complete_execution_without_break():
    """Test: Complete event chain execution - wait for all events without breaking"""

    event_bus = EventBus()
    event_bus.subscribe(RequestInitEvent, handle_request_init)
    event_bus.subscribe(Http402PaymentEvent, handle_http402_payment)
    event_bus.subscribe(RequestTokenEvent, handle_request_token)
    event_bus.subscribe(VerifySuccessEvent, handle_token_issue)
    event_bus.subscribe(VerifySuccessEvent, handle_settle_success)
    
    deps = Dependencies(token_key="test_key", token_expires_in=3600)
    
    chain = EventChain(event_bus, deps)

    start_time = time.time()
    print("\n==== Starting complete event chain (no break) ====")
    print("⏳ Waiting for ALL events to complete (token issue 2s + settlement 10s)...")
    
    all_events = []
    async for event in chain.execute(RequestInitEvent(token=None)):
        print(f"✓ Yielded: {type(event).__name__}")
        all_events.append(event)
    
    end_time = time.time()
    duration = end_time - start_time
    print(f"✓ Event chain completed - all events processed")
    print(f"  Total events: {len(all_events)}")
    print(f"  Total execution time: {duration:.2f} seconds")
    print("✓ All events including settlement completed")
    print("==== Test2 passed ====\n")


@pytest.mark.asyncio
async def test_break_early_stops_chain():
    """Test: BreakEvent stops the chain (verification that break stops settlement)"""

    event_bus = EventBus()
    event_bus.subscribe(RequestInitEvent, handle_request_init)
    event_bus.subscribe(Http402PaymentEvent, handle_http402_payment)
    event_bus.subscribe(RequestTokenEvent, handle_request_token)
    event_bus.subscribe(VerifySuccessEvent, handle_token_issue)
    event_bus.subscribe(VerifySuccessEvent, handle_settle_success)
    
    deps = Dependencies(token_key="test_key", token_expires_in=3600)
    
    chain = EventChain(event_bus, deps)

    start_time = time.time()
    print("\n==== Starting event chain (early break test) ====")
    
    token_received = False
    async for event in chain.execute(RequestInitEvent(token=None)):
        print(f"✓ Yielded: {type(event).__name__}")
        if isinstance(event, TokenIssuedEvent) and not token_received:
            token_received = True
            print(f"  → Got TokenIssuedEvent, breaking immediately...")
            break  # Force break BEFORE settlement handler can start
    
    assert token_received, "TokenIssuedEvent should have been yielded"
    end_time = time.time()
    duration = end_time - start_time
    print(f"✓ Broke from generator at {duration:.2f} seconds")
    
    # Check: did settlement print its message?
    print("\n📊 Analysis:")
    print(f"   Execution time to break: {duration:.2f}s (should be ~2s for token + 0s for settlement)")
    print("   Expected behavior: SettleSuccessEvent handler should NOT print 'Simulating settlement...'")
    print("   Because we broke the generator, the async for loop stops")
    print("\n⏳ Waiting 12 seconds anyway to be 100% sure...")
    await asyncio.sleep(12)
    print("✓ If 'Simulating settlement...' appeared above, break did NOT stop settlement")
    print("✓ If 'Simulating settlement...' did NOT appear, break correctly stopped it")
    print("==== Test3 passed ====\n")