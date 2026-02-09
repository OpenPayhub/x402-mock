from src.x402_mock.servers import Http402Server, generate_token
from src.x402_mock.engine.events import TokenIssuedEvent, SettleSuccessEvent, SettleFailedEvent


pk = "x402mock_private_key_test"
token_access = generate_token(
    private_key=pk,
    expires_in=6000,
)
print("Generated Token:", f"Bearer {token_access}")

# ✨ Initialize app - token endpoint is automatically added at /token
app = Http402Server(
    token_key=pk,
    title="X402 Payment API",
)

# Configure payment method
app.add_payment_method(
    chain_id="eip155:11155111",
    amount=0.5,
    currency="USDC",
)


# Optional: Add event hooks for custom logic
@app.hook(TokenIssuedEvent)
async def on_token_issued(event, deps):
    """Log when tokens are issued."""
    print(f"✅ Token issued: {event.token_response}...")

@app.hook(SettleSuccessEvent)
async def on_settle_success(event, deps):
    """Log when settlements succeed."""
    print(f"✅ Settlement succeeded: {event.settlement_result}...")

@app.hook(SettleFailedEvent)
async def on_settle_failed(event, deps):
    """Log when settlements fail."""
    print(f"❌ Settlement failed: {event.error_message}...")

# ✨ NEW: Protected routes using payment_required dependency

@app.get("/api/protected-data")
@app.payment_required
async def get_protected_data(authorization):
    """This endpoint requires payment to access."""
    print(f"Access granted to payer: {authorization}")
    return {
        "data": "This is premium content",
        "message": "Payment verified successfully",
        "payer": authorization  # Access payer info from token
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8000, log_level="debug")