from src.x402_mock.clients.http_client import Http402Client
from src.x402_mock.adapters.adapters_hub import AdapterHub
import httpx

pk = "Bearer eyJlxxxxxx" # Replace with actual token
wpk = "0xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

ah = AdapterHub(wpk)

async def main():
    async with Http402Client(
        adapter_hub=ah,
        timeout=httpx.Timeout(60.0, read=120.0)
    ) as client:
        client.add_payment_method(
            chain_id="eip155:11155111",
            amount=0.8,
            currency="USDC"
        )
        return await client.get("http://localhost:8000/api/protected-data", headers={"Authorization": pk})


if __name__ == "__main__":
    import asyncio
    response = asyncio.run(main())
    print("Response:", response.json())