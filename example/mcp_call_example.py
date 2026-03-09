import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from x402_mock.adapters.evm.schemas import EVMPaymentComponent


async def main():
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["example/mcp_server_example.py"],
        env={
            "X402_TOKEN_KEY": "dev-secret-change-me",
            "EVM_PRIVATE_KEY": "0xxxx",
            "EVM_INFURA_KEY": "xxxxx"
        })
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            siganture_tool = next((t for t in tools.tools if t.name == "signature"), None)
            payloads = {
                "list_components": [
                    EVMPaymentComponent(**{
                        "payment_type": "evm",
                        "caip2": "eip155:11155111",
                        "currency": "USDC",
                        "token": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
                        "amount": 0.5,
                        "pay_to": "0xabc123...def456",
                        "token_name": "USDC",
                        "token_decimals": 6,
                        "token_version": "2"
                    })
                ]
            }
            permit = await session.call_tool(siganture_tool.name, payloads)
            print("\n[Generated Permit]")
            print(permit)
            
if __name__ == "__main__":
    asyncio.run(main())