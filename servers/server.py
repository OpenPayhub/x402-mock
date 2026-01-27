from dataclasses import asdict
from typing import List
from decimal import Decimal
import os
from pathlib import Path
from dotenv import load_dotenv

from web3 import AsyncWeb3
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ...utils import logger, setup_logger, error_context, create_order_uuid
from ..x402_schema import (
    X402PaymentIntent,
    X402PaymentScheme,
    CryptoPaymentComponent,
    X402PaymentScheme,
    Permit,
)
from .facilitors import execute_transfer_with_permit
from ..eip_types import ERC20_MIN_ABI

"""
uv run -m src.terrazip.x402_mock.servers.server
"""


SERVER_PAYMENT_METHODS: List[X402PaymentScheme] = [
    CryptoPaymentComponent(
        network="eip155:11155111",
        chain_id=11155111,
        currency="USDC",
        contract_address="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
        decimals=6,
    ),
]


class Config:
    @classmethod
    def load(cls, env_name: str = ".env.client"):
        cls._base_dir = Path(__file__).resolve().parent
        env_path = cls._base_dir / env_name
        if env_path.exists():
            load_dotenv(dotenv_path=env_path)
        else:
            raise FileNotFoundError(f"Config path is not exist: {env_path}")

    @staticmethod
    def get(key: str, default: str = None):
        return os.getenv(key, default)


app = FastAPI()
Config.load(env_name=".env.server")

ADDRESS = AsyncWeb3.to_checksum_address(Config.get("WALLET_ADDRESS"))
PRIVATE_KEY = Config.get("PRIVATE_KEY")
INFURA_KEY = Config.get("INFURA_KEY")
RPC_URL = f"https://sepolia.infura.io/v3/{INFURA_KEY}"
async_web3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(RPC_URL))

usdc = async_web3.eth.contract(
    address=AsyncWeb3.to_checksum_address("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"),
    abi=ERC20_MIN_ABI,
)


@app.get("/order_pay")
async def order_create():

    return JSONResponse(
        content=X402PaymentScheme(
            to_address=ADDRESS,
            amount="0.5",
            methods=SERVER_PAYMENT_METHODS,
            metadata={"order_id": create_order_uuid("order_")},
        ).model_dump(),
        status_code=402,
    )


@app.post("/payment_handshake")
async def payment_handshake(request: Request) -> JSONResponse:
    headers = request.headers
    payloads = await request.json()
    logger.debug(f"headers:{headers}, payloads: {payloads}")
    permit = Permit(**payloads.get("permit"))
    tx_hash = await execute_transfer_with_permit(
        async_web3=async_web3,
        usdc_contract=usdc,
        permit=permit,
        receiver_private_key=PRIVATE_KEY,
    )

    if tx_hash:
        logger.info(f"Transfer success!: TX_HASH: {tx_hash}")

    return JSONResponse(content={"tx_hash": tx_hash}, status_code=200)


setup_logger(level="DEBUG")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app=app, host="localhost", port=3000)
