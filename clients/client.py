from dataclasses import asdict
from decimal import Decimal
from typing import List
import os
from pathlib import Path
from dotenv import load_dotenv
import httpx
import asyncio

from web3 import Web3
from fastapi.responses import JSONResponse

from .facilitors import (
    match_components,
    build_payment_intent,
    sign_payment_intent,
    sign_permit,
)
from ..x402_schema import (
    X402PaymentScheme,
    CryptoPaymentComponent,
    X402PaymentIntentWithSignature,
    X402PaymentIntent,
    Permit,
    PaymentAuthorization,
)
from ...utils import logger, error_context
from ..eip_types import ERC20_MIN_ABI

"""
uv run -m src.terrazip.x402_mock.clients.client

"""

CLIENT_PAYMENT_METHODS: List[X402PaymentScheme] = [
    CryptoPaymentComponent(
        network="eip155:11155111",
        chain_id=11155111,
        currency="USDC",
        contract_address="0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
        decimals=6,
    ),
    CryptoPaymentComponent(
        network="eip155:11155111",
        chain_id=11155111,
        currency="EURC",
        contract_address="0x08210F9170F89Ab7658F0B5E3fF39b0E03C594D4",
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


class Client:
    def __init__(self, client_address: str, private_key: str, rpc_url: str):
        self._client_address = client_address
        self._private_key = private_key

        w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.usdc = w3.eth.contract(
            address=Web3.to_checksum_address(
                "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
            ),
            abi=ERC20_MIN_ABI,
        )

    async def order_request(self, url: str) -> X402PaymentScheme:
        try:
            async with httpx.AsyncClient(timeout=15) as http:
                response = await http.get(url=url)
                if response.status_code == 402:
                    logger.info("402 status code request")
                    payload = response.json()
                    logger.debug(f"Got payload from server: {payload}")
                    if payload:
                        return X402PaymentScheme.model_validate(payload)

        except Exception as e:
            error = error_context()
            logger.error(f"Request error for {error}, exception: {e}")
            raise RuntimeError(f"Request error for {error}, exception: {e}")

    def match_component_method(
        self, server_methods: List[CryptoPaymentComponent]
    ) -> CryptoPaymentComponent:
        return match_components(CLIENT_PAYMENT_METHODS, server_methods)

    def build_payment_intent(
        self,
        payment_scheme: X402PaymentScheme,
        payment_component: CryptoPaymentComponent,
    ) -> X402PaymentIntent:
        nonce = self.usdc.functions.nonces(self._client_address).call()
        payment_intent: X402PaymentIntent = build_payment_intent(
            payer=self._client_address,
            payee=payment_scheme.to_address,
            amount=Decimal(payment_scheme.amount),
            nonce=nonce,
            decimals=payment_component.decimals,
            currency=payment_component.currency,
            network=payment_component.network,
            metadata=payment_scheme.metadata,
        )
        logger.debug(f"payment intent info :{payment_intent}")
        return payment_intent

    def sign_payment_intent(
        self, payment_intent: X402PaymentScheme
    ) -> X402PaymentIntentWithSignature:

        return sign_payment_intent(intent=payment_intent, private_key=self._private_key)

    def sign_permit(
        self,
        payment_component: CryptoPaymentComponent,
        payment_scheme: X402PaymentScheme,
        payment_intent: X402PaymentIntent,
    ) -> Permit:
        return sign_permit(
            private_key=self._private_key,
            name=payment_component.currency.upper(),
            chain_id=payment_component.chain_id,
            token=payment_component.contract_address,
            owner=self._client_address,
            spender=payment_scheme.to_address,
            value=payment_intent.amount,
            nonce=payment_intent.nonce,
            deadline=payment_intent.expiry,
        )

    async def send_signature_to_server(
        self,
        url: str,
        permit: Permit,
        payment_intent_with_sign: X402PaymentIntentWithSignature,
    ) -> JSONResponse:
        payment_auth = PaymentAuthorization(
            kind="x402.payment_authorization.v1",
            intent=payment_intent_with_sign,
            permit=permit,
        )
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                response = await http.post(url, json=asdict(payment_auth))
                logger.debug(f"Get response: {response}")
                print(response)

        except Exception as e:
            error_info = error_context()
            logger.error(f"error info :{error_info}, exception: {e}")


class X402MockClient:
    """
    Minimal x402 payment client wrapper.

    Public API:
    - __init__(host, port)
    - run()

    All configuration is loaded internally.
    """

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

        # Load client-side environment
        Config.load(env_name=".env.client")

        infura_key = Config.get("INFURA_KEY")
        rpc_url = f"https://sepolia.infura.io/v3/{infura_key}"

        wallet_address = Web3.to_checksum_address(Config.get("WALLET_ADDRESS"))

        self._client = Client(
            client_address=wallet_address,
            private_key=Config.get("PRIVATE_KEY"),
            rpc_url=rpc_url,
        )

        self._base_url = f"{self.host}:{self.port}"

    async def _run_async(self):
        payment_scheme = await self._client.order_request(
            url=f"{self._base_url}/order_pay"
        )

        matched_component = self._client.match_component_method(payment_scheme.methods)

        payment_intent = self._client.build_payment_intent(
            payment_scheme=payment_scheme,
            payment_component=matched_component,
        )

        signed_payment_intent = self._client.sign_payment_intent(
            payment_intent=payment_intent
        )

        permit = self._client.sign_permit(
            payment_component=matched_component,
            payment_intent=payment_intent,
            payment_scheme=payment_scheme,
        )

        return await self._client.send_signature_to_server(
            url=f"{self._base_url}/payment_handshake",
            permit=permit,
            payment_intent_with_sign=signed_payment_intent,
        )

    def run(self):
        """
        Execute the full payment flow.
        """
        return asyncio.run(self._run_async())

    async def create_task(self):
        return asyncio.create_task(self._run_async())


if __name__ == "__main__":

    client_mock = X402MockClient(host="http://localhost", port=3000)
    client_mock.run()
