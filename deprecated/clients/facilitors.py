from typing import List, Optional
from collections import defaultdict
from decimal import Decimal
import time
import copy

from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data

from ..x402_schema import (
    X402PaymentIntent,
    X402PaymentIntentWithSignature,
    CryptoPaymentComponent,
    Permit,
    PermitSignatureEIP2612,
)
from ...utils import logger, create_order_uuid
from ..eip_types import EIP_712_TYPED


def add_payment_constraints():
    pass


def sign_permit(
    private_key: str,
    name: str,
    chain_id: int,
    token: str,
    owner: str,
    spender: str,
    value: int,
    nonce: int,
    deadline: int,
) -> Permit:
    _eip712 = fill_eip712(
        name=name,
        chain_id=chain_id,
        token=token,
        owner=owner,
        spender=spender,
        value=value,
        nonce=nonce,
        deadline=deadline,
    )
    signable = encode_typed_data(full_message=_eip712)
    signed = Account.sign_message(signable, private_key)
    r_bytes = signed.r.to_bytes(32, "big")
    s_bytes = signed.s.to_bytes(32, "big")
    r_hex = "0x" + r_bytes.hex()
    s_hex = "0x" + s_bytes.hex()
    return Permit(
        token=token,
        chain_id=chain_id,
        owner=owner,
        spender=spender,
        value=value,
        nonce=nonce,
        deadline=deadline,
        signature=PermitSignatureEIP2612(v=signed.v, r=r_hex, s=s_hex),
    )


def fill_eip712(
    name: str,
    chain_id: int,
    token: str,
    owner: str,
    spender: str,
    value: int,
    nonce: int,
    deadline: int,
) -> dict:
    eip_data = copy.deepcopy(EIP_712_TYPED)
    eip_data["domain"] = {
        "name": name,
        "version": "2",
        "chainId": chain_id,
        "verifyingContract": token,
    }

    eip_data["message"] = {
        "owner": owner,
        "spender": spender,
        "value": value,
        "nonce": nonce,
        "deadline": deadline,
    }
    return eip_data


def sign_payment_intent(
    intent: X402PaymentIntent,
    private_key: str,
) -> X402PaymentIntentWithSignature:
    serialized = intent.to_message()

    message = encode_defunct(text=serialized)
    signed = Account.sign_message(message, private_key)

    return X402PaymentIntentWithSignature(
        intent=intent, signature=signed.signature.hex(), signer=intent.payer
    )


def build_payment_intent(
    payer: str,
    payee: str,
    amount: Decimal,
    nonce: int,
    currency: str = "USDC",
    decimals: int = 6,
    network: str = "ethereum",
    ttl: int = 3600,  # seconds
    metadata: Optional[dict] = None,
) -> X402PaymentIntent:
    return X402PaymentIntent(
        intent_id=create_order_uuid("pi_"),
        payee=payee,
        payer=payer,
        network=network,
        currency=currency,
        amount=int(Decimal(amount) * 10**decimals),
        expiry=int(time.time()) + ttl,
        nonce=nonce,
        metadata=metadata,
    )


def match_components(
    client: List[CryptoPaymentComponent], server: List[CryptoPaymentComponent]
) -> CryptoPaymentComponent:
    server_index = index_by_key(server)
    matches = []
    for c in client:
        for s in server_index.get(match_key(c), []):
            matches.append(s)

    if matches:
        logger.debug(f"Client and Server matchs component: {matches}")
        return matches[0]
    else:
        logger.error(
            f"Got Server and Client have no Matchs componets, payment matchs failed! check server provided: {server}"
        )
        raise KeyError(
            "Got Server and Client have no Matchs componets, payment matchs failed!"
        )


def match_key(c: CryptoPaymentComponent) -> tuple:
    return (
        c.network.lower(),
        c.currency.lower(),
        c.chain_id,
        str(c.decimals),
        c.contract_address.lower(),
    )


def index_by_key(components):
    index = defaultdict(list)
    for c in components:
        index[match_key(c)].append(c)
    return index
