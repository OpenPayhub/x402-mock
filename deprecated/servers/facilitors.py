from web3 import AsyncWeb3
from typing import Dict, Any

from ..x402_schema import Permit
from ..x402_utils import to_bytes

from ...utils import logger


def verify_payment_intent():
    pass


async def execute_transfer_with_permit(
    async_web3: AsyncWeb3, usdc_contract, permit: Permit, receiver_private_key: str
) -> str:
    """
    Execute an on-chain transfer using EIP-2612 permit.

    Steps:
    1. Submit permit transaction
    2. Call transferFrom to move funds
    3. Return the final transfer transaction hash
    """
    # init account
    account = async_web3.eth.account.from_key(receiver_private_key)
    # fetch nonce
    tx_nonce = await async_web3.eth.get_transaction_count(
        account.address, block_identifier="pending"
    )
    assert (
        AsyncWeb3.to_checksum_address(permit.spender) == account.address
    ), "permit.spender must equal server sender"

    owner = AsyncWeb3.to_checksum_address(permit.owner)
    spender = AsyncWeb3.to_checksum_address(permit.spender)

    permit_tx_data = await usdc_contract.functions.permit(
        owner,
        spender,
        permit.value,
        permit.deadline,
        permit.signature.v,
        to_bytes(hexstr=permit.signature.r),
        to_bytes(hexstr=permit.signature.s),
    ).build_transaction(
        {
            "from": account.address,
            "nonce": tx_nonce,
            "gas": 150_000,
            "maxFeePerGas": async_web3.to_wei(30, "gwei"),
            "maxPriorityFeePerGas": async_web3.to_wei(2, "gwei"),
            "chainId": int(permit.chain_id),
        }
    )
    allowance = await usdc_contract.functions.allowance(owner, spender).call()
    logger.debug(f"allowance after permit: {allowance}")
    # if allowance == 0:
    #     raise RuntimeError(f"Allowance == 0, permit is Invalid")

    signed_permit_tx = account.sign_transaction(permit_tx_data)
    permit_tx_hash = await async_web3.eth.send_raw_transaction(
        signed_permit_tx.raw_transaction
    )
    await async_web3.eth.wait_for_transaction_receipt(permit_tx_hash, timeout=120)

    # 3. Create and transferFrom
    transfer_tx_data = await usdc_contract.functions.transferFrom(
        owner,
        spender,
        permit.value,
    ).build_transaction(
        {
            "from": account.address,
            "nonce": tx_nonce + 1,
            "gas": 120_000,
            "maxFeePerGas": async_web3.to_wei(30, "gwei"),
            "maxPriorityFeePerGas": async_web3.to_wei(2, "gwei"),
            "chainId": int(permit.chain_id),
        }
    )

    signed_transfer_tx = account.sign_transaction(transfer_tx_data)
    transfer_tx_hash = await async_web3.eth.send_raw_transaction(
        signed_transfer_tx.raw_transaction
    )

    # watting for comfirm transfer
    receipt = await async_web3.eth.wait_for_transaction_receipt(
        transfer_tx_hash, timeout=120
    )
    if receipt.status != 1:
        raise RuntimeError(f"Transfer transaction failed: {transfer_tx_hash.hex()}")

    return transfer_tx_hash.hex()
