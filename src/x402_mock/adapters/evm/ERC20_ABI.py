
"""
USDC ERC20 + ERC-3009 + Permit2 Smart Contract ABI Module

This module provides simplified ABI definitions for USDC token interactions,
covering ERC-3009 transferWithAuthorization, and Uniswap Permit2.

Usage:
    from ERC20_ABI import (
        get_balance_abi,
        get_erc3009_abi,
        get_permit2_abi,
    )

    # Query balance
    balance_abi = get_balance_abi()

    # Execute ERC-3009 transferWithAuthorization
    erc3009_abi = get_erc3009_abi()

    # Execute Permit2 permitTransferFrom
    permit2_abi = get_permit2_abi()
"""

from typing import Dict, Any, List


def get_balance_abi() -> List[Dict[str, Any]]:
    """
    Get ABI for querying USDC token balance.
    
    Returns:
        List[Dict[str, Any]]: ABI for balanceOf function
    
    Example:
        abi = get_balance_abi()
        # Use with web3.py: web3.eth.contract(address=token_address, abi=abi)
        # Call: contract.functions.balanceOf(address).call()
    """
    return [
        {
            "name": "balanceOf",
            "type": "function",
            "stateMutability": "view",
            "inputs": [{"name": "account", "type": "address"}],
            "outputs": [{"name": "", "type": "uint256"}],
        }
    ]


def get_allowance_abi() -> List[Dict[str, Any]]:
    """
    Get ABI for ERC20 `allowance(owner, spender)`.

    Returns:
        List[Dict[str, Any]]: ABI for ERC20 `allowance` function.

    Example:
        abi = get_allowance_abi()
        contract = web3.eth.contract(address=token_address, abi=abi)
        allowance = contract.functions.allowance(owner, spender).call()
    """
    return [
        {
            "name": "allowance",
            "type": "function",
            "stateMutability": "view",
            "inputs": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
            ],
            "outputs": [{"name": "", "type": "uint256"}],
        }
    ]


def get_approve_abi() -> List[Dict[str, Any]]:
    """
    Get ABI for ERC20 `approve(spender, amount)`.

    Returns:
        List[Dict[str, Any]]: ABI for ERC20 `approve` function.
    Example:
        abi = get_approve_abi()
        contract = web3.eth.contract(address=token_address, abi=abi)
        tx = contract.functions.approve(spender, amount).build_transaction({...})
    """
    return [
        {
            "name": "approve",
            "type": "function",
            "stateMutability": "nonpayable",
            "inputs": [
                {"name": "spender", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
            "outputs": [{"name": "", "type": "bool"}],
        }
    ]

def get_erc3009_abi() -> List[Dict[str, Any]]:
    """
    Get ABI for ERC-3009 ``transferWithAuthorization``.

    Used to call the on-chain ``transferWithAuthorization`` function directly on
    a token contract that implements ERC-3009 (e.g. USDC, EURC).  The caller
    passes the signed authorization values (from, to, value, validAfter,
    validBefore, nonce, v, r, s) — matching the fields of
    :class:`~x402_mock.adapters.evm.schemas.ERC3009Authorization`.

    Returns:
        List[Dict[str, Any]]: ABI containing the ``transferWithAuthorization``
        function entry.

    Example::

        abi = get_erc3009_abi()
        contract = web3.eth.contract(address=token_address, abi=abi)
        tx = contract.functions.transferWithAuthorization(
            from_addr, to_addr, value,
            valid_after, valid_before, nonce_bytes32,
            v, r_bytes32, s_bytes32,
        ).build_transaction({...})
    """
    return [
        {
            "name": "transferWithAuthorization",
            "type": "function",
            "stateMutability": "nonpayable",
            "inputs": [
                {"name": "from",        "type": "address"},
                {"name": "to",          "type": "address"},
                {"name": "value",       "type": "uint256"},
                {"name": "validAfter",  "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce",       "type": "bytes32"},
                {"name": "v",           "type": "uint8"},
                {"name": "r",           "type": "bytes32"},
                {"name": "s",           "type": "bytes32"},
            ],
            "outputs": [],
        },
    ]


def get_permit2_abi() -> List[Dict[str, Any]]:
    """
    Get ABI for Uniswap Permit2 ``permitTransferFrom``.

    Used to call the canonical Permit2 singleton contract
    (``0x000000000022D473030F116dDEE9F6B43aC78BA3``) to settle a
    :class:`~x402_mock.adapters.evm.schemas.Permit2Signature`.

    The function signature on-chain::

        function permitTransferFrom(
            PermitTransferFrom calldata permit,
            SignatureTransferDetails calldata transferDetails,
            address owner,
            bytes calldata signature
        ) external

    where ``PermitTransferFrom = { TokenPermissions permitted; uint256 nonce; uint256 deadline }``
    and ``TokenPermissions = { address token; uint256 amount }``,
    and ``SignatureTransferDetails = { address to; uint256 requestedAmount }``.

    Returns:
        List[Dict[str, Any]]: ABI containing the ``permitTransferFrom``
        function entry with fully-resolved tuple components.

    Example::

        abi = get_permit2_abi()
        contract = web3.eth.contract(address=permit2_address, abi=abi)
        tx = contract.functions.permitTransferFrom(
            ((token_addr, amount), nonce, deadline),  # PermitTransferFrom
            (to_addr, amount),                         # SignatureTransferDetails
            owner_addr,
            sig_bytes,
        ).build_transaction({...})
    """
    return [
        {
            "name": "permitTransferFrom",
            "type": "function",
            "stateMutability": "nonpayable",
            "inputs": [
                {
                    "name": "permit",
                    "type": "tuple",
                    "components": [
                        {
                            "name": "permitted",
                            "type": "tuple",
                            "components": [
                                {"name": "token",  "type": "address"},
                                {"name": "amount", "type": "uint256"},
                            ],
                        },
                        {"name": "nonce",    "type": "uint256"},
                        {"name": "deadline", "type": "uint256"},
                    ],
                },
                {
                    "name": "transferDetails",
                    "type": "tuple",
                    "components": [
                        {"name": "to",              "type": "address"},
                        {"name": "requestedAmount", "type": "uint256"},
                    ],
                },
                {"name": "owner",     "type": "address"},
                {"name": "signature", "type": "bytes"},
            ],
            "outputs": [],
        },
    ]
