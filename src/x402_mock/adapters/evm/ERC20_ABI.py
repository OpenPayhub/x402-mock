
"""
USDC ERC20 + EIP2612 Permit Smart Contract ABI Module

This module provides simplified ABI definitions for USDC token interactions with EIP2612 permit support.

Usage:
    from ERC20_ABI import get_balance_abi, get_permit_abi, get_verify_signature_abi
    
    # Query balance
    balance_abi = get_balance_abi()
    
    # Execute permit
    permit_abi = get_permit_abi()
    
    # Verify signature
    verify_abi = get_verify_signature_abi()
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


def get_verify_signature_abi() -> List[Dict[str, Any]]:
    """
    Get ABI for verifying permit signatures on-chain.
    
    Returns:
        List[Dict[str, Any]]: ABI for signature verification functions
    
    Functions included:
        - nonces(address): Get current nonce for signature verification
        - DOMAIN_SEPARATOR(): Get EIP712 domain separator
        - allowance(owner, spender): Get current allowance amount
    
    Example:
        abi = get_verify_signature_abi()
        contract = web3.eth.contract(address=token_address, abi=abi)
        nonce = contract.functions.nonces(owner_address).call()
        allowance = contract.functions.allowance(owner, spender).call()
    """
    return [
        {
            "name": "nonces",
            "type": "function",
            "stateMutability": "view",
            "inputs": [{"name": "owner", "type": "address"}],
            "outputs": [{"name": "", "type": "uint256"}],
        },
        {
            "name": "DOMAIN_SEPARATOR",
            "type": "function",
            "stateMutability": "view",
            "inputs": [],
            "outputs": [{"name": "", "type": "bytes32"}],
        },
        {
            "name": "allowance",
            "type": "function",
            "stateMutability": "view",
            "inputs": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
            ],
            "outputs": [{"name": "", "type": "uint256"}],
        },
    ]


def get_permit_abi() -> List[Dict[str, Any]]:
    """
    Get ABI for executing permit transactions on-chain.
    
    Returns:
        List[Dict[str, Any]]: ABI for permit execution functions
    
    Functions included:
        - permit(owner, spender, value, deadline, v, r, s): Execute permit approval
        - transferFrom(from, to, value): Transfer tokens using permitted allowance
    
    Example:
        abi = get_permit_abi()
        contract = web3.eth.contract(address=token_address, abi=abi)
        
        # Execute permit and transfer in one transaction
        tx = contract.functions.permit(
            owner, spender, value, deadline, v, r, s
        ).transact()
        
        contract.functions.transferFrom(owner, recipient, value).transact()
    """
    return [
        {
            "name": "permit",
            "type": "function",
            "stateMutability": "nonpayable",
            "inputs": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
                {"name": "v", "type": "uint8"},
                {"name": "r", "type": "bytes32"},
                {"name": "s", "type": "bytes32"},
            ],
            "outputs": [],
        },
        {
            "name": "transferFrom",
            "type": "function",
            "stateMutability": "nonpayable",
            "inputs": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
            ],
            "outputs": [{"name": "", "type": "bool"}],
        },
    ]
