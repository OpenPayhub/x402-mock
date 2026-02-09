"""
EVM Chain Configuration Management

Provides unified access to EVM chain configurations and assets.
Includes utilities for RPC URL construction, environment-aware RPC key handling,
and chain state initialization based on permit data.
"""

import os
from typing import Dict, Optional
from decimal import Decimal, InvalidOperation
from pydantic import BaseModel, Field

import dotenv

dotenv.load_dotenv()

class AssetConfig(BaseModel):
    """Token asset configuration."""
    address: str = Field(..., description="Token contract address")
    name: str = Field(..., description="Token name")
    decimals: int = Field(..., description="Token decimals")
    version: str = Field(..., description="EIP2612 permit version")


class ChainConfig(BaseModel):
    """EVM blockchain network configuration."""
    network: str = Field(..., description="Network identifier (e.g., ethereum-mainnet)")
    name: str = Field(..., description="Human-readable network name")
    type: str = Field(default="evm", description="Blockchain type (evm/svm)")
    rpc_url: str = Field(..., description="JSON-RPC endpoint URL template")
    public_rpc_url: str = Field(..., description="Public RPC endpoint (fallback when no infra key)")
    explorer_url: str = Field(..., description="Block explorer URL")
    assets: Dict[str, AssetConfig] = Field(default_factory=dict, description="Supported assets")


# Raw chain configuration data
# Each chain includes both premium RPC template (with {RPC_KEYS} placeholder) and public RPC fallback.
# Premium RPC is used when evm_infra_key environment variable is set, otherwise public RPC is used.
_EVM_CHAINS_DATA: Dict = {
    "eip155:1": {
      "network": "ethereum-mainnet",
      "name": "Ethereum Mainnet",
      "type": "evm",
      "rpc_url": "https://mainnet.infura.io/v3/{RPC_KEYS}",
      "public_rpc_url": "https://api.mycryptoapi.com/eth",
      "explorer_url": "https://etherscan.io",
      "assets": {
        "USDC": {
          "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
          "name": "USD Coin",
          "decimals": 6,
          "version": "2"
        }
      }
    },
    "eip155:8453": {
      "network": "base-mainnet",
      "name": "Base Mainnet",
      "type": "evm",
      "rpc_url": "https://base-mainnet.infura.io/v3/{RPC_KEYS}",
      "public_rpc_url": "https://base.gateway.tenderly.co",
      "explorer_url": "https://basescan.org",
      "assets": {
        "USDC": {
          "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          "name": "USD Coin",
          "decimals": 6,
          "version": "2"
        }
      }
    },
    "eip155:137": {
      "network": "Polygon",
      "name": "Polygon Mainnet",
      "type": "evm",
      "rpc_url": "https://polygon-mainnet.infura.io/v3/{RPC_KEYS}",
      "public_rpc_url": "https://rpc-mainnet.matic.network",
      "explorer_url": "https://polygonscan.com",
      "assets": {
        "USDC": {
          "address": "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359",
          "name": "USD Coin",
          "decimals": 6,
          "version": "2"
        }
      }
    },
    "eip155:11155111": {
      "network": "Ethereum-Sepolia",
      "name": "Sepolia Testnet",
      "type": "evm",
      "rpc_url": "https://sepolia.infura.io/v3/{RPC_KEYS}",
      "public_rpc_url": "https://rpc.sepolia.org",
      "explorer_url": "https://sepolia.etherscan.io",
      "assets": {
        "USDC": {
          "address": "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
          "name": "USDC",
          "decimals": 6,
          "version": "2"
        }
      }
    },
}


def get_rpc_url(chain_id: int, infra_key: Optional[str] = None) -> Optional[str]:
    """
    Construct RPC URL for given chain with environment-aware infrastructure key handling.
    
    This function determines the RPC URL in the following priority:
    1. If infra_key is provided (non-empty), use it with the chain's RPC template from _EVM_CHAINS_DATA
    2. Otherwise, use the public_rpc_url fallback configured in _EVM_CHAINS_DATA
    3. Return None if chain is unsupported
    
    The function supports CAIP-2 format chain IDs by converting them (e.g., "eip155:1" → 1).
    All RPC configurations are centralized in _EVM_CHAINS_DATA for easier maintenance.
    
    Args:
        chain_id: Chain ID as integer (e.g., 1 for Ethereum) or CAIP-2 format string (e.g., "eip155:1")
        infra_key: Optional infrastructure API key from environment (e.g., Alchemy/Infura key).
                   If None or empty, uses public_rpc_url from configuration.
    
    Returns:
        str: Complete RPC URL ready for use, or None if chain is unsupported
    
    Example:
        # Using infrastructure key (premium RPC)
        rpc = get_rpc_url(1, infra_key="xyz123")  
        # Returns: "https://eth-mainnet.g.alchemy.com/v2/xyz123"
        
        # Falling back to public RPC
        rpc = get_rpc_url(11155111)  
        # Returns: "https://rpc.sepolia.org"
    """
    # Normalize chain_id: convert CAIP-2 format to integer if needed
    if isinstance(chain_id, str):
        if ":" in chain_id:
            chain_id = int(chain_id.split(":")[1])
        else:
            chain_id = int(chain_id)
    
    # Find the CAIP-2 format key for this chain_id
    caip2_key = None
    for key in _EVM_CHAINS_DATA.keys():
        if int(key.split(":")[1]) == chain_id:
            caip2_key = key
            break
    
    if not caip2_key:
        return None
    
    config_data = _EVM_CHAINS_DATA[caip2_key]
    
    # If infra_key is provided and non-empty, use premium RPC template with the key
    if infra_key and infra_key.strip():
        return config_data["rpc_url"].replace("{RPC_KEYS}", infra_key)
    
    # Otherwise, fall back to public RPC URL from configuration
    return config_data.get("public_rpc_url")


def get_chain_config(chain_id: str) -> Optional[ChainConfig]:
    """
    Get chain configuration by chain ID.
    
    Args:
        chain_id: Chain identifier in CAIP-2 format (e.g., "eip155:1", "eip155:11155111")
    
    Returns:
        ChainConfig: Pydantic model with chain configuration, or None if not found
    
    Example:
        config = get_chain_config("eip155:1")
        print(config.name)  # "Ethereum Mainnet"
        print(config.assets["USDC"].address)  # USDC address
    """
    if chain_id not in _EVM_CHAINS_DATA:
        return None
    
    data = _EVM_CHAINS_DATA[chain_id]
    
    # Convert asset dicts to AssetConfig objects
    assets = {
        symbol: AssetConfig(**asset_data)
        for symbol, asset_data in data.get("assets", {}).items()
    }
    
    return ChainConfig(
        network=data["network"],
        name=data["name"],
        type=data["type"],
        rpc_url=data["rpc_url"],
        public_rpc_url=data["public_rpc_url"],
        explorer_url=data["explorer_url"],
        assets=assets
    )


def get_all_chain_configs() -> Dict[str, ChainConfig]:
    """
    Get all supported chain configurations.
    
    Returns:
        Dict mapping chain IDs to ChainConfig objects
    """
    configs = {}
    for chain_id in _EVM_CHAINS_DATA.keys():
        config = get_chain_config(chain_id)
        if config:
            configs[chain_id] = config
    return configs


def is_chain_supported(chain_id: str) -> bool:
    """
    Check if chain is supported.
    
    Args:
        chain_id: Chain identifier (e.g., "eip155:1")
    
    Returns:
        True if chain is supported, False otherwise
    """
    return chain_id in _EVM_CHAINS_DATA


def get_private_key_from_env() -> Optional[str]:
    """
    Load EVM server private key from environment variables.
    
    This function retrieves the private key that the EVM server adapter uses
    for signing transactions and initializing the server account.
    
    Environment Variable:
        - evm_private_key: The server's EVM private key (0x-prefixed hex format)
    
    Returns:
        str: Private key from environment, or None if not configured
    
    Note:
        The private key should be stored securely in environment variables
        and never committed to version control.
    
    Example:
        # In your .env file or environment setup:
        # export EVM_PRIVATE_KEY="0x1234567890abcdef..."
        
        pk = get_private_key_from_env()
        if pk:
            adapter = EVMServerAdapter(private_key=pk)
    """
    return os.getenv("EVM_PRIVATE_KEY")


def get_infra_key_from_env() -> Optional[str]:
    """
    Load EVM infrastructure API key from environment variables.
    
    This function retrieves the optional infrastructure API key used to
    construct premium RPC endpoints (e.g., Alchemy, Infura keys).
    If not provided, the adapter will fall back to public RPC nodes.
    
    Environment Variable:
        - EVM_INFURA_KEY: Infrastructure provider API key (e.g., Alchemy/Infura key)
    
    Returns:
        str: Infra key from environment, or None if not configured
    
    Note:
        If EVM_INFURA_KEY is not set or empty, public RPC endpoints will be used.
        Public endpoints may have rate limits, but are free and don't require configuration.
    
    Example:
        # In your .env file or environment setup:
        # export EVM_INFURA_KEY="xyz123abc456..."
        
        infra_key = get_infra_key_from_env()
        # Will be used to construct premium RPC URLs like:
        # "https://eth-mainnet.g.alchemy.com/v2/xyz123abc456..."
    """
    return os.getenv("EVM_INFURA_KEY")


def amount_to_value(*, amount: float | int | str | Decimal, decimals: int) -> int:
    """Convert a human-readable token `amount` into smallest-unit integer `value`.

    This is the canonical conversion used by permit signing / verification / transactions.

    Args:
        amount: Human-readable amount (e.g. 1.23 for USDC). Accepts float/int/str/Decimal.
        decimals: Token decimals (e.g. 6 for USDC).

    Returns:
        int: Smallest-unit integer value.

    Raises:
        ValueError: If inputs are invalid or the amount cannot be represented in smallest units.
    """
    if not isinstance(decimals, int) or decimals < 0:
        raise ValueError("decimals must be a non-negative int")

    try:
        # Use str() to avoid binary-float surprises (e.g. 0.1 -> 0.100000000000000005...)
        dec_amount = amount if isinstance(amount, Decimal) else Decimal(str(amount))
    except (InvalidOperation, ValueError, TypeError) as e:
        raise ValueError(f"Invalid amount: {amount!r}") from e

    if dec_amount < 0:
        raise ValueError("amount must be non-negative")

    scale = Decimal(10) ** decimals
    scaled = dec_amount * scale

    # Require exact smallest-unit representability (no fractional smallest units)
    if scaled != scaled.to_integral_value():
        raise ValueError(
            f"amount {amount!r} is not representable with decimals={decimals} "
            f"(would create fractional smallest units)"
        )

    return int(scaled)


def value_to_amount(*, value: int | str | Decimal, decimals: int) -> float:
    """Convert a smallest-unit integer `value` into human-readable token `amount`.

    This is the canonical conversion used for user-facing display / matching / requests.

    Args:
        value: Smallest-unit integer value (e.g. 1230000 for 1.23 USDC). Accepts int/str/Decimal.
        decimals: Token decimals (e.g. 6 for USDC).

    Returns:
        float: Human-readable amount.

    Raises:
        ValueError: If inputs are invalid.
    """
    if not isinstance(decimals, int) or decimals < 0:
        raise ValueError("decimals must be a non-negative int")

    try:
        dec_value = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as e:
        raise ValueError(f"Invalid value: {value!r}") from e

    if dec_value < 0:
        raise ValueError("value must be non-negative")

    if dec_value != dec_value.to_integral_value():
        raise ValueError("value must be an integer in smallest units")

    scale = Decimal(10) ** decimals
    return float(dec_value / scale)


