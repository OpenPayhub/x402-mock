"""
EVM Chain Configuration Management

Provides unified access to EVM chain configurations and assets.
Includes utilities for RPC URL construction, environment-aware RPC key handling,
and chain state initialization based on permit data.
"""

import os
from typing import Dict, Optional, Tuple, List, Any, Union
from decimal import Decimal, InvalidOperation
from pydantic import BaseModel, Field

from web3 import Web3
import dotenv
import httpx

dotenv.load_dotenv()

class EvmAssetConfig(BaseModel):
    """Token asset configuration."""
    symbol: str
    address: str = Field(..., description="Token contract address")
    name: str = Field(..., description="Token name")
    decimals: int = Field(..., description="Token decimals")
    version: str = Field(..., description="EIP712 permit version")


class EvmChainInfo(BaseModel):
    """Subset of ethereum-lists chain metadata we rely on.

    This model is designed to be compatible with the JSON files in:
    `ethereum-lists/chains` (eip155-<chain_id>.json).

    Note:
        The upstream payload contains many more fields; we keep only the ones
        needed by the dynamic chain config builder below.
    """
    name: str = Field(..., description="Human-readable network name")
    rpc: List[str] = Field(..., description="List of RPC endpoints")
    infoURL: str = Field(..., description="URL with more information about the chain")
    chainId: int = Field(..., description="Chain ID of the network")
    explorers: Optional[List[Dict[str, str]]] = Field(
        default=None,
        description="Optional list of explorer descriptors from the upstream payload",
    )
    

class EvmChainConfig(BaseModel):
    """EVM blockchain network configuration."""
    caip2: str
    chain_id: int
    type: str = Field(default="evm", description="Blockchain type (evm/svm)")
    rpc_url: Optional[str] = Field(..., description="JSON-RPC endpoint URL template")
    public_rpc_url: str = Field(..., description="Public RPC endpoint (fallback when no infra key)")
    explorer_url: str = Field(..., description="Block explorer URL")
    assets: Dict[str, EvmAssetConfig] = Field(default_factory=dict, description="Supported assets")

# ---------------------------------------------------------------------------
# ERC-1271 constants
# ---------------------------------------------------------------------------

#: Magic value returned by a valid ERC-1271 ``isValidSignature`` call.
ERC1271_MAGIC_VALUE: bytes = b"\x16\x26\xba\x7e"


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
        },
        "USDT": {
          "address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
          "name": "Tether USD",
          "decimals": 6,
          "version": "1"
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
        },
        "USDT": {
            "address": "0xfde4C96256153236af98292015BA95836c75af0a",
            "name": "Tether USD",
            "decimals": 6,
            "version": "0"
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
        },
        "USDT": {
            "address": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
            "name": "Tether USD",
            "decimals": 6,
            "version": "0"
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
          "name": "USD Coin",
          "decimals": 6,
          "version": "2"
        },
        "USDT": {
            "address": "0xbDeaD2A70Fe794D2f97b37EFDE497e68974a296d",
            "name": "USDT",
            "decimals": 6,
            "version": "0"
        }
      }
    },
}



def parse_token_address_and_decimals(
    token_list: List[Dict[str, Any]], 
    chain_id: int, 
    symbol: str
) -> Tuple[str, int]:
    """
    Locates a token's contract address and decimals within a metadata list.

    Args:
        token_list (List[Dict[str, Any]]): A list of dictionaries containing token metadata.
        chain_id (int): The EIP-155 chain identifier to filter by.
        symbol (str): The token ticker symbol (e.g., 'WETH', 'USDC').

    Returns:
        Tuple[str, int]: A tuple containing the (address, decimals).

    Raises:
        ValueError: If the token is not found on the specified chain, or if the 
                    found token contains invalid/missing address or decimals data.
    """
    search_symbol = symbol.strip().upper()

    for token in token_list:
        # Match both chainId and symbol (case-insensitive)
        if (
            token.get("chainId") == chain_id and 
            str(token.get("symbol", "")).upper() == search_symbol
        ):
            address = token.get("address")
            decimals = token.get("decimals")

            # Strict validation to ensure the returned data is usable
            if not isinstance(address, str) or not isinstance(decimals, int):
                raise ValueError(
                    f"Invalid metadata for '{symbol}' on chain {chain_id}. "
                    f"Expected (str, int), got (address: {type(address).__name__}, "
                    f"decimals: {type(decimals).__name__})"
                )

            return address, decimals

    raise ValueError(
        f"Token with symbol '{symbol}' was not found in the provided list for chain ID {chain_id}."
    )


def fetch_evm_token_list() -> List[Dict[str, Any]]:
    """
    Fetches the official Uniswap token list and extracts token metadata.

    Returns:
        List[Dict[str, Any]]: A list of token metadata objects.

    Raises:
        ValueError: If the response is empty or the 'tokens' key is missing.
        httpx.HTTPError: If the network request fails.
    """
    uniswap_url = "https://tokens.uniswap.org"
    data = fetch_json(uniswap_url)
    
    tokens = data.get("tokens")
    if not tokens:
        raise ValueError(
            f"Failed to extract tokens: 'tokens' key missing or empty at {uniswap_url}"
        )
    
    return tokens


def fetch_evm_chain_info(caip2: str) -> EvmChainInfo:
    """
    Retrieves EVM chain configuration from the ethereum-lists repository.

    Args:
        caip2 (str): The CAIP-2 compliant chain identifier (e.g., 'eip155:1').

    Returns:
        EvmChainInfo: A validated data object containing chain specifications.

    Raises:
        httpx.HTTPError: If the chain configuration file is not found or unreachable.
        TypeError: If the returned payload does not match the EvmChainInfo schema.
    """
    chain_id = _parse_caip2_eip155_chain_id(caip2)
    url = (
        "https://raw.githubusercontent.com/ethereum-lists/chains/master/_data/chains/"
        f"eip155-{chain_id}.json"
    )
    
    payload = fetch_json(url)
    
    try:
        return EvmChainInfo(**payload)
    except Exception as e:
        raise TypeError(
            f"Schema mismatch: Data from {url} is incompatible with EvmChainInfo."
        ) from e


def fetch_json(url: str, timeout: float = 10.0) -> Dict[str, Any]:
    """
    Fetches JSON data from a URL and raises detailed exceptions on failure.

    Args:
        url (str): The target URL to request.
        timeout (float): Connection timeout in seconds.

    Returns:
        Dict[str, Any]: The parsed JSON response.

    Raises:
        httpx.HTTPStatusError: If the server returns a 4xx or 5xx status code.
        httpx.RequestError: If a network-level error occurs (DNS, Connection Refused).
        RuntimeError: If the response is not valid JSON.
    """
    with httpx.Client(timeout=timeout) as client:
        try:
            response = client.get(url)
            
            # Checks for 4xx/5xx errors
            response.raise_for_status()
            
            try:
                return response.json()
            except Exception as json_exc:
                raise RuntimeError(
                    f"Failed to decode JSON from {url}. Content-Type: {response.headers.get('Content-Type')}"
                ) from json_exc

        except httpx.HTTPStatusError as exc:
            # Custom message including status code and method
            raise httpx.HTTPStatusError(
                f"HTTP {exc.response.status_code} error occurred while requesting {url}. "
                f"Response body: {exc.response.text[:100]}",
                request=exc.request,
                response=exc.response
            ) from exc

        except httpx.RequestError as exc:
            # Detailed network error info
            raise httpx.RequestError(
                f"Network error: Failed to reach {url}. Details: {str(exc)}",
                request=exc.request
            ) from exc


def _parse_caip2_eip155_chain_id(caip2: str) -> int:
    """
    Parses a CAIP-2 identifier (e.g., 'eip155:1' or 'eip155-1') into an integer chain ID.

    Args:
        caip2 (str): The CAIP-2 string to parse.

    Returns:
        int: The extracted EIP-155 chain ID.

    Raises:
        ValueError: If the input format is invalid, the prefix is missing, 
                    or the chain ID is not a positive integer.
    """
    if not isinstance(caip2, str) or not caip2.strip():
        raise ValueError(f"Invalid input type: Expected non-empty string, got {type(caip2).__name__}")

    # Standardize the input by replacing hyphen with colon for uniform splitting
    normalized = caip2.strip().replace("-", ":")
    parts = normalized.split(":")

    # Validate structure: must have exactly one separator and the correct prefix
    if len(parts) != 2 or parts[0] != "eip155":
        raise ValueError(
            f"Invalid CAIP-2 format: '{caip2}'. "
            f"Expected format 'eip155:<chain_id>' or 'eip155-<chain_id>'"
        )

    try:
        chain_id = int(parts[1])
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"Failed to parse chain ID from '{caip2}'. "
            f"The segment '{parts[1]}' is not a valid integer."
        ) from exc

    if chain_id <= 0:
        raise ValueError(
            f"Invalid chain ID in '{caip2}': {chain_id}. "
            f"Chain ID must be a positive integer."
        )

    return chain_id


def parse_public_rpc_url(rpcs: List[str], start_with: str = "https://") -> Optional[str]:
    """Pick a public (no-key) RPC URL from a chain's RPC list.

    This function prefers plain HTTPS endpoints that do not contain common
    placeholder markers (`$` or `{...}`), which typically indicate an API key is required.

    Args:
        rpcs: RPC URL list from the chain metadata payload.
        start_with: Scheme/prefix filter (defaults to HTTPS).

    Returns:
        A public RPC URL, or None if none is found.
    """
    if not rpcs or not isinstance(rpcs, list):
        raise ValueError(
            "No RPC URLs provided in chain configuration; rpcs must be a list of strings, "
            f"but {type(rpcs).__name__} was provided"
        )

    for rpc in rpcs:
        if not isinstance(rpc, str):
            continue
        if not rpc.startswith(start_with):
            continue
        if "$" in rpc or "{" in rpc or "}" in rpc:
            continue
        return rpc


def fetch_erc20_name_and_version(*, rpc_url: str, token_address: str) -> Tuple[Optional[str], str]:
    """Fetch token `name()` and optional EIP-712 `version()` from the chain RPC.

    Notes:
        - `version()` is not part of ERC-20 and may not exist (defaults to "0").
        - If `name()` cannot be resolved, returns None for name.
    """
    if not isinstance(rpc_url, str) or not rpc_url.strip():
        raise ValueError("rpc_url must be a non-empty string")
    if not isinstance(token_address, str) or not token_address.strip():
        raise ValueError("token_address must be a non-empty string")

    w3 = Web3(Web3.HTTPProvider(rpc_url.strip(), request_kwargs={"timeout": 10}))
    checksum = w3.to_checksum_address(token_address.strip())

    abi = [
        {
            "name": "name",
            "type": "function",
            "stateMutability": "view",
            "inputs": [],
            "outputs": [{"name": "", "type": "string"}],
        },
        {
            "name": "version",
            "type": "function",
            "stateMutability": "view",
            "inputs": [],
            "outputs": [{"name": "", "type": "string"}],
        },
    ]
    contract = w3.eth.contract(address=checksum, abi=abi)

    name: Optional[str] = None
    version: str = "0"

    try:
        val = contract.functions.name().call()
        if isinstance(val, str) and val.strip():
            name = val.strip()
    except Exception:
        name = None

    try:
        val = contract.functions.version().call()
        if isinstance(val, str) and val.strip():
            version = val.strip()
    except Exception:
        version = "0"

    return name, version


def parse_private_url(
    urls: List[str], 
    start_with: Union[str, Tuple[str, ...]] = "https:"
) -> List[str]:
    """
    Filters a list of URLs based on a protocol prefix and the presence of API key placeholders.

    This function identifies infrastructure URLs that contain environment variable 
    placeholders (e.g., '${INFURA_API_KEY}') and match the specified starting prefix.

    Args:
        urls (List[str]): A list of RPC or WebSocket URL strings.
        start_with (Union[str, Tuple[str, ...]]): The protocol prefix to filter by. 
            Defaults to "https:". Can be a string or a tuple of strings.

    Returns:
        List[str]: A list of URLs matching the prefix and containing a '${' placeholder.
                   Returns an empty list if no matches are found.

    Raises:
        TypeError: If 'urls' is not a list or 'start_with' is not a string/tuple.
    """
    if not isinstance(urls, list):
        raise TypeError(f"Expected 'urls' to be a list, got {type(urls).__name__}")
    
    if not isinstance(start_with, (str, tuple)):
        raise TypeError(f"Expected 'start_with' to be str or tuple, got {type(start_with).__name__}")

    filtered_urls = []
    
    for url in urls:
        if not isinstance(url, str):
            continue
            
        # Check if the URL starts with the target protocol and contains the placeholder syntax
        if url.startswith(start_with) and "${" in url and "}" in url:
            filtered_urls.append(url)
            
    return filtered_urls

 
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


def get_rpc_key_from_env() -> Optional[str]:
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
    return os.getenv("EVM_PRC_KEY")


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



