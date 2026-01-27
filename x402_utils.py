from typing import Dict, Any
import json
from eth_utils import to_bytes


def canonical_json(data: Dict[str, Any]) -> str:
    """
    RFC8785-ish: sort_keys + no whitespace
    """
    return json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def hex_to_bytes32(hexstr: str) -> bytes:
    return to_bytes(hexstr=hexstr.replace("0x", "").rjust(64, "0"))
