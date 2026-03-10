from enum import Enum
from typing import List

class ProtocalVersion(Enum):
    """
    Protocol version enumeration.
    
    Note: The class name contains a typo ('Protocal' instead of 'Protocol').
    This is kept as-is for backward compatibility with existing code.
    See: https://github.com/OpenPayhub/x402-mock/issues
    """
    Version0_1 = "Version 0.1"
    
    @classmethod
    def from_string(cls, value):
        try:
            return cls(value)
        except ValueError:
            raise ValueError(f"Unsupported protocol version: {value}")
    

class SupportedVersions:
    versions_list: List[ProtocalVersion]