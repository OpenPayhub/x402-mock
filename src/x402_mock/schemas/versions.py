from enum import Enum
from typing import List

class ProtocalVersion(Enum):
    Version0_1 = "Version 0.1"
    
    @classmethod
    def from_string(cls, value):
        try:
            return cls(value)
        except ValueError:
            raise ValueError(f"Unsupported protocol version: {value}")
    

class SupportedVersions:
    versions_list: List[ProtocalVersion]