from typing import Any
from decimal import Decimal
from dataclasses import dataclass


@dataclass
class X402ClientPaymentConstraints:
    amount: Decimal
    frequency: Any
    pass