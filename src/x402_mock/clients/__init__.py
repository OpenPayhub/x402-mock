"""
Client module for x402 payment authorization.

Provides easy-to-use interfaces for accessing protected resources
with automatic permit signing and token exchange.
"""

from .http_client import Http402Client

__all__ = ["Http402Client"]
