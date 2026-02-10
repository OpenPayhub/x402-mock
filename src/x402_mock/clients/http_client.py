"""
HTTP 402 Payment Flow Middleware

Provides a transparent middleware layer for httpx that automatically handles
402 Payment Required responses with permit signing and token exchange.
"""

from typing import Dict, Optional
from urllib.parse import urlparse

import httpx

from ..adapters.adapters_hub import AdapterHub
from ..adapters.unions import PermitTypes
from ..schemas.https import (
    Server402ResponsePayload,
    ServerTokenResponse,
    ClientRequestHeader,
    ClientTokenRequest,
)
from ..schemas.versions import ProtocalVersion


class Http402Client(httpx.AsyncClient):
    """
    Extended httpx.AsyncClient with automatic 402 payment handling.
    
    This client extends httpx.AsyncClient and automatically handles 402 Payment 
    Required status codes by:
    1. Parsing payment requirements
    2. Generating signed permits
    3. Exchanging permits for access tokens
    4. Retrying the original request with authorization
    
    Fully compatible with httpx.AsyncClient - supports all methods, properties,
    and can be used as an async context manager.
    
    Usage:
        ```python
        async with Http402Client() as client:
            client.add_payment_method("eip155:11155111", 100.0, "USDC")
            response = await client.get("https://api.example.com/data")
        ```
    """
    
    def __init__(
        self,
        adapter_hub: Optional[AdapterHub] = None,
        **kwargs
    ):
        """
        Initialize client with optional payment adapter.
        
        Args:
            adapter_hub: Optional AdapterHub for payment handling
            token: Optional initial authorization token
            **kwargs: All standard httpx.AsyncClient arguments (timeout, headers, etc.)
        """
        super().__init__(**kwargs)
        self._hub = adapter_hub or AdapterHub()
    
    def add_payment_method(
        self,
        chain_id: str,
        amount: float,
        currency: str
    ) -> None:
        """
        Register local payment capability.
        
        This enables the middleware to automatically generate payment permits
        when encountering 402 responses.
        
        Args:
            chain_id: Blockchain identifier (e.g., "eip155:11155111")
            amount: Maximum payment amount supported
            currency: Currency code (e.g., "USDC")
        """
        self._hub.register_payment_methods(chain_id, amount, currency)
    
    # =========================================================================
    # Override httpx.AsyncClient.request to add 402 handling
    # =========================================================================
    
    async def request(
        self,
        method: str,
        url: httpx._types.URLTypes,
        **kwargs
    ) -> httpx.Response:
        """
        Execute HTTP request with automatic 402 handling.
        
        Overrides httpx.AsyncClient.request() to intercept 402 responses.
        All other httpx methods (get, post, etc.) automatically use this.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: All standard httpx arguments
            
        Returns:
            httpx.Response object
        """
        return await self._execute_with_402_handling(method, url, **kwargs)
    
    # =========================================================================
    # Core 402 Handling Logic
    # =========================================================================
    
    async def _execute_with_402_handling(
        self,
        method: str,
        url: httpx._types.URLTypes,
        **kwargs
    ) -> httpx.Response:
        """
        Execute request and automatically handle 402 responses.
        
        Flow:
            1. Send initial request
            2. If 402: Process payment → Get token → Retry
            3. Return final response
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional httpx arguments
            
        Returns:
            Final HTTP response (after 402 handling if needed)
        """
        # Initial request using parent class method
        response = await super().request(method, url, **kwargs)
        
        # Handle 402 and retry if needed
        if response.status_code == 402:
            base_url = self._extract_base_url(str(url))
            await self._handle_402_response(response, base_url)
            
            # Retry with authorization token
            headers = self._inject_authorization_header(kwargs.get('headers'))
            kwargs['headers'] = headers
            response = await super().request(method, url, **kwargs)
        
        return response
    
    async def _handle_402_response(
        self,
        response: httpx.Response,
        base_url: str
    ) -> None:
        """
        Process 402 Payment Required response.
        
        Orchestrates the payment flow:
        1. Parse payment requirements
        2. Generate signed permit
        3. Exchange for access token
        
        Args:
            response: 402 HTTP response
            base_url: Base URL of the server (for token exchange endpoint)
        """
        payload = self._parse_402_payload(response)
        permit = await self._generate_permit(payload)
        token = await self._exchange_permit_for_token(
            base_url,
            payload.access_token_endpoint,
            permit
        )
        self._token = token
    
    def _parse_402_payload(
        self,
        response: httpx.Response
    ) -> Server402ResponsePayload:
        """
        Parse payment requirements from 402 response.
        
        Args:
            response: 402 HTTP response
            
        Returns:
            Parsed payment scheme and token endpoint
        """
        return Server402ResponsePayload(**response.json())
    
    async def _generate_permit(
        self,
        payload: Server402ResponsePayload
    ) -> PermitTypes:
        """
        Generate signed payment permit using registered payment methods.
        
        Args:
            payload: Payment requirements from server
            
        Returns:
            Signed permit ready for token exchange
        """
        return await self._hub.signature(payload.payment_scheme.payment_components)
    
    async def _exchange_permit_for_token(
        self,
        base_url: str,
        token_endpoint: str,
        permit: PermitTypes
    ) -> str:
        """
        Exchange signed permit for access token.
        
        Args:
            base_url: Server base URL
            token_endpoint: Token exchange endpoint path
            permit: Signed payment permit
            
        Returns:
            Formatted authorization token string
        """
        url = f"{base_url}{token_endpoint}"
        request = ClientTokenRequest(
            version=ProtocalVersion.Version0_1,
            permit=permit
        )
        
        response = await super().post(
            url,
            json=request.model_dump(mode="json")
        )
        token_response = ServerTokenResponse(**response.json())
        
        return f"{token_response.token_type} {token_response.access_token}"
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def _inject_authorization_header(
        self,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Inject authorization token into request headers.
        
        Uses ClientRequestHeader model to ensure proper formatting.
        
        Args:
            headers: Existing headers dict (or None)
            
        Returns:
            Headers dict with authorization token
        """
        if self._token:
            header_model = ClientRequestHeader(authorization=self._token)
            auth_headers = header_model.model_dump(by_alias=True, exclude_none=True)
            
            if headers:
                return {**headers, **auth_headers}
            return auth_headers
        
        return headers or {}
    
    def _extract_base_url(self, url: str) -> str:
        """
        Extract base URL from full URL.
        
        Extracts scheme + netloc for constructing token endpoint URLs.
        Example: "https://api.example.com/path" -> "https://api.example.com"
        
        Args:
            url: Full URL
            
        Returns:
            Base URL (scheme + netloc)
        """
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
