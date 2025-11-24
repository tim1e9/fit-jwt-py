"""Type stubs for fitjwtpy"""

from typing import Dict, Any, Optional


class PkceDetails:
    """PKCE authentication details container."""
    code_verifier: str
    code_challenge: str
    method: str
    
    def __init__(self, code_verifier: str, code_challenge: str, method: str) -> None: ...


class JwtTokens:
    """JWT tokens container."""
    access_token: str
    id_token: str
    refresh_token: str
    
    def __init__(self, access_token: str, id_token: str, refresh_token: str) -> None: ...


def init() -> None:
    """Initialize the library by loading environment variables and OIDC configuration."""
    ...


def get_auth_url(pkce_details: PkceDetails) -> str:
    """Construct the authorization URL with PKCE parameters."""
    ...


def get_pkce_details(pkce_method: str = 'S256') -> PkceDetails:
    """Generate PKCE details for OAuth 2.0 authorization flow."""
    ...


def get_jwt_token(code: str, code_verifier: str) -> JwtTokens:
    """Exchange an authorization code for JWT tokens."""
    ...


def refresh_jwt_token(refresh_token: str) -> JwtTokens:
    """Refresh JWT tokens using a refresh token."""
    ...


def is_token_valid(cur_token: str, token_type: str) -> bool:
    """Validate a JWT token by checking signature, audience, issuer, and expiration."""
    ...


def get_user_from_token(access_token: str) -> Optional[Dict[str, Any]]:
    """Extract and validate user information from an access token."""
    ...
