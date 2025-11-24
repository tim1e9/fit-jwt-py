"""
fitjwtpy: A lightweight Python library for working with JWT and OIDC.
"""

import os
import base64
import hashlib
import json
import time
from typing import Optional, Dict, Any
from urllib.request import urlopen, Request
from urllib.parse import urlencode

from .utils import (
    get_environment_variables,
    get_oidc_provider_url,
    get_token_url,
    is_valid_signature
)


class PkceDetails:
    """
    Container for PKCE (Proof Key for Code Exchange) authentication details.
    
    Attributes:
        code_verifier: Random string used to generate the code challenge
        code_challenge: Hashed version of code_verifier (or plain text if method is 'plain')
        method: PKCE method, either 'S256' or 'plain'
    """
    
    def __init__(self, code_verifier: str, code_challenge: str, method: str):
        self.code_verifier = code_verifier
        self.code_challenge = code_challenge
        self.method = method


class JwtTokens:
    """
    Container for the three types of tokens associated with JWT/OIDC.
    
    Attributes:
        access_token: Token used to access protected resources
        id_token: Token containing user identity information
        refresh_token: Token used to obtain new access tokens
    """
    
    def __init__(self, access_token: str, id_token: str, refresh_token: str):
        self.access_token = access_token
        self.id_token = id_token
        self.refresh_token = refresh_token


# Global variables for environment and URLs
_ev: Optional[Dict[str, Any]] = None
_AUTH_URL: Optional[str] = None
_token_url: Optional[str] = None


def init() -> None:
    """
    Initialize the library by loading environment variables and OIDC configuration.
    
    This function must be called before using any other library functions.
    It loads environment variables and fetches JWKS keys from the provider.
    
    Raises:
        ValueError: If required environment variables are missing
    """
    global _ev, _AUTH_URL, _token_url
    _ev = get_environment_variables()
    _AUTH_URL = get_oidc_provider_url()
    _token_url = get_token_url()


def get_pkce_details(pkce_method: str = 'S256') -> PkceDetails:
    """
    Generate PKCE details for OAuth 2.0 authorization flow.
    
    Args:
        pkce_method: The PKCE method to use, either 'S256' (default) or 'plain'
        
    Returns:
        PkceDetails object containing code verifier, challenge, and method
    """
    # Generate a random code verifier
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
    
    # Generate code challenge based on method
    if pkce_method == 'plain':
        code_challenge = code_verifier
    else:
        # S256: SHA256 hash of the verifier
        hash_digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(hash_digest).decode('utf-8').rstrip('=')
    
    return PkceDetails(code_verifier, code_challenge, pkce_method)


def get_auth_url(pkce_details: PkceDetails) -> str:
    """
    Construct the authorization URL with PKCE parameters.
    
    Args:
        pkce_details: PKCE details to include in the URL
        
    Returns:
        Complete authorization URL with PKCE parameters
    """
    params = {
        'code_challenge': pkce_details.code_challenge,
        'code_challenge_method': pkce_details.method,
    }
    return f"{_AUTH_URL}&{urlencode(params)}"


def get_jwt_token(code: str, code_verifier: str) -> JwtTokens:
    """
    Exchange an authorization code for JWT tokens.
    
    Args:
        code: The authorization code received from the OAuth provider
        code_verifier: The PKCE code verifier used in the authorization request
        
    Returns:
        JwtTokens object containing access, ID, and refresh tokens
        
    Raises:
        Exception: If the token request fails
    """
    try:
        # The token request requires authentication with client credentials
        credentials = f"{_ev['CLIENT_ID']}:{_ev['CLIENT_SECRET']}"
        base64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8')
        auth_header = f"Basic {base64_creds}"
        
        # Prepare form data
        form_data = {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': _ev['CLIENT_ID'],
            'redirect_uri': _ev['CUR_HOSTNAME'] + _ev['OAUTH_REDIR_URI'],
            'code_verifier': code_verifier,
        }
        
        # Make the token request
        data = urlencode(form_data).encode('utf-8')
        req = Request(
            _token_url,
            data=data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': auth_header
            }
        )
        
        with urlopen(req) as response:
            all_data = json.loads(response.read().decode('utf-8'))
            
        # Format the response to include the three retrieved tokens
        jwt_tokens = JwtTokens(
            all_data.get('access_token'),
            all_data.get('id_token'),
            all_data.get('refresh_token')
        )
        return jwt_tokens
        
    except Exception as exc:
        msg = f"Error: Exception thrown when attempting to obtain a token: {exc}"
        print(msg)
        raise Exception(msg)


def refresh_jwt_token(refresh_token: str) -> JwtTokens:
    """
    Refresh JWT tokens using a refresh token.
    
    Args:
        refresh_token: The refresh token to use for obtaining new tokens
        
    Returns:
        JwtTokens object containing new access, ID, and refresh tokens
        
    Raises:
        Exception: If the refresh request fails
    """
    try:
        # Prepare authentication header
        credentials = f"{_ev['CLIENT_ID']}:{_ev['CLIENT_SECRET']}"
        base64_creds = base64.urlsafe_b64encode(credentials.encode('utf-8')).decode('utf-8')
        auth_header = f"Basic {base64_creds}"
        
        # Prepare form data
        form_data = {
            'grant_type': 'refresh_token',
            'client_id': _ev['CLIENT_ID'],
            'refresh_token': refresh_token,
        }
        
        # Make the refresh request
        data = urlencode(form_data).encode('utf-8')
        req = Request(
            _token_url,
            data=data,
            headers={
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': auth_header
            }
        )
        
        with urlopen(req) as response:
            all_data = json.loads(response.read().decode('utf-8'))
            
        # Format the response to include the three retrieved tokens
        jwt_tokens = JwtTokens(
            all_data.get('access_token'),
            all_data.get('id_token'),
            all_data.get('refresh_token')
        )
        return jwt_tokens
        
    except Exception as exc:
        msg = f"Error: Exception thrown when attempting to refresh a token: {exc}"
        print(msg)
        raise Exception(msg)


def is_token_valid(cur_token: str, token_type: str) -> bool:
    """
    Validate a JWT token by checking signature, audience, issuer, and expiration.
    
    Args:
        cur_token: The JWT token to validate
        
    Returns:
        True if token is valid, False otherwise
    """
    try:
        # only 'id_token' or 'access_token' values are valid
        if token_type not in ['id_token', 'access_token']:
            raise ValueError("Invalid token type. Only 'id_token' or 'access_token' are allowed.")
        
        parts = cur_token.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid token format")
            
        _jwt_header, jwt_payload, _jwt_signature = parts
        
        # Validate signature
        if not is_valid_signature(cur_token):
            raise ValueError("The JSON signature is not valid.")
        
        # Decode payload
        jwt_details = json.loads(base64.urlsafe_b64decode(jwt_payload + '==').decode('utf-8'))

        # Verify issuer (check if JWKS_URL contains the issuer)
        if jwt_details.get('iss') not in _ev['JWKS_URL']:
            raise ValueError("The issuer for the token is different from what is expected.")

        if token_type == 'id_token':
            # Verify audience matches client ID
            if jwt_details.get('aud') != _ev['CLIENT_ID']:
                raise ValueError("The token audience doesn't match what was sent")        

        # Check token expiration
        exp_time = jwt_details.get('exp', 0) * 1000  # Convert to milliseconds
        cur_time = int(time.time() * 1000)
        if exp_time < cur_time:
            raise ValueError("The token has expired")
        
        return True
        
    except Exception as exc:
        print(f"Error parsing the jwtDetails from a token: {exc}")
        return False


# This can get confusing. This is called to access resources, so we really need
# the access token. However, we're grabbing the current user's details, so it feels
# like we should use the id_token. Resist the urge to use the id_token. What a mess.
def get_user_from_token(access_token: str) -> Optional[Dict[str, Any]]:
    """
    Extract and validate user information from an access token.
    
    Args:
        access_token: The JWT access token to parse
        
    Returns:
        Dictionary containing user information, or None if token is invalid
    """
    if not is_token_valid(access_token, "access_token"):
        return None
    
    try:
        parts = access_token.split('.')
        if len(parts) != 3:
            return None
            
        _jwt_header, jwt_payload, _jwt_signature = parts
        
        # Decode the payload
        user = json.loads(base64.urlsafe_b64decode(jwt_payload + '==').decode('utf-8'))
        return user
        
    except Exception:
        return None
