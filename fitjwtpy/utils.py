"""
Utility functions for JWT/OIDC operations including environment variable handling,
OIDC URL construction, RSA key management, and token validation.
"""

import os
import json
import base64
import time
from typing import Dict, Any, Optional
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend

# Global environment variables storage
_ev: Optional[Dict[str, Any]] = None


def get_public_key(key_id: str) -> str:
    """
    Given a key ID, reconstitute an RSA public key from JWKS.
    
    Uses the cryptography library to construct the RSA public key from the
    modulus (n) and exponent (e) values in the JWKS entry.
    
    Args:
        key_id: The key ID (kid) from the JWT header
        
    Returns:
        PEM-formatted RSA public key
        
    Raises:
        ValueError: If the key ID is not found in the JWKS
    """
    keys = _ev['JWKS_KEYS']
    jwk = next((k for k in keys if k.get('kid') == key_id), None)
    
    if not jwk:
        raise ValueError(f"No key found for key with ID: {key_id}. Retrieve new keys?")
    
    # Decode the base64url-encoded modulus and exponent, convert to integers
    n = int.from_bytes(base64.urlsafe_b64decode(jwk['n'] + '=='), 'big')
    e = int.from_bytes(base64.urlsafe_b64decode(jwk['e'] + '=='), 'big')
    
    # Construct the RSA public key using cryptography library
    public_numbers = rsa.RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key()
    
    # Export to PEM format
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pem_bytes.decode('utf-8')


def get_environment_variables() -> Dict[str, Any]:
    """
    Load and validate all required environment variables and fetch JWKS keys.
    
    Returns:
        Dictionary containing all environment variables and JWKS keys
        
    Raises:
        ValueError: If any required environment variable is missing
    """
    global _ev
    
    # Load common environment variables
    _ev = {
        'AUTH_ENDPOINT': os.environ.get('AUTH_ENDPOINT'),
        'TOKEN_ENDPOINT': os.environ.get('TOKEN_ENDPOINT'),
        'OAUTH_REDIR_URI': os.environ.get('OAUTH_REDIR_URI', '/auth/callback'),
        'CUR_HOSTNAME': os.environ.get('CUR_HOSTNAME'),
        'CLIENT_ID': os.environ.get('CLIENT_ID'),
        'CLIENT_SECRET': os.environ.get('CLIENT_SECRET'),
        'STATE': os.environ.get('OAUTH_STATE'),
        'SCOPE': os.environ.get('OAUTH_SCOPE'),
        'RESPONSE_TYPE': os.environ.get('OAUTH_RESP_TYPE', 'code'),
        'JWKS_URL': os.environ.get('JWKS_URL'),
    }
    
    # Validate all required variables are present
    if any(v is None for v in _ev.values()):
        raise ValueError("Not all environment variables are defined. Please review all required fields.")
    
    # Load the keys (JWKS)
    try:
        req = Request(_ev['JWKS_URL'], headers={'Content-Type': 'application/json'})
        with urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
            _ev['JWKS_KEYS'] = data['keys']
    except Exception as e:
        raise RuntimeError(f"Failed to load JWKS keys from {_ev['JWKS_URL']}: {e}")
    
    return _ev


def get_oidc_provider_url() -> str:
    """
    Construct the OIDC provider authorization URL with required parameters.
    
    Returns:
        Complete authorization URL
    """
    params = {
        'client_id': _ev['CLIENT_ID'],
        'scope': _ev['SCOPE'],
        'response_type': _ev['RESPONSE_TYPE'],
        'redirect_uri': _ev['CUR_HOSTNAME'] + _ev['OAUTH_REDIR_URI'],
        'state': _ev['STATE'],
    }
    return f"{_ev['AUTH_ENDPOINT']}?{urlencode(params)}"


def get_token_url() -> str:
    """
    Get the token endpoint URL.
    
    Returns:
        Token endpoint URL
    """
    return _ev['TOKEN_ENDPOINT']


def is_valid_signature(raw_token: str) -> bool:
    """
    Validate the JWT signature using RS256 algorithm.
    
    Args:
        raw_token: The raw JWT token string
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        
        parts = raw_token.split('.')
        if len(parts) != 3:
            return False
            
        raw_token_header, raw_token_payload, raw_token_signature = parts
        
        # Decode the signature
        token_signature = base64.urlsafe_b64decode(raw_token_signature + '==')
        
        # Parse header and check algorithm
        token_header = json.loads(base64.urlsafe_b64decode(raw_token_header + '==').decode('utf-8'))
        if token_header.get('alg') != 'RS256':
            print(f"Only the RS256 algorithm is supported. Current algorithm: {token_header.get('alg')}")
            return False
        
        # Reconstitute the content to verify
        content_to_verify = f"{raw_token_header}.{raw_token_payload}".encode('utf-8')
        
        # Get public key and verify
        public_key_pem = get_public_key(token_header['kid'])
        public_key = load_pem_public_key(public_key_pem.encode('utf-8'), backend=default_backend())
        
        # Verify the signature
        try:
            public_key.verify(
                token_signature,
                content_to_verify,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
            
    except Exception as exc:
        print(f"Error verifying the JWT signature: {exc}")
        return False
