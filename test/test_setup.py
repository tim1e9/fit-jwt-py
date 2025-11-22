"""Test setup utilities for fitjwtpy tests."""

import os
from typing import Dict, Any
from unittest.mock import Mock


def setup_test_environment() -> None:
    """Configure environment variables and mock fetch for testing."""
    # Set up test environment variables
    os.environ['AUTH_ENDPOINT'] = 'https://example.com/auth'
    os.environ['TOKEN_ENDPOINT'] = 'https://example.com/token'
    os.environ['OAUTH_REDIR_URI'] = '/auth/callback'
    os.environ['CUR_HOSTNAME'] = 'https://localhost:3000'
    os.environ['CLIENT_ID'] = 'abc123'
    os.environ['CLIENT_SECRET'] = 'secret'
    os.environ['OAUTH_STATE'] = 'xyz'
    os.environ['OAUTH_SCOPE'] = 'openid email'
    os.environ['JWKS_URL'] = 'http://localhost:9999/mock-jwks'


def create_mock_response(json_data: Dict[str, Any]) -> Mock:
    """Create a mock HTTP response object."""
    mock_response = Mock()
    mock_response.read.return_value = str(json_data).replace("'", '"').encode('utf-8')
    mock_response.__enter__ = Mock(return_value=mock_response)
    mock_response.__exit__ = Mock(return_value=False)
    return mock_response
