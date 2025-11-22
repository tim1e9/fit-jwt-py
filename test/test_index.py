"""Tests for the main index module of fitjwtpy."""

import unittest
import base64
from unittest.mock import patch, Mock
import sys
import os

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fitjwtpy.index import (
    PkceDetails,
    JwtTokens,
    get_user_from_token,
    get_jwt_token,
    refresh_jwt_token,
    init
)
from test.test_setup import setup_test_environment, create_mock_response


class TestIndexModule(unittest.TestCase):
    """Test cases for the main index module."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment once before all tests."""
        setup_test_environment()
    
    def test_pkce_details_and_jwt_tokens_store_data_correctly(self):
        """Test that PkceDetails and JwtTokens classes store data correctly."""
        pkce = PkceDetails('verifier', 'challenge', 'plain')
        self.assertEqual(pkce.code_verifier, 'verifier')
        self.assertEqual(pkce.code_challenge, 'challenge')
        self.assertEqual(pkce.method, 'plain')
        
        jwt = JwtTokens('a', 'b', 'c')
        self.assertEqual(jwt.access_token, 'a')
        self.assertEqual(jwt.id_token, 'b')
        self.assertEqual(jwt.refresh_token, 'c')
    
    @patch('fitjwtpy.utils.urlopen')  # Mock JWKS fetch in init()
    @patch('fitjwtpy.index.urlopen')  # Mock token endpoint
    def test_get_jwt_token_returns_tokens_from_mocked_fetch(self, mock_index_urlopen, mock_utils_urlopen):
        """Test that get_jwt_token returns tokens from a mocked HTTP response."""
        # Mock the JWKS response for init()
        mock_jwks_response = create_mock_response({'keys': []})
        mock_utils_urlopen.return_value = mock_jwks_response
        
        # Mock the token response
        mock_token_response = create_mock_response({
            'access_token': 'tokenA',
            'id_token': 'tokenB',
            'refresh_token': 'tokenC'
        })
        mock_index_urlopen.return_value = mock_token_response
        
        # Initialize and test
        init()
        token = get_jwt_token('code123', 'verifier123')
        
        self.assertEqual(token.access_token, 'tokenA')
        self.assertEqual(token.id_token, 'tokenB')
        self.assertEqual(token.refresh_token, 'tokenC')
    
    @patch('fitjwtpy.utils.urlopen')  # Mock JWKS fetch in init()
    @patch('fitjwtpy.index.urlopen')  # Mock token endpoint
    def test_refresh_jwt_token_returns_tokens_from_mocked_fetch(self, mock_index_urlopen, mock_utils_urlopen):
        """Test that refresh_jwt_token returns tokens from a mocked HTTP response."""
        # Mock the JWKS response for init()
        mock_jwks_response = create_mock_response({'keys': []})
        mock_utils_urlopen.return_value = mock_jwks_response
        
        # Mock the token response
        mock_token_response = create_mock_response({
            'accessToken': 'refA',
            'id_token': 'refB',
            'refresh_token': 'refC'
        })
        mock_index_urlopen.return_value = mock_token_response
        
        # Initialize and test
        init()
        token = refresh_jwt_token('refresh-123')
        
        self.assertEqual(token.access_token, 'refA')
        self.assertEqual(token.id_token, 'refB')
        self.assertEqual(token.refresh_token, 'refC')
    
    @patch('fitjwtpy.utils.urlopen')  # Mock JWKS fetch in init()
    @patch('fitjwtpy.index.urlopen')  # Mock token endpoint
    def test_get_jwt_token_throws_on_fetch_failure(self, mock_index_urlopen, mock_utils_urlopen):
        """Test that get_jwt_token raises an exception on fetch failure."""
        # Mock the JWKS response for init()
        mock_jwks_response = create_mock_response({'keys': []})
        mock_utils_urlopen.return_value = mock_jwks_response
        
        mock_index_urlopen.side_effect = Exception('mocked fetch error')
        
        init()
        
        with self.assertRaises(Exception) as context:
            get_jwt_token('code', 'verifier')
        
        self.assertIn('Exception thrown when attempting to obtain a token', str(context.exception))
    
    @patch('fitjwtpy.utils.urlopen')  # Mock JWKS fetch in init()
    @patch('fitjwtpy.index.urlopen')  # Mock token endpoint
    def test_get_jwt_token_throws_if_json_response_is_invalid(self, mock_index_urlopen, mock_utils_urlopen):
        """Test that get_jwt_token raises an exception if JSON response is invalid."""
        # Mock the JWKS response for init()
        mock_jwks_response = create_mock_response({'keys': []})
        mock_utils_urlopen.return_value = mock_jwks_response
        
        mock_response = Mock()
        mock_response.read.side_effect = Exception('bad json')
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_index_urlopen.return_value = mock_response
        
        init()
        
        with self.assertRaises(Exception) as context:
            get_jwt_token('code', 'verifier')
        
        self.assertIn('Exception thrown when attempting to obtain a token', str(context.exception))
    
    @patch('fitjwtpy.utils.urlopen')  # Mock JWKS fetch in init()
    @patch('fitjwtpy.index.urlopen')  # Mock token endpoint
    def test_get_jwt_token_handles_missing_tokens_gracefully(self, mock_index_urlopen, mock_utils_urlopen):
        """Test that get_jwt_token handles missing tokens in response."""
        # Mock the JWKS response for init()
        mock_jwks_response = create_mock_response({'keys': []})
        mock_utils_urlopen.return_value = mock_jwks_response
        
        mock_token_response = create_mock_response({})
        mock_index_urlopen.return_value = mock_token_response
        
        init()
        result = get_jwt_token('code', 'verifier')
        
        self.assertIsInstance(result, JwtTokens)
        self.assertIsNone(result.access_token)
        self.assertIsNone(result.id_token)
        self.assertIsNone(result.refresh_token)
    
    @patch('fitjwtpy.utils.urlopen')  # Mock JWKS fetch in init()
    @patch('fitjwtpy.index.urlopen')  # Mock token endpoint
    def test_refresh_jwt_token_throws_on_fetch_failure(self, mock_index_urlopen, mock_utils_urlopen):
        """Test that refresh_jwt_token raises an exception on fetch failure."""
        # Mock the JWKS response for init()
        mock_jwks_response = create_mock_response({'keys': []})
        mock_utils_urlopen.return_value = mock_jwks_response
        
        mock_index_urlopen.side_effect = Exception('mocked refresh error')
        
        init()
        
        with self.assertRaises(Exception) as context:
            refresh_jwt_token('refresh-token')
        
        self.assertIn('Exception thrown when attempting to refresh a token', str(context.exception))
    
    def test_get_user_from_token_returns_none_if_token_is_invalid(self):
        """Test that get_user_from_token returns None for invalid tokens."""
        token = 'header.payload.sig'
        result = get_user_from_token(token)
        self.assertIsNone(result)
    
    def test_get_user_from_token_returns_none_if_payload_is_malformed_json(self):
        """Test that get_user_from_token returns None for malformed JSON in payload."""
        # Create a payload with invalid JSON
        payload = base64.urlsafe_b64encode(b'this is not json').decode('utf-8').rstrip('=')
        token = f"header.{payload}.sig"
        result = get_user_from_token(token)
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
