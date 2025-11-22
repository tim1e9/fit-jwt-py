"""Tests for the utils module of fitjwtpy."""

import unittest
import asyncio
import base64
import json
import os
import sys
from unittest.mock import patch, Mock

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fitjwtpy.utils import get_public_key, get_environment_variables
from test.test_setup import setup_test_environment, create_mock_response


class TestUtilsModule(unittest.TestCase):
    """Test cases for the utils module."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment once before all tests."""
        setup_test_environment()
    
    @patch('fitjwtpy.utils.urlopen')
    def test_get_environment_variables_throws_if_env_var_is_missing(self, mock_urlopen):
        """Test that get_environment_variables raises ValueError when env vars are missing."""
        # Mock the JWKS response
        mock_response = create_mock_response({'keys': []})
        mock_urlopen.return_value = mock_response
        
        # Save and delete CLIENT_ID
        backup = os.environ.get('CLIENT_ID')
        if 'CLIENT_ID' in os.environ:
            del os.environ['CLIENT_ID']
        
        # Test that it raises ValueError
        with self.assertRaises(ValueError) as context:
            get_environment_variables()
        
        self.assertIn('Not all environment variables', str(context.exception))
        
        # Restore CLIENT_ID
        if backup:
            os.environ['CLIENT_ID'] = backup
    
    @patch('fitjwtpy.utils.urlopen')
    def test_get_public_key_throws_if_key_not_found(self, mock_urlopen):
        """Test that get_public_key raises ValueError when key is not found."""
        # Mock the JWKS response with empty keys
        mock_response = create_mock_response({'keys': []})
        mock_urlopen.return_value = mock_response
        
        # Initialize environment
        get_environment_variables()
        
        # Test that it raises ValueError for non-existent key
        with self.assertRaises(ValueError) as context:
            get_public_key('nonexistent')
        
        self.assertIn('No key found', str(context.exception))
    
    @patch('fitjwtpy.utils.urlopen')
    def test_get_public_key_constructs_pem_from_valid_fake_jwks_entry(self, mock_urlopen):
        """Test that get_public_key constructs a valid PEM from JWKS entry."""
        # Create a fake JWKS entry
        modulus = base64.urlsafe_b64encode(b'abcd1234').decode('utf-8').rstrip('=')
        exponent = base64.urlsafe_b64encode(bytes([0x01, 0x00, 0x01])).decode('utf-8').rstrip('=')
        
        mock_response = create_mock_response({
            'keys': [
                {
                    'kid': 'test-key',
                    'kty': 'RSA',
                    'alg': 'RS256',
                    'use': 'sig',
                    'n': modulus,
                    'e': exponent
                }
            ]
        })
        mock_urlopen.return_value = mock_response
        
        # Initialize environment with custom key
        get_environment_variables()
        
        # Get the public key
        pem = get_public_key('test-key')
        
        # Verify PEM format (PKCS#8 format, not PKCS#1)
        self.assertIn('-----BEGIN PUBLIC KEY-----', pem)
        self.assertIn('-----END PUBLIC KEY-----', pem)


if __name__ == '__main__':
    unittest.main()
