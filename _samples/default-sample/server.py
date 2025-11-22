"""
Simple Flask server demonstrating fitjwtpy usage.

This server shows how to implement OAuth 2.0 / OIDC authentication
using the fitjwtpy library with Flask.
"""

import json
import os
from flask import Flask, request, redirect, jsonify, make_response
from dotenv import load_dotenv
from functools import wraps

from fitjwtpy import (
    get_auth_url,
    get_pkce_details,
    get_jwt_token,
    refresh_jwt_token,
    get_user_from_token,
    init
)

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
COOKIE_NAME = os.environ.get('COOKIE_NAME', 'pkce_cookie')
JWT_HEADER_NAME = os.environ.get('JWT_HEADER_NAME', 'Authorization')
PORT = int(os.environ.get('PYTHON_PORT', 3000))


# ------------------- Authn / Authz Endpoints --------------------------------

@app.route('/login')
def login():
    # We are using (Proof Key for Code Exchange) or "PKCE". Don't ask - I don't name this stuff
    # We are also mandating the S256 hash of the PKCE code
    pkce_details = get_pkce_details('S256')
    response = make_response(redirect(get_auth_url(pkce_details)))
    response.set_cookie(COOKIE_NAME, json.dumps({
        'codeVerifier': pkce_details.code_verifier,
        'codeChallenge': pkce_details.code_challenge,
        'method': pkce_details.method
    }))
    return response


# This is called after the user has authenticated. Extract the code, and exchange it for a JWT token.
@app.route('/auth/callback')
def auth_callback():
    code = request.args.get('code')
    # Extract the code challenge from the cookie
    raw_cookie = request.cookies.get(COOKIE_NAME)
    if not raw_cookie:
        return jsonify({'status': 'cookie missing'})
    else:
        pkce_details = json.loads(raw_cookie)
        # Note: get_jwt_token() can throw an exception. A real app should catch and handle it.
        jwt_components = get_jwt_token(code, pkce_details['codeVerifier'])
        
        # Clear the cookie - it's no longer needed
        response = make_response(jsonify({
            'accessToken': jwt_components.access_token,
            'idToken': jwt_components.id_token,
            'refreshToken': jwt_components.refresh_token
        }))
        response.set_cookie(COOKIE_NAME, '', expires=0)
        
        # Redirect this to the main authenticated landing page, but include the token(s)
        return response


# Logout callback. This may be called when a user explicitly logs out, but it's generally not used.
# Remember: JWTs don't really get invalidated; they simply expire over time. Of course, we can
# add custom code to simulate JWT invalidation, but it's a slippery slope
@app.route('/logout/callback')
def logout_callback():
    return redirect('/')


# This should be used as Flask decorator before every secure route is called. It will attempt
# to verify the user details, and if valid, place those details within the request.
def check_authenticated(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get(JWT_HEADER_NAME)
        if not token:
            return jsonify({'message': 'User does not have credentials'}), 401
        
        user = get_user_from_token(token)
        if not user:
            return jsonify({'message': 'User details are missing. Does the user have valid credentials?'}), 401
        
        request.user = user
        return f(*args, **kwargs)
    return decorated_function


# ----------------------------------------------------------------------------

# The default, unprotected route
@app.route('/')
def index():
    return jsonify({'msg': 'The index is not protected, so everyone should be able to see this.'})


@app.route('/aboutme')
@check_authenticated
def aboutme():
    # If the user details aren't found, this code will never run. (See check_authenticated())
    user = request.user
    return jsonify({'msg': user})


@app.route('/testrefresh')
def testrefresh():
    # Test the ability to refresh a JWT token. (This is just used for completeness. Consider
    # a far more comprehensive workflow for refreshing a token in a real app.)
    token = request.headers.get('Authorization')
    # Note: refresh_jwt_token() can throw an exception. A real app should catch and handle it.
    new_details = refresh_jwt_token(token)
    return jsonify({
        'msg': {
            'accessToken': new_details.access_token,
            'idToken': new_details.id_token,
            'refreshToken': new_details.refresh_token
        }
    })


# ------------------------- Standard Python/Flask Scaffolding ----------------------

if __name__ == '__main__':
    init()
    print(f"Example app listening at http://localhost:{PORT}")
    app.run(host='0.0.0.0', port=PORT, debug=True)
