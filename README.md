# fitjwtpy

A lightweight / fit Python library for working with JWT and OIDC authentication flows.

This is a Python port of the [fit-jwt](https://github.com/tim1e9/fit-jwt) JavaScript/TypeScript
library, maintaining the same API design and zero-dependency philosophy (aside from `cryptography`
for RSA signature verification).

**NOTE**: If you're looking for a complete, OAuth-compliant client, this isn't it. Instead, this
library implements a subset of the specification. The purpose of this subset is to simplify the
developer experience, avoid exposing unused code to potential security issues, and to make things
cleaner. But with that said, this isn't for everyone. If you're not sure, you should probably ask
someone you trust before going any further.

## How to use it

Install the package with `pip install fitjwtpy`. Then, add code to your project as necessary.

**NOTE** A full example exists in the `./_samples` directory. It outlines
everything required to use this library - including application flows and environment variables.


## Environment Variables

The library requires the following environment variables:

```bash
# OAuth Provider Endpoints
AUTH_ENDPOINT=https://your-provider.com/oauth/authorize
TOKEN_ENDPOINT=https://your-provider.com/oauth/token
JWKS_URL=https://your-provider.com/.well-known/jwks.json

# Your Application Configuration
CLIENT_ID=your_client_id
CLIENT_SECRET=your_client_secret
CUR_HOSTNAME=https://your-app.com
OAUTH_REDIR_URI=/auth/callback

# OAuth Parameters
OAUTH_STATE=random_state_value
OAUTH_SCOPE=openid email profile
OAUTH_RESP_TYPE=code  # default: code
```

See the `_samples` directory for provider-specific configuration examples
(Auth0, AWS Cognito, Google, Keycloak).


## Running Tests

The tests require the `cryptography` dependency to be installed.

```bash
# Install dependencies (if not already installed)
pip install cryptography

# Run all tests (verbose mode recommended for clarity)
python -m unittest discover test -v

# Run without verbose output
python -m unittest discover test

# Run specific test file
python -m unittest test.test_index
```

**Note:** You may see error messages during test runs - these are expected as the
tests verify error handling behavior.

## Building and Deploying to PyPI

### Prerequisites

Install the required build tools:

```bash
pip install build twine
```

### Building the Package

1. **Clean previous builds** (optional but recommended):

```bash
rm -rf dist/ build/ *.egg-info
```

2. **Build the distribution packages**:

```bash
python -m build
```

This creates two files in the `dist/` directory:
- A source distribution (`.tar.gz`)
- A wheel distribution (`.whl`)

### Testing the Build Locally

Before deploying, test the package locally:

```bash
pip install dist/fitjwtpy-*.whl
```

Or test in a virtual environment:

```bash
python -m venv test_env
source test_env/bin/activate  # On Windows: test_env\Scripts\activate
pip install dist/fitjwtpy-*.whl
python -c "import fitjwtpy; print('Package installed successfully')"
deactivate
```

### Deploying to PyPI

#### Private PyPI Registry

To publish to a private PyPI registry (e.g. JFrog Artifactory, Nexus, or self-hosted):

1. **Configure your private registry URL**:

```bash
# Example for a private registry
PRIVATE_REPO_URL=http://noobnoob.io:8888
```

2. **Upload to your private registry**:

```bash
python -m twine upload --verbose --repository-url http://noobnoob.io:8888 dist/*
```

When prompted, enter your private registry credentials (username and password/token).

3. **Test installation from your private registry**:

```bash
pip install --index-url https://your-private-pypi.company.com/simple/ fitjwtpy
```

**JFrog Artifactory Example:**

```bash
# Upload to Artifactory
python -m twine upload \
    --repository-url https://artifactory.company.com/artifactory/api/pypi/pypi-local \
    --username your-username \
    --password your-api-key \
    dist/*
```


## Sample Application

A complete sample application is included in `_samples/default-sample/`. It demonstrates:
- OAuth 2.0 login flow with PKCE
- Token validation and user information extraction
- Token refresh
- Protected routes


## Differences from JavaScript Version

This Python port maintains API parity with the original JavaScript library, with these adaptations:

1. **Naming Convention**: Uses `snake_case` instead of `camelCase` (Pythonic)
2. **Synchronous Design**: All functions are synchronous
3. **Dependencies**: Uses `cryptography` library for RSA operations (JavaScript uses built-in `crypto`)

## Supported OAuth Providers

The library works with any OAuth 2.0 / OIDC compliant provider. Sample configurations are provided for:

- Auth0
- AWS Cognito
- Google
- Keycloak

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Credits

Python port by Tim Crowley, based on the original
[fit-jwt](https://github.com/tim1e9/fit-jwt) JavaScript library.
