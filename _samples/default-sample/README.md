# Using fitjwtpy

This sample application demonstrates how to use fitjwtpy in a Python application.

## Running the Application

**NOTE**: fitjwtpy is not published to PyPi. The following steps describe how to
pull it from a private registry. To publish fitjwtpy to a private registry,
please refer to the main `README.md` file.

Steps to run:
1. Configure pip to use your private PyPI server using the local `pip.conf` file:
   ```bash
   # Set the private registry URL environment variable
   export PRIVATE_PYPI_URL=http://noobnoob.io:8888/simple/
   
   # Point pip to use the local pip.conf file in this directory
   export PIP_CONFIG_FILE=./pip.conf
   
   # Install dependencies
   pip install -r requirements.txt
   ```

2. Verify that all environment variables are properly defined in a `.env` file.
   (See the environment variable sample files in the parent `_samples` directory for more details.)

3. Start the application:
   ```bash
   python server.py
   ```

4. In a browser, navigate to the main page: http://localhost:3000/
   
   The response should be a simple JSON doc which reads:
   ```json
   {
     "msg": "The index is not protected, so everyone should be able to see this."
   }
   ```

5. To force authentication, navigate to the login page: http://localhost:3000/login

6. You should be redirected to the OAuth provider. From there, provide your credentials.

7. If the credentials are correct, the browser should show the authenticated details.
   (Remember - this is a sample. You wouldn't normally do this.)

8. To verify that the credentials are "real", navigate to http://localhost:3000/aboutme
   
   This should display information that was returned by the OAuth provider. **HOWEVER**, since
   this isn't a real application, and client-side persistence isn't implemented, you may need
   to copy the ID token and use it in the following curl command:
   ```bash
   export TMP_AUTH=<place the access token value here>
   curl -H "Authorization: $TMP_AUTH" http://localhost:3000/aboutme
   ```
   
   The output should be something similar to the following:
   ```json
   {
     "msg": {
         "exp": 1747231259,
         "iat": 1747230959,
         "auth_time": 1747230705,
         "name": "Firstname Lastname",
         "preferred_username": "kpowers",
         "given_name": "Firstname",
         "family_name": "Lastname",
         "email": "kpowers@example.com"
      }
   }
   ```

9. For some applications, it may be valuable to include logout functionality. Although
   nothing happens within this application, the logout route has been included for 
   demonstration purposes.

10. It is also possible to refresh the JWT token by navigating to: http://localhost:3000/testrefresh
    After navigating to this URL, the refreshed tokens should be visible.

## Differences from Node.js Version

- Uses Python's built-in `http.server` instead of Express.js (zero external web framework dependencies)
- Uses `python-dotenv` for environment variable loading (equivalent to Node's dotenv)
- Cookie handling uses Python's `SimpleCookie` from the standard library
- Async operations use Python's `asyncio` instead of JavaScript promises

## References

PKCE - (https://datatracker.ietf.org/doc/html/rfc7636) requires these three values:
       Code Challenge, Code Challenge Method, and Code Verifier
       
A nice explanation: https://pazel.dev/teach-me-pkce-proof-key-for-code-exchange-in-5-minutes
