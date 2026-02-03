# Postman Testing Guide for Authorization Server

This guide provides step-by-step instructions for testing the OAuth2 Authorization Server using Postman.

## Server Configuration

- **Base URL**: `http://localhost:12000`
- **Issuer**: `http://localhost:12000`
- **Protocol**: OAuth 2.0 / OpenID Connect
- **Token Signing Algorithm**: RS256

## Supported Scopes

- `openid` - OpenID Connect authentication
- `read` - Read access
- `write` - Write access (if allowed for client)
- `username` - Access to username
- `profile` - Access to user profile
- `personal` - Access to personal data

## Supported Grant Types

- **Authorization Code** with PKCE (Proof Key for Code Exchange)
- **Refresh Token**
- **Client Credentials** (if configured)

---

## 1. Create a Client (Optional)

If you need to register a new OAuth2 client, use this endpoint.

### Request

```http
POST http://localhost:12000/client/create-client
Content-Type: application/json
```

### Request Body

```json
{
  "clientId": "postman-test-client",
  "clientSecret": "postman-secret-123",
  "redirectUrl": "https://oauth.pstmn.io/v1/callback",
  "showConsentForm": true,
  "writeAllowed": true,
  "allowProfile": true,
  "allowPersonalData": false
}
```

### Response

```json
{
  "id": "65f1a2b3c4d5e6f7a8b9c0d1",
  "clientId": "postman-test-client",
  "redirectUrl": "https://oauth.pstmn.io/v1/callback",
  "createdAt": "2026-02-03T08:15:00Z"
}
```

> [!NOTE]
> Save the `clientId` and `clientSecret` for subsequent requests.

---

## 2. Authorization Code Flow with PKCE

This is the recommended flow for testing the full OAuth2 authorization process.

### Step 2.1: Generate PKCE Parameters

Before starting, you need to generate PKCE parameters. You can use online tools or this JavaScript code in Postman's Pre-request Script:

```javascript
// Generate code_verifier (43-128 characters)
const codeVerifier = pm.variables
  .replaceIn("{{$randomAlphaNumeric}}")
  .repeat(43)
  .substring(0, 43);
pm.environment.set("code_verifier", codeVerifier);

// Generate code_challenge (SHA256 hash of code_verifier, base64url encoded)
const crypto = require("crypto-js");
const codeChallenge = crypto
  .SHA256(codeVerifier)
  .toString(crypto.enc.Base64)
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=/g, "");
pm.environment.set("code_challenge", codeChallenge);

console.log("Code Verifier:", codeVerifier);
console.log("Code Challenge:", codeChallenge);
```

### Step 2.2: Authorization Request (Browser Required)

> [!IMPORTANT]
> **Critical Architecture Note**: Due to the custom authentication architecture, you **CANNOT** directly access the authorization server at `http://localhost:12000/oauth2/authorize`. The authorization server requires a valid JWT token in the request, which is injected by the frontend application.

> [!WARNING]
> **You MUST use the frontend proxy URL** instead of the direct authorization server URL. The frontend will:
>
> 1. Receive the OAuth2 parameters
> 2. Check if the user is logged in
> 3. Inject the JWT token into the request
> 4. Redirect to the authorization server with the token

**Correct Authorization URL (via Frontend Proxy):**

```
http://localhost:5173/oauth2/authorize?response_type=code&client_id=YOUR_CLIENT_ID&scope=openid%20read%20write%20profile&redirect_uri=YOUR_REDIRECT_URI&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256
```

**Incorrect (Will Fail with 400 Bad Request):**

```
❌ http://localhost:12000/oauth2/authorize?...
```

**Why This Architecture?**

The authorization server uses a custom `SessionFilter` that extracts user authentication from a JWT token. When you access the authorization endpoint directly:

- No JWT token is present in the request
- The `SessionFilter` cannot authenticate the user
- The server returns a 400 Bad Request error

By going through the frontend (`http://localhost:5173`), the frontend application:

- Checks if you're logged in (has a valid session)
- Retrieves the JWT token from your session/cookies
- Appends the token to the authorization request
- Redirects you to `http://localhost:12000/oauth2/authorize` with the token

**Authorization URL (Use Frontend - Port 5173):**

```
http://localhost:5173/oauth2/authorize?response_type=code&client_id=YOUR_CLIENT_ID&scope=openid%20read%20write%20profile&redirect_uri=YOUR_REDIRECT_URI&code_challenge=YOUR_CODE_CHALLENGE&code_challenge_method=S256
```

**Complete Example:**

```
http://localhost:5173/oauth2/authorize?response_type=code&client_id=testclient1&scope=openid%20read&redirect_uri=http://localhost:6000/callback&code_challenge=uAlCmjyFRMWtZ8L55W8Fec0MjB39ARRfl9_liwQ8RM4&code_challenge_method=S256
```

**Parameters:**

| Parameter               | Value                                | Description                        |
| ----------------------- | ------------------------------------ | ---------------------------------- |
| `response_type`         | `code`                               | Request an authorization code      |
| `client_id`             | `postman-test-client`                | Your client ID                     |
| `scope`                 | `openid read write profile`          | Requested scopes (space-separated) |
| `redirect_uri`          | `https://oauth.pstmn.io/v1/callback` | Must match registered redirect URI |
| `code_challenge`        | Generated value                      | PKCE code challenge                |
| `code_challenge_method` | `S256`                               | SHA256 hashing method              |

**Flow:**

1. **Ensure you're logged in to the frontend first**:
   - Visit `http://localhost:5173/login`
   - Login with your credentials
   - The frontend will store your JWT token in cookies/session

2. **Open the authorization URL** (via frontend proxy at port 5173) in your browser

3. **Frontend processes the request**:
   - Checks if you're authenticated
   - If not authenticated, redirects you to login
   - If authenticated, extracts the JWT token
   - Redirects to `http://localhost:12000/oauth2/authorize` with the token appended

4. **Authorization server processes the request**:
   - Validates the JWT token via `SessionFilter`
   - Authenticates the user from the token
   - Shows the consent page (if enabled for the client)

5. **Approve consent** (if required)

6. **Redirect to callback**:
   - You'll be redirected to your `redirect_uri` with a `code` parameter

**Example Redirect:**

```
https://oauth.pstmn.io/v1/callback?code=eyJhbGciOiJIUzI1NiJ9...&state=xyz
```

> [!TIP]
> Copy the `code` value from the URL - you'll need it for the next step.

### Step 2.3: Exchange Authorization Code for Tokens

Now exchange the authorization code for access and refresh tokens.

#### Request

```http
POST http://localhost:12000/oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>
```

#### Request Body (x-www-form-urlencoded)

| Key             | Value                                |
| --------------- | ------------------------------------ |
| `grant_type`    | `authorization_code`                 |
| `code`          | The authorization code from Step 2.2 |
| `redirect_uri`  | `https://oauth.pstmn.io/v1/callback` |
| `code_verifier` | The code_verifier you generated      |

#### Postman Configuration

1. **Authorization Tab:**
   - Type: `Basic Auth`
   - Username: `postman-test-client`
   - Password: `postman-secret-123`

2. **Body Tab:**
   - Select `x-www-form-urlencoded`
   - Add the parameters above

#### Response

```json
{
  "access_token": "eyJraWQiOiJyc2Eta2V5LWN1cnJlbnQiLCJhbGciOiJSUzI1NiJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
  "scope": "openid read write profile",
  "id_token": "eyJraWQiOiJyc2Eta2V5LWN1cnJlbnQiLCJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

> [!NOTE]
> Save the `access_token` and `refresh_token` for subsequent requests.

---

## 3. Refresh Token Flow

Use the refresh token to obtain a new access token without requiring user login.

### Request

```http
POST http://localhost:12000/oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>
```

### Request Body (x-www-form-urlencoded)

| Key             | Value                            |
| --------------- | -------------------------------- |
| `grant_type`    | `refresh_token`                  |
| `refresh_token` | Your refresh token from Step 2.3 |

### Response

```json
{
  "access_token": "eyJraWQiOiJyc2Eta2V5LWN1cnJlbnQiLCJhbGciOiJSUzI1NiJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
  "scope": "openid read write profile",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

> [!TIP]
> The server issues a new refresh token on each use (non-reusable refresh tokens for better security).

---

## 4. Token Introspection

Validate and inspect an access token.

### Request

```http
POST http://localhost:12000/oauth2/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>
```

### Request Body (x-www-form-urlencoded)

| Key     | Value             |
| ------- | ----------------- |
| `token` | Your access token |

### Response

```json
{
  "active": true,
  "sub": "651a2b3c4d5e6f7a8b9c0d1e",
  "aud": ["postman-test-client"],
  "nbf": 1706950800,
  "scope": "openid read write profile",
  "iss": "http://localhost:12000",
  "exp": 1706952600,
  "iat": 1706950800,
  "jti": "abc123-def456-ghi789",
  "client_id": "postman-test-client",
  "token_type": "Bearer"
}
```

---

## 5. Token Revocation

Revoke an access or refresh token.

### Request

```http
POST http://localhost:12000/oauth2/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>
```

### Request Body (x-www-form-urlencoded)

| Key               | Value                                        |
| ----------------- | -------------------------------------------- |
| `token`           | The token to revoke                          |
| `token_type_hint` | `access_token` or `refresh_token` (optional) |

### Response

```
200 OK
```

> [!NOTE]
> The endpoint returns 200 OK even if the token is already invalid (per OAuth2 spec).

---

## 6. JWKS Endpoint (Public Keys)

Retrieve the public keys used for token signature verification.

### Request

```http
GET http://localhost:12000/oauth2/jwks
```

### Response

```json
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "rsa-key-current",
      "alg": "RS256",
      "n": "nDsKk9Kf2X9AFqyPjy9ci_JEs1ufBws7HxmYtiyxFaQOaxlPPDy_0KozYR3aK5FM..."
    },
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "kid": "rsa-key-old",
      "alg": "RS256",
      "n": "qbcxFzr2oBzwRNU3K--rbqFAQMFxhVihXad4fJk58RKAhxb4VhNxHWaw-Ha_xdQ..."
    }
  ]
}
```

---

## 7. OpenID Connect Discovery

Get the OpenID Connect configuration.

### Request

```http
GET http://localhost:12000/.well-known/openid-configuration
```

### Response

```json
{
  "issuer": "http://localhost:12000",
  "authorization_endpoint": "http://localhost:12000/oauth2/authorize",
  "token_endpoint": "http://localhost:12000/oauth2/token",
  "jwks_uri": "http://localhost:12000/oauth2/jwks",
  "revocation_endpoint": "http://localhost:12000/oauth2/revoke",
  "introspection_endpoint": "http://localhost:12000/oauth2/introspect",
  "userinfo_endpoint": "http://localhost:12000/userinfo",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": [
    "openid",
    "read",
    "write",
    "username",
    "profile",
    "personaldata"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ],
  "code_challenge_methods_supported": ["S256"]
}
```

---

## 8. UserInfo Endpoint

Retrieve user information using an access token.

### Request

```http
GET http://localhost:12000/userinfo
Authorization: Bearer YOUR_ACCESS_TOKEN
```

### Response

```json
{
  "sub": "651a2b3c4d5e6f7a8b9c0d1e",
  "name": "John Doe",
  "email": "john.doe@example.com",
  "email_verified": true,
  "preferred_username": "johndoe"
}
```

> [!NOTE]
> The response varies based on the scopes granted to the access token.

---

## Postman Environment Variables

Create a Postman environment with these variables for easier testing:

| Variable             | Example Value                        |
| -------------------- | ------------------------------------ |
| `base_url`           | `http://localhost:12000`             |
| `client_id`          | `postman-test-client`                |
| `client_secret`      | `postman-secret-123`                 |
| `redirect_uri`       | `https://oauth.pstmn.io/v1/callback` |
| `code_verifier`      | Generated dynamically                |
| `code_challenge`     | Generated dynamically                |
| `authorization_code` | Obtained from browser                |
| `access_token`       | Obtained from token endpoint         |
| `refresh_token`      | Obtained from token endpoint         |

---

## Common Issues and Troubleshooting

### Issue: "invalid_client" Error

**Cause:** Client credentials are incorrect or client doesn't exist in the database.

**Solution:**

- Verify client exists in MongoDB
- Check `client_id` and `client_secret` are correct
- Ensure Basic Auth is properly encoded

### Issue: "invalid_grant" Error

**Cause:** Authorization code is expired, already used, or invalid.

**Solution:**

- Authorization codes expire in 5 minutes
- Each code can only be used once
- Generate a new authorization code and try again

### Issue: "invalid_scope" Error

**Cause:** Requested scope is not allowed for the client.

**Solution:**

- Check client configuration in MongoDB
- Ensure scopes like `write`, `profile`, `personal` are enabled for your client
- Use only supported scopes: `openid`, `read`, `write`, `username`, `profile`, `personal`

### Issue: PKCE Validation Failed

**Cause:** `code_verifier` doesn't match the original `code_challenge`.

**Solution:**

- Ensure you're using the same `code_verifier` that generated the `code_challenge`
- Verify the code_challenge is properly base64url encoded
- Check that `code_challenge_method` is set to `S256`

### Issue: Redirect URI Mismatch

**Cause:** The `redirect_uri` in the token request doesn't match the one used in the authorization request.

**Solution:**

- Use the exact same `redirect_uri` in both requests
- Ensure the URI matches what's registered for the client in the database

### Issue: 400 Bad Request - "Whitelabel Error Page"

**Cause:** You're trying to access the authorization server directly at `http://localhost:12000/oauth2/authorize` without a JWT token.

**Solution:**

- **Always use the frontend URL**: `http://localhost:5173/oauth2/authorize` instead of `http://localhost:12000`
- Ensure you're logged in to the frontend first (`http://localhost:5173/login`)
- The frontend will inject the required JWT token before redirecting to the authorization server
- See the architecture explanation in Step 2.2 above

---

## Testing with Postman's OAuth 2.0 Feature

Postman has built-in OAuth 2.0 support that can automate some of these steps.

### Configuration

1. Go to the **Authorization** tab in your request
2. Select **OAuth 2.0** as the type
3. Click **Get New Access Token**
4. Configure as follows:

| Field                 | Value                                     |
| --------------------- | ----------------------------------------- |
| Token Name            | `Auth Server Token`                       |
| Grant Type            | `Authorization Code (With PKCE)`          |
| Callback URL          | `https://oauth.pstmn.io/v1/callback`      |
| Auth URL              | `http://localhost:12000/oauth2/authorize` |
| Access Token URL      | `http://localhost:12000/oauth2/token`     |
| Client ID             | `postman-test-client`                     |
| Client Secret         | `postman-secret-123`                      |
| Code Challenge Method | `SHA-256`                                 |
| Scope                 | `openid read write profile`               |
| Client Authentication | `Send as Basic Auth header`               |

5. Click **Request Token**
6. A browser window will open for login and consent
7. After approval, Postman will automatically exchange the code for tokens

> [!TIP]
> This method is faster for repeated testing but less educational than manual testing.

---

## Additional Resources

- [TESTING.md](file:///Users/rahulgupta/Desktop/distributedSecurity/Autherization/TESTING.md) - Automated testing guide
- [SecurityConfig.java](file:///Users/rahulgupta/Desktop/distributedSecurity/Autherization/src/main/java/one/org/security/Autherization/infrastructure/config/SecurityConfig.java) - Security configuration
- Server logs: `test.log` in the project root

---

## Quick Reference: All Endpoints

| Endpoint                            | Method | Purpose                                   |
| ----------------------------------- | ------ | ----------------------------------------- |
| `/client/create-client`             | POST   | Register a new OAuth2 client              |
| `/oauth2/authorize`                 | GET    | Start authorization code flow             |
| `/oauth2/token`                     | POST   | Exchange code for tokens / refresh tokens |
| `/oauth2/introspect`                | POST   | Validate and inspect tokens               |
| `/oauth2/revoke`                    | POST   | Revoke access or refresh tokens           |
| `/oauth2/jwks`                      | GET    | Get public signing keys                   |
| `/.well-known/openid-configuration` | GET    | OpenID Connect discovery                  |
| `/userinfo`                         | GET    | Get user information                      |

---

**Happy Testing! 🚀**
