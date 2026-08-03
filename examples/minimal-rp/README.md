# Minimal OIDC Relying Party

A single-file Python/Flask application that demonstrates the **Authorization Code flow with PKCE** against an Aegaeon server.

## What it does

1. **OIDC Discovery** — fetches `/.well-known/openid-configuration` from the issuer
2. **Dynamic Client Registration** (RFC 7591) — registers itself via `POST /register`
3. **Authorization with PKCE S256** — redirects the user to `/authorize` with a code challenge
4. **Token exchange** — exchanges the authorization code for tokens at `/token`
5. **ID token display** — decodes and displays the ID token claims

## Prerequisites

- Python 3.10+
- A running DB-backed Aegaeon server (default issuer: `http://localhost:8080`) with an active
  management Environment, OIDC enabled in that Environment policy, and an ACTIVE
  `OIDC_ID_TOKEN_SIGNING` runtime key.

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Start Aegaeon separately using the supported PostgreSQL-backed runtime.
# From the repository root:
#   nix run .#dev-services-up
#   export DATABASE_URL='postgres://aegaeon:aegaeon@localhost:5432/aegaeon?sslmode=disable'
#   atlas migrate apply --env local
#   # Create/activate the management Environment and OIDC runtime key.
#   AEGAEON_RUNTIME_ISSUER_HOST=127.0.0.1:8080 AEGAEON_DATABASE_URL="$DATABASE_URL" nix run .#dev-server

# Run the RP
python app.py
```

Open <http://localhost:5000> and click **Login with Aegaeon**.

The legacy `AEGAEON_OIDC_*` startup-environment server shortcut is removed from supported runtime;
debug/test fixtures seed equivalent rows directly into PostgreSQL. For the supported runtime
checklist, see
`docs/operations/runtime-configuration.md`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `AEGAEON_ISSUER` | `http://localhost:8080` | Aegaeon issuer URL |
| `RP_PORT` | `5000` | Port for the Flask RP |
| `RP_REDIRECT_URI` | `http://localhost:5000/callback` | OAuth redirect URI |
| `FLASK_SECRET` | *(random)* | Flask session signing key |

## Using with Nix

From the repository root:

```bash
nix develop
cd examples/minimal-rp
pip install -r requirements.txt
python app.py
```

## Security Notes

This is a **demonstration application** and intentionally cuts corners for simplicity:

- **ID token signature verification is skipped.** Production RPs **MUST** verify the signature against the provider's JWKS endpoint. See [OIDC Core ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).
- **Nonce replay protection** is implemented (nonce sent in auth request, validated in callback).
- **Access tokens are not stored** in the session cookie. Production RPs should use server-side or encrypted storage.
- The RP uses `client_secret_post` authentication at the token endpoint.
- Aegaeon's `/authorize` endpoint auto-creates demo sessions, so no separate user login UI is needed for testing.
