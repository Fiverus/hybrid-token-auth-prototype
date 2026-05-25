# Hybrid Token-Based Authentication Prototype

Academic prototype for a bachelor thesis on secure token-based authentication in web applications.

## What This Repository Demonstrates

This project combines several mechanisms in one runnable local stand:

1. separate gateway, auth, resource, and provider services
2. local username/password validation
3. external OIDC provider login
4. authorization code flow with PKCE
5. provider access-token introspection
6. provider ID-token validation
7. internal JWT access tokens
8. refresh-token cookies with rotation
9. CSRF protection for cookie-based refresh/logout actions
10. protected API routes and role-based access control

## Service Topology

```text
Browser client
  -> Gateway service (:3000)
  -> Auth service (:3001)
  -> Resource service (:3002)
  -> Local OIDC provider (:4000)
```

The exact ports are configurable through `.env`.

## Quick Start

```bash
npm install
copy .env.example .env
npm run dev
```

Open:

```text
http://localhost:3000
```

Optional local HTTPS:

```text
Set ENABLE_HTTPS=true and provide either:
1. TLS_KEY_PATH + TLS_CERT_PATH, or
2. TLS_PFX_PATH (+ TLS_PFX_PASSPHRASE when needed)

Use a locally trusted certificate if you want the full browser/OIDC flow over HTTPS.
```

## Demo Credentials

Regular user:

```text
Local username: demo
Local password: Password123!
Provider username: demo
Provider password: Password123!
```

Admin user:

```text
Local username: admin
Local password: AdminPass123!
Provider username: admin
Provider password: AdminPass123!
```

## Browser Flow

1. Click `Authenticate with external provider`
2. Complete the provider popup login
3. Return to the main page and confirm that `client_id` and external token fields were populated
4. Click `Login`
5. Use `Get protected profile`, `Get admin resource`, `Refresh access token`, and `Logout`

## API Surface

Gateway:

1. `GET /health`
2. `GET /api/config`
3. `POST /api/oidc/exchange`
4. `POST /api/auth/login`
5. `POST /api/auth/refresh`
6. `POST /api/auth/logout`
7. `GET /api/protected/profile`
8. `GET /api/protected/admin`

OIDC provider:

1. `GET /.well-known/openid-configuration`
2. `GET /oauth/authorize`
3. `POST /oauth/authorize`
4. `POST /oauth/token`
5. `POST /oauth/introspect`
6. `GET /oauth/jwks`
7. `GET /oauth/userinfo`

## Verification

Automated tests:

```bash
npm test
```

Sequential benchmark:

```bash
npm run perf
```

The benchmark runs `500` local iterations by default and prints a summary table for login,
protected-resource access, refresh, and logout.

Concurrent load smoke test:

```bash
npm run load
```

Additional artifacts:

1. [docs/architecture.md](./docs/architecture.md)
2. [docs/requirements.md](./docs/requirements.md)
3. [docs/test-plan.md](./docs/test-plan.md)
4. [docs/postman_collection.json](./docs/postman_collection.json)

## Security Choices

1. provider auth uses authorization code flow with PKCE
2. provider issues an ID token signed with RSA
3. auth service validates both provider access-token introspection and provider ID-token claims
4. internal access tokens are short-lived JWTs
5. internal refresh tokens are rotated and revocable
6. refresh/logout require a CSRF token
7. the local stack can run over HTTPS when a certificate and key are configured
8. local passwords are stored as bcrypt hashes

## Important Limitations

This is still an academic prototype, not a production identity platform.

Deliberate limitations:

1. the OIDC provider is local and self-contained
2. token persistence is file-backed JSON, not Redis or a database
3. HTTPS support depends on a locally provided certificate/key and is still not a production deployment setup
4. there is no real third-party identity provider integration
5. the load tests are local-machine measurements
