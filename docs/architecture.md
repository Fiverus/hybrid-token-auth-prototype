# Architecture Overview

## Purpose

The repository implements an academic hybrid authentication prototype that combines:

1. local username/password validation
2. external OIDC provider authentication
3. authorization code flow with PKCE
4. external access-token introspection
5. internal JWT access tokens
6. refresh-token cookies with CSRF protection

## Running Services

1. Gateway service
   - serves the browser client
   - exposes `/api/*`
   - performs API-gateway-style request validation
   - proxies traffic to the internal services
2. Auth service
   - verifies local credentials
   - introspects external provider access tokens
   - validates provider ID tokens
   - issues internal JWT access tokens and refresh tokens
3. Resource service
   - protects application resources with internal bearer JWT validation
   - demonstrates role-based access control
4. Local OIDC provider
   - exposes authorization, token, introspection, JWKS, and userinfo endpoints
   - issues authorization codes and provider tokens

## Request Flow

```text
Browser client
  -> Gateway /api/config
  -> External OIDC provider /oauth/authorize
  -> Gateway /api/oidc/exchange
  -> Gateway /api/auth/login
  -> Auth service
       -> local credential validation
       -> provider token introspection
       -> provider ID token validation
       -> internal JWT issuance
  -> Resource service /api/protected/*
```

## Persistence

The prototype uses local file-backed JSON stores for:

1. internal refresh-token state
2. provider authorization codes
3. provider access-token introspection state
4. provider signing key material

This keeps the project self-contained while still avoiding restart-sensitive in-memory-only token storage.

## Remaining Deliberate Limits

1. the external provider is local and academic, not a third-party production IdP
2. persistence is file-backed, not database- or Redis-backed
3. the stack supports HTTPS with a configured certificate/key, but production deployment still requires proper infrastructure
