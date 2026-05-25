# Requirements Specification

This document captures the bachelor-project prototype requirements in a form that maps to a type-3 implementation-oriented thesis.

## Functional Requirements

1. The system must provide a browser-accessible demo client.
2. The system must provide a separate local OIDC provider service.
3. The external-provider authentication flow must use authorization code flow with PKCE.
4. The provider must issue an external access token and an ID token.
5. The gateway must expose an endpoint for exchanging the authorization code for provider tokens.
6. The local login flow must require local credentials and valid provider-issued tokens.
7. The auth service must introspect the provider access token before issuing the internal access token.
8. The auth service must validate the provider ID token before issuing the internal access token.
9. The system must issue a short-lived internal JWT access token after successful hybrid authentication.
10. The system must store the internal refresh token in an `HttpOnly` cookie.
11. The system must rotate the internal refresh token on refresh.
12. The system must protect refresh and logout operations with a CSRF token.
13. The system must provide protected API routes secured by the internal JWT.
14. The system must provide an admin-only protected route.
15. The local stack must support HTTPS when a certificate and key are configured.

## Non-Functional Requirements

1. The prototype must remain runnable on a single development machine.
2. The repository must expose reproducible verification scripts and automated tests.
3. The repository must clearly separate gateway, auth, resource, and provider responsibilities.
4. The repository must document mocked or academic-only components explicitly.
5. The prototype must preserve enough realism to support a bachelor-thesis defense and public GitHub publication.

## Acceptance Criteria

1. `npm test` passes.
2. `npm run perf` produces benchmark output.
3. `npm run load` produces concurrent protected-resource load output.
4. The browser demo supports provider authentication, local login, token refresh, and logout.
