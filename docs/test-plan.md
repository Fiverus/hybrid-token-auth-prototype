# Test Plan

## Automated Functional Coverage

The automated test suite verifies:

1. gateway health aggregation
2. runtime OIDC configuration exposure
3. authorization code + PKCE exchange against the provider
4. successful hybrid local login
5. rejection of malformed local login requests
6. protected-route access with the internal JWT
7. admin-route role restrictions
8. CSRF enforcement on refresh
9. refresh-token rotation
10. refresh-token revocation on logout

Run:

```bash
npm test
```

## Lightweight Sequential Performance Check

Run:

```bash
npm run perf
```

This script measures:

1. local hybrid login latency
2. protected resource latency
3. refresh latency
4. logout latency

Methodology notes:

1. the script executes `500` iterations by default
2. each iteration measures end-to-end request time on the local machine
3. summary values include min, average, and max latency per scenario
4. results can be written to a JSON artifact with `PERF_OUTPUT_PATH`

The measurements are local-machine measurements intended for academic comparison, not production SLA claims.

## Concurrent Load Smoke Test

Run:

```bash
npm run load
```

The load script performs concurrent protected-resource requests using a previously obtained internal access token and prints a small summary table.

## Manual Verification

Manual browser verification should confirm:

1. provider popup login
2. local login after provider authorization
3. access to `/api/protected/profile`
4. access denial on `/api/protected/admin` for a non-admin user
5. access success on `/api/protected/admin` for the admin user
