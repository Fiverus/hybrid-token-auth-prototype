import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";

const totalRequests = Number(process.env.LOAD_REQUESTS || 200);
const concurrency = Number(process.env.LOAD_CONCURRENCY || 20);
const storageDir = fs.mkdtempSync(path.join(os.tmpdir(), "hybrid-auth-load-"));

process.env.STORAGE_DIR = storageDir;
process.env.LOGIN_RATE_LIMIT_MAX = process.env.LOGIN_RATE_LIMIT_MAX || "5000";

const { startPrototypeStack } = await import("../src/stack.js");

function sha256Base64Url(value) {
  return crypto.createHash("sha256").update(value).digest("base64url");
}

async function requestJson(url, { method = "GET", headers = {}, body } = {}) {
  const response = await fetch(url, {
    method,
    headers,
    body
  });

  const json = await response.json();
  return { response, json };
}

async function prepareInternalAccessToken(baseUrl, providerBaseUrl) {
  const configResponse = await requestJson(`${baseUrl}/api/config`);
  const oidcConfig = configResponse.json.oidc;
  const codeVerifier = crypto.randomBytes(48).toString("base64url");
  const nonce = crypto.randomBytes(18).toString("base64url");

  const authorizeResponse = await fetch(`${providerBaseUrl}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      client_id: oidcConfig.clientId,
      redirect_uri: oidcConfig.redirectUri,
      scope: oidcConfig.scope,
      state: crypto.randomBytes(18).toString("base64url"),
      nonce,
      code_challenge: sha256Base64Url(codeVerifier),
      code_challenge_method: "S256",
      username: "demo",
      password: "Password123!"
    })
  });

  const redirectUrl = new URL(authorizeResponse.headers.get("location"));
  const exchangeResponse = await requestJson(`${baseUrl}/api/oidc/exchange`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code: redirectUrl.searchParams.get("code"),
      codeVerifier
    })
  });

  const loginResponse = await requestJson(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Client-Id": oidcConfig.clientId
    },
    body: JSON.stringify({
      username: "demo",
      password: "Password123!",
      externalAccessToken: exchangeResponse.json.access_token,
      idToken: exchangeResponse.json.id_token,
      oidcNonce: nonce
    })
  });

  if (!loginResponse.response.ok) {
    throw new Error(`Failed to prepare internal access token: ${JSON.stringify(loginResponse.json)}`);
  }

  return loginResponse.json.accessToken;
}

const stack = await startPrototypeStack({
  gatewayPort: 0,
  authPort: 0,
  resourcePort: 0,
  providerPort: 0
});

try {
  const accessToken = await prepareInternalAccessToken(stack.gatewayBaseUrl, stack.providerBaseUrl);
  const durations = [];
  let completed = 0;

  async function worker() {
    while (true) {
      completed += 1;

      if (completed > totalRequests) {
        return;
      }

      const startedAt = performance.now();
      const response = await fetch(`${stack.gatewayBaseUrl}/api/protected/profile`, {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      });
      await response.json();

      if (!response.ok) {
        throw new Error(`Load test request failed with status ${response.status}.`);
      }

      durations.push(performance.now() - startedAt);
    }
  }

  await Promise.all(Array.from({ length: concurrency }, () => worker()));

  const totalDurationMs = durations.reduce((sum, value) => sum + value, 0);

  console.table([
    {
      scenario: "protected_profile_concurrent",
      totalRequests,
      concurrency,
      minMs: Math.min(...durations).toFixed(2),
      avgMs: (totalDurationMs / durations.length).toFixed(2),
      maxMs: Math.max(...durations).toFixed(2),
      approxRequestsPerSecond: (totalRequests / (totalDurationMs / 1000)).toFixed(2)
    }
  ]);
} finally {
  await stack.close();
  fs.rmSync(storageDir, { recursive: true, force: true });
}
