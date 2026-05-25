import { performance } from "node:perf_hooks";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const iterations = Number(process.env.PERF_ITERATIONS || 500);
const outputPath = process.env.PERF_OUTPUT_PATH
  ? path.resolve(process.cwd(), process.env.PERF_OUTPUT_PATH)
  : "";
const storageDir = fs.mkdtempSync(path.join(os.tmpdir(), "hybrid-auth-perf-"));

process.env.STORAGE_DIR = storageDir;
process.env.LOGIN_RATE_LIMIT_MAX = process.env.LOGIN_RATE_LIMIT_MAX || String(Math.max(iterations + 10, 100));

const { startPrototypeStack } = await import("../src/stack.js");

function average(values) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function summarize(name, values) {
  return {
    scenario: name,
    iterations: values.length,
    minMs: values.length ? values.reduce((min, value) => Math.min(min, value), values[0]).toFixed(2) : "0.00",
    avgMs: values.length ? average(values).toFixed(2) : "0.00",
    maxMs: values.length ? values.reduce((max, value) => Math.max(max, value), values[0]).toFixed(2) : "0.00"
  };
}

function getRefreshCookie(response) {
  return response.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith("refreshToken="))
    ?.split(";")[0];
}

function getCsrfCookie(response) {
  return response.headers
    .getSetCookie()
    .find((cookie) => cookie.startsWith("csrfToken="))
    ?.split(";")[0];
}

function sha256Base64Url(value) {
  return crypto.createHash("sha256").update(value).digest("base64url");
}

async function requestJson(url, { method = "GET", headers = {}, body, cookies = [] } = {}) {
  const requestHeaders = {
    ...headers
  };

  if (cookies.length > 0) {
    requestHeaders.Cookie = cookies.join("; ");
  }

  const response = await fetch(url, {
    method,
    headers: requestHeaders,
    body
  });

  const json = await response.json();
  return { response, json };
}

const stack = await startPrototypeStack({
  gatewayPort: 0,
  authPort: 0,
  resourcePort: 0,
  providerPort: 0
});

const baseUrl = stack.gatewayBaseUrl;
const providerBaseUrl = stack.providerBaseUrl;

try {
  const configResponse = await requestJson(`${baseUrl}/api/config`);
  const oidcConfig = configResponse.json.oidc;
  const codeVerifier = crypto.randomBytes(48).toString("base64url");
  const nonce = crypto.randomBytes(18).toString("base64url");
  const codeChallenge = sha256Base64Url(codeVerifier);

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
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      username: "demo",
      password: "Password123!"
    })
  });

  const redirectUrl = new URL(authorizeResponse.headers.get("location"));
  const code = redirectUrl.searchParams.get("code");
  const exchangeResponse = await requestJson(`${baseUrl}/api/oidc/exchange`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code,
      codeVerifier
    })
  });
  const externalSession = {
    accessToken: exchangeResponse.json.access_token,
    idToken: exchangeResponse.json.id_token,
    nonce
  };

  const loginDurations = [];
  const profileDurations = [];
  const refreshDurations = [];
  const logoutDurations = [];

  for (let iteration = 0; iteration < iterations; iteration += 1) {
    const loginStartedAt = performance.now();
    const loginResponse = await fetch(`${baseUrl}/api/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Client-Id": oidcConfig.clientId
      },
      body: JSON.stringify({
        username: "demo",
        password: "Password123!",
        externalAccessToken: externalSession.accessToken,
        idToken: externalSession.idToken,
        oidcNonce: externalSession.nonce
      })
    });
    const loginDuration = performance.now() - loginStartedAt;
    const loginJson = await loginResponse.json();

    if (!loginResponse.ok) {
      throw new Error(`Login benchmark failed: ${JSON.stringify(loginJson)}`);
    }

    const refreshCookie = getRefreshCookie(loginResponse);
    const csrfCookie = getCsrfCookie(loginResponse);

    if (!refreshCookie || !csrfCookie || !loginJson.csrfToken) {
      throw new Error("Refresh token or CSRF token was not returned during benchmark.");
    }

    loginDurations.push(loginDuration);

    const profileStartedAt = performance.now();
    const profileResponse = await fetch(`${baseUrl}/api/protected/profile`, {
      headers: {
        Authorization: `Bearer ${loginJson.accessToken}`
      }
    });
    const profileDuration = performance.now() - profileStartedAt;
    await profileResponse.json();

    if (!profileResponse.ok) {
      throw new Error("Protected profile benchmark failed.");
    }

    profileDurations.push(profileDuration);

    const refreshStartedAt = performance.now();
    const refreshResponse = await fetch(`${baseUrl}/api/auth/refresh`, {
      method: "POST",
      headers: {
        Cookie: `${refreshCookie}; ${csrfCookie}`,
        "X-CSRF-Token": loginJson.csrfToken
      }
    });
    const refreshDuration = performance.now() - refreshStartedAt;
    await refreshResponse.json();

    if (!refreshResponse.ok) {
      throw new Error("Refresh benchmark failed.");
    }

    refreshDurations.push(refreshDuration);

    const logoutStartedAt = performance.now();
    const logoutResponse = await fetch(`${baseUrl}/api/auth/logout`, {
      method: "POST",
      headers: {
        Cookie: `${refreshCookie}; ${csrfCookie}`,
        "X-CSRF-Token": loginJson.csrfToken
      }
    });
    const logoutDuration = performance.now() - logoutStartedAt;
    await logoutResponse.json();

    if (!logoutResponse.ok) {
      throw new Error("Logout benchmark failed.");
    }

    logoutDurations.push(logoutDuration);
  }

  const summary = [
    summarize("login", loginDurations),
    summarize("protected_profile", profileDurations),
    summarize("refresh", refreshDurations),
    summarize("logout", logoutDurations)
  ];

  console.table(summary);

  if (outputPath) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(
      outputPath,
      JSON.stringify(
        {
          generatedAt: new Date().toISOString(),
          iterations,
          summary
        },
        null,
        2
      )
    );
  }
} finally {
  await stack.close();
  fs.rmSync(storageDir, { recursive: true, force: true });
}
