import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { after, before } from "node:test";
import assert from "node:assert/strict";

const storageDir = fs.mkdtempSync(path.join(os.tmpdir(), "hybrid-auth-prototype-"));

process.env.STORAGE_DIR = storageDir;
process.env.LOGIN_RATE_LIMIT_MAX = "1000";

let stack;
let baseUrl = "";
let providerBaseUrl = "";
let oidcConfig;

function buildCookieHeader(cookies) {
  return cookies.map((cookie) => cookie.split(";")[0]).join("; ");
}

function getSetCookies(response) {
  return response.headers.getSetCookie();
}

function sha256Base64Url(value) {
  return crypto.createHash("sha256").update(value).digest("base64url");
}

async function requestJson(url, { method = "GET", headers = {}, body, cookies = [] } = {}) {
  const requestHeaders = {
    ...headers
  };

  if (cookies.length > 0) {
    requestHeaders.Cookie = buildCookieHeader(cookies);
  }

  const response = await fetch(url, {
    method,
    headers: requestHeaders,
    body
  });

  const json = await response.json();
  return { response, json, setCookies: getSetCookies(response) };
}

async function getConfig() {
  const result = await requestJson(`${baseUrl}/api/config`);
  oidcConfig = result.json.oidc;
  return result;
}

async function completeExternalAuthorization({
  username = "demo",
  password = "Password123!"
} = {}) {
  if (!oidcConfig) {
    await getConfig();
  }

  const codeVerifier = crypto.randomBytes(48).toString("base64url");
  const state = crypto.randomBytes(18).toString("base64url");
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
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      username,
      password
    })
  });

  assert.equal(authorizeResponse.status, 302);
  const redirectUrl = new URL(authorizeResponse.headers.get("location"));
  const code = redirectUrl.searchParams.get("code");

  const exchangeResult = await requestJson(`${baseUrl}/api/oidc/exchange`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code,
      codeVerifier
    })
  });

  assert.equal(exchangeResult.response.status, 200);

  return {
    nonce,
    accessToken: exchangeResult.json.access_token,
    idToken: exchangeResult.json.id_token,
    scope: exchangeResult.json.scope
  };
}

async function login({
  username = "demo",
  password = "Password123!",
  externalSession
} = {}) {
  return requestJson(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Client-Id": oidcConfig.clientId
    },
    body: JSON.stringify({
      username,
      password,
      externalAccessToken: externalSession?.accessToken,
      idToken: externalSession?.idToken,
      oidcNonce: externalSession?.nonce
    })
  });
}

before(async () => {
  const { startPrototypeStack } = await import("../src/stack.js");
  stack = await startPrototypeStack({
    gatewayPort: 0,
    authPort: 0,
    resourcePort: 0,
    providerPort: 0
  });

  baseUrl = stack.gatewayBaseUrl;
  providerBaseUrl = stack.providerBaseUrl;
  await getConfig();
});

after(async () => {
  if (stack) {
    await stack.close();
  }

  fs.rmSync(storageDir, { recursive: true, force: true });
});

test("gateway health endpoint reports all services", async () => {
  const { response, json } = await requestJson(`${baseUrl}/health`);

  assert.equal(response.status, 200);
  assert.equal(json.status, "ok");
  assert.deepEqual(json.services, {
    gateway: "ok",
    auth: "ok",
    resource: "ok",
    provider: "ok"
  });
});

test("config endpoint exposes OIDC browser configuration", async () => {
  const { response, json } = await getConfig();

  assert.equal(response.status, 200);
  assert.equal(json.oidc.clientId, "bachelor-client");
  assert.match(json.oidc.authorizeUrl, /oauth\/authorize$/);
  assert.match(json.oidc.redirectUri, /\/oidc\/callback$/);
});

test("external OIDC authorization code flow returns access and ID tokens", async () => {
  const externalSession = await completeExternalAuthorization();

  assert.ok(externalSession.accessToken);
  assert.ok(externalSession.idToken);
  assert.equal(externalSession.scope, "openid profile api.read");
});

test("local login succeeds after external provider authentication", async () => {
  const externalSession = await completeExternalAuthorization();
  const { response, json, setCookies } = await login({ externalSession });

  assert.equal(response.status, 200);
  assert.ok(json.accessToken);
  assert.ok(json.csrfToken);
  assert.equal(json.externalIdentity.preferredUsername, "demo");
  assert.ok(setCookies.some((cookie) => cookie.startsWith("refreshToken=")));
  assert.ok(setCookies.some((cookie) => cookie.startsWith("csrfToken=")));
});

test("local login rejects missing external provider tokens", async () => {
  const { response, json } = await login({ externalSession: null });

  assert.equal(response.status, 400);
  assert.match(json.message, /externalAccessToken/i);
});

test("protected profile accepts internal JWT token", async () => {
  const externalSession = await completeExternalAuthorization();
  const loginResult = await login({ externalSession });
  const { response, json } = await requestJson(`${baseUrl}/api/protected/profile`, {
    headers: {
      Authorization: `Bearer ${loginResult.json.accessToken}`
    }
  });

  assert.equal(response.status, 200);
  assert.equal(json.user.username, "demo");
});

test("admin route works for admin user and blocks regular user", async () => {
  const demoExternal = await completeExternalAuthorization();
  const demoLogin = await login({ externalSession: demoExternal });
  const demoAdminResponse = await requestJson(`${baseUrl}/api/protected/admin`, {
    headers: {
      Authorization: `Bearer ${demoLogin.json.accessToken}`
    }
  });

  assert.equal(demoAdminResponse.response.status, 403);

  const adminExternal = await completeExternalAuthorization({
    username: "admin",
    password: "AdminPass123!"
  });
  const adminLogin = await login({
    username: "admin",
    password: "AdminPass123!",
    externalSession: adminExternal
  });
  const adminResponse = await requestJson(`${baseUrl}/api/protected/admin`, {
    headers: {
      Authorization: `Bearer ${adminLogin.json.accessToken}`
    }
  });

  assert.equal(adminResponse.response.status, 200);
});

test("refresh requires CSRF token and rotates refresh token", async () => {
  const externalSession = await completeExternalAuthorization();
  const loginResult = await login({ externalSession });
  const refreshCookie = loginResult.setCookies.find((cookie) => cookie.startsWith("refreshToken="));
  const csrfCookie = loginResult.setCookies.find((cookie) => cookie.startsWith("csrfToken="));

  assert.ok(refreshCookie);
  assert.ok(csrfCookie);

  const missingCsrfRefresh = await requestJson(`${baseUrl}/api/auth/refresh`, {
    method: "POST",
    cookies: [refreshCookie, csrfCookie]
  });

  assert.equal(missingCsrfRefresh.response.status, 403);

  const refreshResult = await requestJson(`${baseUrl}/api/auth/refresh`, {
    method: "POST",
    headers: {
      "X-CSRF-Token": loginResult.json.csrfToken
    },
    cookies: [refreshCookie, csrfCookie]
  });

  assert.equal(refreshResult.response.status, 200);
  assert.equal(refreshResult.json.refreshTokenRotated, true);

  const nextRefreshCookie = refreshResult.setCookies.find((cookie) =>
    cookie.startsWith("refreshToken=")
  );

  assert.ok(nextRefreshCookie);
  assert.notEqual(nextRefreshCookie.split(";")[0], refreshCookie.split(";")[0]);
});

test("logout revokes refresh token", async () => {
  const externalSession = await completeExternalAuthorization();
  const loginResult = await login({ externalSession });
  const refreshCookie = loginResult.setCookies.find((cookie) => cookie.startsWith("refreshToken="));
  const csrfCookie = loginResult.setCookies.find((cookie) => cookie.startsWith("csrfToken="));

  const logoutResult = await requestJson(`${baseUrl}/api/auth/logout`, {
    method: "POST",
    headers: {
      "X-CSRF-Token": loginResult.json.csrfToken
    },
    cookies: [refreshCookie, csrfCookie]
  });

  assert.equal(logoutResult.response.status, 200);

  const refreshAfterLogout = await requestJson(`${baseUrl}/api/auth/refresh`, {
    method: "POST",
    headers: {
      "X-CSRF-Token": loginResult.json.csrfToken
    },
    cookies: [refreshCookie, csrfCookie]
  });

  assert.equal(refreshAfterLogout.response.status, 401);
});
