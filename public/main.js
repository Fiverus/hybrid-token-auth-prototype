let accessToken = "";
let csrfToken = "";
let runtimeConfig = null;
let pendingOidcFlow = null;
let oidcSession = null;
let lastHandledOidcCallbackKey = "";

const usernameInput = document.querySelector("#username");
const passwordInput = document.querySelector("#password");
const clientIdInput = document.querySelector("#clientId");
const externalAccessTokenInput = document.querySelector("#externalAccessToken");
const idTokenInput = document.querySelector("#idToken");
const oidcNonceInput = document.querySelector("#oidcNonce");
const tokenOutput = document.querySelector("#tokenOutput");
const oidcOutput = document.querySelector("#oidcOutput");
const responseOutput = document.querySelector("#responseOutput");
const providerStatus = document.querySelector("#providerStatus");

function showResponse(data) {
  responseOutput.textContent = JSON.stringify(data, null, 2);
}

function showToken(token) {
  tokenOutput.textContent = token || "No access token yet.";
}

function syncExternalInputs(session) {
  if (runtimeConfig?.oidc?.clientId) {
    clientIdInput.value = runtimeConfig.oidc.clientId;
  }

  if (!session) {
    externalAccessTokenInput.value = "";
    idTokenInput.value = "";
    oidcNonceInput.value = "";
    return;
  }

  externalAccessTokenInput.value = session.accessToken;
  idTokenInput.value = session.idToken;
  oidcNonceInput.value = session.nonce;
}

function showOidcSession(session) {
  if (!session) {
    oidcOutput.textContent = "No external tokens yet.";
    providerStatus.textContent = "No external provider session yet.";
    syncExternalInputs(null);
    return;
  }

  oidcOutput.textContent = JSON.stringify(
    {
      accessToken: session.accessToken,
      scope: session.scope,
      nonce: session.nonce,
      claims: session.claims
    },
    null,
    2
  );
  providerStatus.textContent = `External provider session is ready for ${session.claims.preferred_username}.`;
  syncExternalInputs(session);
}

async function requestJson(url, options) {
  try {
    const response = await fetch(url, options);
    const data = await response.json();
    return { response, data };
  } catch (error) {
    showResponse({
      message: "Request failed.",
      error: error.message
    });

    return null;
  }
}

function base64UrlEncode(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

async function sha256Base64Url(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(digest));
}

function parseJwtPayload(token) {
  const [, payloadSegment] = token.split(".");

  if (!payloadSegment) {
    return {};
  }

  const base64 = payloadSegment.replace(/-/g, "+").replace(/_/g, "/");
  const normalized = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return JSON.parse(atob(normalized));
}

async function loadConfig() {
  const result = await requestJson("/api/config", {
    method: "GET",
    credentials: "include"
  });

  if (!result || !result.response.ok) {
    return;
  }

  runtimeConfig = result.data;
  clientIdInput.value = runtimeConfig.oidc.clientId;
  showResponse({
    message: "Runtime configuration loaded.",
    oidc: runtimeConfig.oidc
  });
}

async function startExternalProviderAuth() {
  if (!runtimeConfig) {
    await loadConfig();
  }

  if (!runtimeConfig) {
    return;
  }

  const codeVerifier = randomToken(48);
  const codeChallenge = await sha256Base64Url(codeVerifier);
  const state = randomToken(18);
  const nonce = randomToken(18);

  pendingOidcFlow = {
    codeVerifier,
    state,
    nonce
  };

  const authorizeUrl = new URL(runtimeConfig.oidc.authorizeUrl);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", runtimeConfig.oidc.clientId);
  authorizeUrl.searchParams.set("redirect_uri", runtimeConfig.oidc.redirectUri);
  authorizeUrl.searchParams.set("scope", runtimeConfig.oidc.scope);
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("nonce", nonce);
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  window.open(authorizeUrl.toString(), "oidc-provider", "width=560,height=720");
}

async function handleOidcCallbackPayload(payload) {
  if (!runtimeConfig) {
    await loadConfig();
  }

  if (!runtimeConfig || !payload || payload.type !== "oidc-callback") {
    return;
  }

  const callbackKey = `${payload.code || ""}|${payload.state || ""}|${payload.error || ""}`;

  if (callbackKey === lastHandledOidcCallbackKey) {
    return;
  }

  lastHandledOidcCallbackKey = callbackKey;

  if (!pendingOidcFlow) {
    showResponse({
      message: "OIDC callback was received without a pending transaction."
    });
    return;
  }

  if (payload.error) {
    showResponse({
      message: "External provider returned an error.",
      error: payload.error
    });
    return;
  }

  if (payload.state !== pendingOidcFlow.state) {
    showResponse({
      message: "OIDC state validation failed."
    });
    return;
  }

  const exchangeResult = await requestJson("/api/oidc/exchange", {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code: payload.code,
      codeVerifier: pendingOidcFlow.codeVerifier
    })
  });

  if (!exchangeResult) {
    return;
  }

  const { response, data } = exchangeResult;

  if (!response.ok) {
    showResponse(data);
    return;
  }

  oidcSession = {
    accessToken: data.access_token,
    idToken: data.id_token,
    scope: data.scope,
    nonce: pendingOidcFlow.nonce,
    claims: parseJwtPayload(data.id_token)
  };
  pendingOidcFlow = null;
  showOidcSession(oidcSession);
  showResponse({
    message: "External provider authorization completed successfully.",
    scope: data.scope,
    claims: oidcSession.claims
  });
}

function consumeStoredOidcCallback() {
  const rawPayload = localStorage.getItem("oidc-callback");

  if (!rawPayload) {
    return;
  }

  try {
    const payload = JSON.parse(rawPayload);
    localStorage.removeItem("oidc-callback");
    void handleOidcCallbackPayload(payload);
  } catch (error) {
    localStorage.removeItem("oidc-callback");
  }
}

window.addEventListener("message", async (event) => {
  if (!runtimeConfig) {
    await loadConfig();
  }

  if (!runtimeConfig || event.origin !== runtimeConfig.gatewayBaseUrl) {
    return;
  }

  void handleOidcCallbackPayload(event.data);
});

window.addEventListener("storage", (event) => {
  if (event.key !== "oidc-callback" || !event.newValue) {
    return;
  }

  consumeStoredOidcCallback();
});

window.addEventListener("focus", () => {
  consumeStoredOidcCallback();
});

async function login() {
  if (!runtimeConfig) {
    await loadConfig();
  }

  const clientId = clientIdInput.value.trim() || runtimeConfig?.oidc?.clientId || "";
  const externalAccessToken = externalAccessTokenInput.value.trim();
  const idToken = idTokenInput.value.trim();
  const oidcNonce = oidcNonceInput.value.trim();

  if (!clientId || !externalAccessToken || !idToken || !oidcNonce) {
    showResponse({
      message: "clientId, externalAccessToken, idToken and oidcNonce are required before local login."
    });
    return;
  }

  const result = await requestJson("/api/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Client-Id": clientId
    },
    credentials: "include",
    body: JSON.stringify({
      username: usernameInput.value,
      password: passwordInput.value,
      externalAccessToken,
      idToken,
      oidcNonce
    })
  });

  if (!result) {
    return;
  }

  const { response, data } = result;

  if (response.ok) {
    accessToken = data.accessToken;
    csrfToken = data.csrfToken;
    showToken(accessToken);
  }

  showResponse(data);
}

async function getProfile() {
  const result = await requestJson("/api/protected/profile", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`
    },
    credentials: "include"
  });

  if (result) {
    showResponse(result.data);
  }
}

async function getAdminResource() {
  const result = await requestJson("/api/protected/admin", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`
    },
    credentials: "include"
  });

  if (result) {
    showResponse(result.data);
  }
}

async function refreshAccessToken() {
  const result = await requestJson("/api/auth/refresh", {
    method: "POST",
    credentials: "include",
    headers: {
      "X-CSRF-Token": csrfToken
    }
  });

  if (!result) {
    return;
  }

  const { response, data } = result;

  if (response.ok) {
    accessToken = data.accessToken;
    showToken(accessToken);
  }

  showResponse(data);
}

async function logout() {
  const result = await requestJson("/api/auth/logout", {
    method: "POST",
    credentials: "include",
    headers: {
      "X-CSRF-Token": csrfToken
    }
  });

  if (!result) {
    return;
  }

  accessToken = "";
  csrfToken = "";
  oidcSession = null;
  showToken(accessToken);
  showOidcSession(oidcSession);
  showResponse(result.data);
}

document.querySelector("#providerButton").addEventListener("click", startExternalProviderAuth);
document.querySelector("#loginButton").addEventListener("click", login);
document.querySelector("#profileButton").addEventListener("click", getProfile);
document.querySelector("#adminButton").addEventListener("click", getAdminResource);
document.querySelector("#refreshButton").addEventListener("click", refreshAccessToken);
document.querySelector("#logoutButton").addEventListener("click", logout);

loadConfig();
consumeStoredOidcCallback();
