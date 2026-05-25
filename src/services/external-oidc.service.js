import jwt from "jsonwebtoken";

const publicKeyCache = new Map();

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const data = await response.json();

  if (!response.ok) {
    const error = new Error(data.message || `Request failed: ${response.status}`);
    error.statusCode = response.status;
    throw error;
  }

  return data;
}

export async function exchangeAuthorizationCode({
  providerBaseUrl,
  clientId,
  code,
  codeVerifier,
  redirectUri
}) {
  return fetchJson(`${providerBaseUrl}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri
    })
  });
}

export async function introspectExternalAccessToken({ providerBaseUrl, token }) {
  return fetchJson(`${providerBaseUrl}/oauth/introspect`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: new URLSearchParams({
      token
    })
  });
}

async function getProviderPublicKey(providerBaseUrl) {
  if (publicKeyCache.has(providerBaseUrl)) {
    return publicKeyCache.get(providerBaseUrl);
  }

  const response = await fetch(`${providerBaseUrl}/oauth/public-key`);

  if (!response.ok) {
    throw new Error("Unable to fetch provider public key.");
  }

  const publicKeyPem = await response.text();
  publicKeyCache.set(providerBaseUrl, publicKeyPem);
  return publicKeyPem;
}

export async function validateExternalIdToken({
  providerBaseUrl,
  idToken,
  expectedAudience,
  expectedIssuer,
  expectedNonce
}) {
  const publicKeyPem = await getProviderPublicKey(providerBaseUrl);
  const payload = jwt.verify(idToken, publicKeyPem, {
    algorithms: ["RS256"],
    audience: expectedAudience,
    issuer: expectedIssuer
  });

  if (expectedNonce && payload.nonce !== expectedNonce) {
    const error = new Error("ID token nonce validation failed.");
    error.statusCode = 401;
    throw error;
  }

  return payload;
}
