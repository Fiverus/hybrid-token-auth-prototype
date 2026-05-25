import crypto from "node:crypto";
import path from "node:path";
import { env } from "../config/env.js";
import { expiresAtFromDuration } from "../utils/duration.js";
import { readJsonFile, writeJsonFile } from "../utils/fileStore.js";
import { randomToken } from "../utils/crypto.js";

const providerStorePath = path.join(env.storageDir, "oidc-provider.json");
const defaultStore = {
  authorizationCodes: {},
  accessTokens: {},
  keyMaterial: null
};

function readProviderStore() {
  return readJsonFile(providerStorePath, defaultStore);
}

function writeProviderStore(store) {
  writeJsonFile(providerStorePath, store);
}

export function getOrCreateProviderKeyMaterial() {
  const store = readProviderStore();

  if (store.keyMaterial) {
    return store.keyMaterial;
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048
  });

  const kid = randomToken(12);
  const keyMaterial = {
    kid,
    privateKeyPem: privateKey.export({ type: "pkcs1", format: "pem" }).toString(),
    publicKeyPem: publicKey.export({ type: "pkcs1", format: "pem" }).toString(),
    publicJwk: {
      ...publicKey.export({ format: "jwk" }),
      use: "sig",
      alg: "RS256",
      kid
    }
  };

  store.keyMaterial = keyMaterial;
  writeProviderStore(store);
  return keyMaterial;
}

export function createAuthorizationCode({
  clientId,
  redirectUri,
  scope,
  codeChallenge,
  codeChallengeMethod,
  nonce,
  state,
  user
}) {
  const store = readProviderStore();
  const code = randomToken(24);

  store.authorizationCodes[code] = {
    clientId,
    redirectUri,
    scope,
    codeChallenge,
    codeChallengeMethod,
    nonce,
    state,
    sub: user.sub,
    username: user.username,
    fullName: user.fullName,
    expiresAt: expiresAtFromDuration("5m", 5 * 60 * 1000)
  };

  writeProviderStore(store);
  return code;
}

export function consumeAuthorizationCode(code) {
  const store = readProviderStore();
  const record = store.authorizationCodes[code];

  if (!record) {
    return null;
  }

  delete store.authorizationCodes[code];
  writeProviderStore(store);
  return record;
}

export function issueProviderAccessToken({ sub, username, fullName, clientId, scope }) {
  const store = readProviderStore();
  const accessToken = randomToken(32);
  const expiresAt = expiresAtFromDuration(env.externalAccessTokenTtl, 10 * 60 * 1000);

  store.accessTokens[accessToken] = {
    active: true,
    sub,
    username,
    fullName,
    client_id: clientId,
    scope,
    exp: Math.floor(expiresAt / 1000)
  };

  writeProviderStore(store);
  return {
    accessToken,
    record: store.accessTokens[accessToken]
  };
}

export function introspectProviderAccessToken(accessToken) {
  const store = readProviderStore();
  const record = store.accessTokens[accessToken];

  if (!record) {
    return { active: false, reason: "External token was not found." };
  }

  const now = Math.floor(Date.now() / 1000);

  if (!record.active || record.exp <= now) {
    return { active: false, reason: "External token is inactive or expired." };
  }

  return {
    ...record,
    active: true
  };
}
