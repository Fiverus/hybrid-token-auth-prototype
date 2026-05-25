import path from "node:path";
import dotenv from "dotenv";

dotenv.config();

function parseNumber(value, fallback) {
  const parsedValue = Number(value);
  return Number.isFinite(parsedValue) && parsedValue > 0 ? parsedValue : fallback;
}

function parseBoolean(value, fallback = false) {
  if (value === undefined) {
    return fallback;
  }

  return value === "true";
}

function resolveOptionalPath(value) {
  return value ? path.resolve(process.cwd(), value) : "";
}

const enableHttps = parseBoolean(process.env.ENABLE_HTTPS, false);

export const env = {
  port: Number(process.env.PORT || 3000),
  nodeEnv: process.env.NODE_ENV || "development",
  enableHttps,
  tlsKeyPath: resolveOptionalPath(process.env.TLS_KEY_PATH),
  tlsCertPath: resolveOptionalPath(process.env.TLS_CERT_PATH),
  tlsPfxPath: resolveOptionalPath(process.env.TLS_PFX_PATH),
  tlsPfxPassphrase: process.env.TLS_PFX_PASSPHRASE || "",

  jwtAccessSecret:
    process.env.JWT_ACCESS_SECRET || "replace-this-access-secret-with-long-random-value",
  jwtRefreshSecret:
    process.env.JWT_REFRESH_SECRET || "replace-this-refresh-secret-with-long-random-value",
  oidcIssuer: process.env.OIDC_ISSUER || "http://127.0.0.1:4000",
  oidcClientId: process.env.OIDC_CLIENT_ID || "bachelor-client",
  oidcRedirectPath: process.env.OIDC_REDIRECT_PATH || "/oidc/callback",

  accessTokenTtl: process.env.ACCESS_TOKEN_TTL || "15m",
  refreshTokenTtl: process.env.REFRESH_TOKEN_TTL || "7d",
  externalAccessTokenTtl: process.env.EXTERNAL_ACCESS_TOKEN_TTL || "10m",
  externalIdTokenTtl: process.env.EXTERNAL_ID_TOKEN_TTL || "10m",

  cookieSecure: parseBoolean(process.env.COOKIE_SECURE, enableHttps),
  cookieSameSite: process.env.COOKIE_SAME_SITE || "lax",

  frontendOrigin: process.env.FRONTEND_ORIGIN || "http://localhost:3000",
  gatewayPort: parseNumber(process.env.GATEWAY_PORT, Number(process.env.PORT || 3000)),
  authServicePort: parseNumber(process.env.AUTH_SERVICE_PORT, 3001),
  resourceServicePort: parseNumber(process.env.RESOURCE_SERVICE_PORT, 3002),
  oidcProviderPort: parseNumber(process.env.OIDC_PROVIDER_PORT, 4000),
  storageDir: path.resolve(process.cwd(), process.env.STORAGE_DIR || ".data"),

  loginRateLimitWindowMs: parseNumber(process.env.LOGIN_RATE_LIMIT_WINDOW_MS, 15 * 60 * 1000),
  loginRateLimitMax: parseNumber(process.env.LOGIN_RATE_LIMIT_MAX, 10)
};
