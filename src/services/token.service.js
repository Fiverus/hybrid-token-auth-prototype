import path from "node:path";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { env } from "../config/env.js";
import { randomToken } from "../utils/crypto.js";
import { durationToMilliseconds } from "../utils/duration.js";
import { readJsonFile, writeJsonFile } from "../utils/fileStore.js";

const refreshStorePath = path.join(env.storageDir, "refresh-tokens.json");

function readRefreshStore() {
  return readJsonFile(refreshStorePath, {});
}

function writeRefreshStore(value) {
  writeJsonFile(refreshStorePath, value);
}

export function generateAccessToken(user, scope) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role,
      scope,
      type: "access"
    },
    env.jwtAccessSecret,
    {
      expiresIn: env.accessTokenTtl,
      issuer: "hybrid-token-auth-prototype",
      audience: "prototype-api"
    }
  );
}

export function generateRefreshToken(user) {
  const tokenId = uuidv4();
  const refreshStore = readRefreshStore();

  const refreshToken = jwt.sign(
    {
      sub: user.id,
      tokenId,
      type: "refresh"
    },
    env.jwtRefreshSecret,
    {
      expiresIn: env.refreshTokenTtl,
      issuer: "hybrid-token-auth-prototype",
      audience: "prototype-refresh"
    }
  );

  refreshStore[tokenId] = {
    userId: user.id,
    revoked: false,
    createdAt: new Date()
  };
  writeRefreshStore(refreshStore);

  return refreshToken;
}

export function verifyAccessToken(accessToken) {
  return jwt.verify(accessToken, env.jwtAccessSecret, {
    issuer: "hybrid-token-auth-prototype",
    audience: "prototype-api"
  });
}

export function verifyRefreshToken(refreshToken) {
  const payload = jwt.verify(refreshToken, env.jwtRefreshSecret, {
    issuer: "hybrid-token-auth-prototype",
    audience: "prototype-refresh"
  });

  const refreshStore = readRefreshStore();
  const record = refreshStore[payload.tokenId];

  if (!record || record.revoked) {
    const error = new Error("Refresh token is revoked or unknown.");
    error.statusCode = 401;
    throw error;
  }

  return payload;
}

export function revokeRefreshToken(refreshToken) {
  try {
    const payload = jwt.verify(refreshToken, env.jwtRefreshSecret, {
      issuer: "hybrid-token-auth-prototype",
      audience: "prototype-refresh"
    });

    const refreshStore = readRefreshStore();
    const record = refreshStore[payload.tokenId];

    if (record) {
      record.revoked = true;
      refreshStore[payload.tokenId] = record;
      writeRefreshStore(refreshStore);
    }
  } catch {}
}

export function buildCsrfCookieOptions() {
  return {
    httpOnly: false,
    secure: env.cookieSecure,
    sameSite: env.cookieSameSite,
    path: "/api/auth"
  };
}

export function generateCsrfToken() {
  return randomToken(24);
}

export function buildRefreshCookieOptions() {
  return {
    httpOnly: true,
    secure: env.cookieSecure,
    sameSite: env.cookieSameSite,
    path: "/api/auth",
    maxAge: durationToMilliseconds(env.refreshTokenTtl, 7 * 24 * 60 * 60 * 1000)
  };
}
