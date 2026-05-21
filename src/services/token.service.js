import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import { env } from "../config/env.js";

const refreshTokenStore = new Map();

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

  refreshTokenStore.set(tokenId, {
    userId: user.id,
    revoked: false,
    createdAt: new Date()
  });

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

  const record = refreshTokenStore.get(payload.tokenId);

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

    const record = refreshTokenStore.get(payload.tokenId);

    if (record) {
      record.revoked = true;
      refreshTokenStore.set(payload.tokenId, record);
    }
  } catch {}
}

export function buildRefreshCookieOptions() {
  return {
    httpOnly: true,
    secure: env.cookieSecure,
    sameSite: env.cookieSameSite,
    path: "/api/auth",
    maxAge: 7 * 24 * 60 * 60 * 1000
  };
}
