import express from "express";
import bcrypt from "bcryptjs";
import { env } from "../config/env.js";
import { findUserById, findUserByUsername } from "../data/users.js";
import { createRateLimit } from "../middleware/rateLimit.js";
import { requireCsrf } from "../middleware/requireCsrf.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import {
  introspectExternalAccessToken,
  validateExternalIdToken
} from "../services/external-oidc.service.js";
import {
  buildCsrfCookieOptions,
  buildRefreshCookieOptions,
  generateCsrfToken,
  generateAccessToken,
  generateRefreshToken,
  revokeRefreshToken,
  verifyRefreshToken
} from "../services/token.service.js";

const loginRateLimiter = createRateLimit({
  windowMs: env.loginRateLimitWindowMs,
  max: env.loginRateLimitMax,
  message: "Too many login attempts. Please try again later."
});

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

async function validateExternalAccess({
  providerBaseUrl,
  user,
  externalAccessToken,
  idToken,
  clientId,
  oidcNonce
}) {
  const introspectionResult = await introspectExternalAccessToken({
    providerBaseUrl,
    token: externalAccessToken
  });

  if (!introspectionResult.active) {
    return {
      ok: false,
      statusCode: 401,
      body: {
        message: "Token introspection failed.",
        reason: introspectionResult.reason
      }
    };
  }

  let idTokenPayload;

  try {
    idTokenPayload = await validateExternalIdToken({
      providerBaseUrl,
      idToken,
      expectedAudience: clientId,
      expectedIssuer: providerBaseUrl,
      expectedNonce: oidcNonce
    });
  } catch (error) {
    return {
      ok: false,
      statusCode: error.statusCode || 401,
      body: {
        message: "ID token validation failed.",
        reason: error.message
      }
    };
  }

  if (introspectionResult.client_id !== clientId) {
    return {
      ok: false,
      statusCode: 403,
      body: {
        message: "OAuth 2.0 authorization failed.",
        reason: "Token was issued for another client."
      }
    };
  }

  const tokenScopes = introspectionResult.scope.split(" ");

  if (!tokenScopes.includes("api.read")) {
    return {
      ok: false,
      statusCode: 403,
      body: {
        message: "OAuth 2.0 authorization failed.",
        reason: "Required scope api.read is missing."
      }
    };
  }

  if (!user.allowedScopes.includes("api.read")) {
    return {
      ok: false,
      statusCode: 403,
      body: {
        message: "OAuth 2.0 authorization failed.",
        reason: "User is not allowed to use api.read scope."
      }
    };
  }

  if (idTokenPayload.sub !== introspectionResult.sub || user.externalSubject !== idTokenPayload.sub) {
    return {
      ok: false,
      statusCode: 403,
      body: {
        message: "OAuth 2.0 authorization failed.",
        reason: "External identity does not match the local user mapping."
      }
    };
  }

  return {
    ok: true,
    scope: introspectionResult.scope,
    providerUser: idTokenPayload
  };
}

export function createAuthRouter({ providerBaseUrl }) {
  const authRouter = express.Router();

  authRouter.post(
    "/login",
    loginRateLimiter,
    asyncHandler(async (req, res) => {
      const { username, password, externalAccessToken, idToken, oidcNonce } = req.body;

      if (
        !isNonEmptyString(username) ||
        !isNonEmptyString(password) ||
        !isNonEmptyString(externalAccessToken) ||
        !isNonEmptyString(idToken) ||
        !isNonEmptyString(oidcNonce)
      ) {
        return res.status(400).json({
          message: "username, password, externalAccessToken, idToken and oidcNonce are required."
        });
      }

      const normalizedUsername = username.trim();
      const user = findUserByUsername(normalizedUsername);

      if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
        return res.status(401).json({ message: "Invalid username or password." });
      }

      const externalValidation = await validateExternalAccess({
        providerBaseUrl,
        user,
        externalAccessToken: externalAccessToken.trim(),
        idToken: idToken.trim(),
        clientId: req.clientId,
        oidcNonce: oidcNonce.trim()
      });

      if (!externalValidation.ok) {
        return res.status(externalValidation.statusCode).json(externalValidation.body);
      }

      const accessToken = generateAccessToken(user, externalValidation.scope);
      const refreshToken = generateRefreshToken(user);
      const csrfToken = generateCsrfToken();

      res.cookie("refreshToken", refreshToken, buildRefreshCookieOptions());
      res.cookie("csrfToken", csrfToken, buildCsrfCookieOptions());

      return res.json({
        message: "Authentication completed successfully.",
        accessToken,
        tokenType: "Bearer",
        expiresIn: env.accessTokenTtl,
        refreshTokenTtl: env.refreshTokenTtl,
        csrfToken,
        externalIdentity: {
          sub: externalValidation.providerUser.sub,
          preferredUsername: externalValidation.providerUser.preferred_username,
          name: externalValidation.providerUser.name
        },
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          fullName: user.fullName
        },
        checks: {
          apiGateway: "passed",
          tokenIntrospection: "passed",
          oidcIdTokenValidation: "passed",
          oauthAuthorization: "passed"
        }
      });
    })
  );

  authRouter.post(
    "/refresh",
    requireCsrf,
    asyncHandler(async (req, res) => {
      const refreshToken = req.cookies.refreshToken;

      if (!refreshToken) {
        return res.status(401).json({ message: "Refresh token cookie is missing." });
      }

      let refreshPayload;

      try {
        refreshPayload = verifyRefreshToken(refreshToken);
      } catch {
        res.clearCookie("refreshToken", {
          ...buildRefreshCookieOptions(),
          maxAge: undefined
        });

        return res.status(401).json({ message: "Refresh token is invalid, expired or revoked." });
      }

      const user = findUserById(refreshPayload.sub);

      if (!user) {
        return res.status(401).json({ message: "User no longer exists." });
      }

      revokeRefreshToken(refreshToken);

      const accessToken = generateAccessToken(user, "openid profile api.read");
      const nextRefreshToken = generateRefreshToken(user);

      res.cookie("refreshToken", nextRefreshToken, buildRefreshCookieOptions());

      return res.json({
        message: "Access token refreshed successfully.",
        accessToken,
        tokenType: "Bearer",
        expiresIn: env.accessTokenTtl,
        refreshTokenRotated: true
      });
    })
  );

  authRouter.post("/logout", requireCsrf, (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (refreshToken) {
      revokeRefreshToken(refreshToken);
    }

    res.clearCookie("refreshToken", {
      ...buildRefreshCookieOptions(),
      maxAge: undefined
    });
    res.clearCookie("csrfToken", {
      ...buildCsrfCookieOptions(),
      maxAge: undefined
    });

    return res.json({ message: "Logout completed successfully." });
  });

  return authRouter;
}
