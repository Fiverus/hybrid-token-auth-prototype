import express from "express";
import bcrypt from "bcryptjs";
import { findUserById, findUserByUsername } from "../data/users.js";
import { apiGatewayCheck } from "../middleware/apiGateway.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { introspectToken, validateOAuthAccess } from "../services/oauth.service.js";
import {
  buildRefreshCookieOptions,
  generateAccessToken,
  generateRefreshToken,
  revokeRefreshToken,
  verifyRefreshToken
} from "../services/token.service.js";

export const authRouter = express.Router();

authRouter.post(
  "/login",
  apiGatewayCheck,
  asyncHandler(async (req, res) => {
    const { username, password, externalToken } = req.body;

    if (!req.gatewayValidated) {
      return res.status(403).json({ message: "Request blocked by API Gateway." });
    }

    if (!username || !password || !externalToken) {
      return res.status(400).json({
        message: "username, password and externalToken are required."
      });
    }

    const user = findUserByUsername(username);

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return res.status(401).json({ message: "Invalid username or password." });
    }

    const introspectionResult = await introspectToken(externalToken);

    if (!introspectionResult.active) {
      return res.status(401).json({
        message: "Token introspection failed.",
        reason: introspectionResult.reason
      });
    }

    const oauthResult = await validateOAuthAccess({
      user,
      clientId: req.clientId,
      introspectionResult
    });

    if (!oauthResult.authorized) {
      return res.status(403).json({
        message: "OAuth 2.0 authorization failed.",
        reason: oauthResult.reason
      });
    }

    const accessToken = generateAccessToken(user, oauthResult.scope);
    const refreshToken = generateRefreshToken(user);

    res.cookie("refreshToken", refreshToken, buildRefreshCookieOptions());

    return res.json({
      message: "Authentication completed successfully.",
      accessToken,
      tokenType: "Bearer",
      expiresIn: "15 minutes",
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        fullName: user.fullName
      },
      checks: {
        apiGateway: "passed",
        tokenIntrospection: "passed",
        oauthAuthorization: "passed"
      }
    });
  })
);

authRouter.post(
  "/refresh",
  asyncHandler(async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh token cookie is missing." });
    }

    const refreshPayload = verifyRefreshToken(refreshToken);
    const user = findUserById(refreshPayload.sub);

    if (!user) {
      return res.status(401).json({ message: "User no longer exists." });
    }

    const accessToken = generateAccessToken(user, "openid profile api.read");

    return res.json({
      message: "Access token refreshed successfully.",
      accessToken,
      tokenType: "Bearer",
      expiresIn: "15 minutes"
    });
  })
);

authRouter.post("/logout", (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (refreshToken) {
    revokeRefreshToken(refreshToken);
  }

  res.clearCookie("refreshToken", {
    ...buildRefreshCookieOptions(),
    maxAge: undefined
  });

  return res.json({ message: "Logout completed successfully." });
});
