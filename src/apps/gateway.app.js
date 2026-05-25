import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import { env } from "../config/env.js";
import { apiGatewayCheck } from "../middleware/apiGateway.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { exchangeAuthorizationCode } from "../services/external-oidc.service.js";
import { forwardJsonRequest } from "../utils/proxy.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createGatewayApp({
  runtimeConfig,
  authBaseUrl,
  resourceBaseUrl,
  providerBaseUrl
}) {
  const app = express();

  function resolveGatewayBaseUrl(req) {
    return `${req.protocol}://${req.get("host")}`;
  }

  app.use(
    helmet({
      contentSecurityPolicy: false
    })
  );
  app.use(
    cors({
      origin: runtimeConfig.getGatewayBaseUrl(),
      credentials: true
    })
  );
  app.use(express.json());
  app.use(cookieParser());
  app.use(morgan("dev"));
  app.use(express.static(path.join(__dirname, "../../public")));

  app.get(env.oidcRedirectPath, (req, res) => {
    return res.sendFile(path.join(__dirname, "../../public/oidc-callback.html"));
  });

  app.get(
    "/health",
    asyncHandler(async (req, res) => {
      const [authHealth, resourceHealth, providerHealth] = await Promise.all([
        fetch(`${authBaseUrl}/health`).then((response) => response.json()),
        fetch(`${resourceBaseUrl}/health`).then((response) => response.json()),
        fetch(`${providerBaseUrl}/health`).then((response) => response.json())
      ]);

      return res.json({
        status: "ok",
        service: "hybrid-token-auth-prototype-gateway",
        services: {
          gateway: "ok",
          auth: authHealth.status,
          resource: resourceHealth.status,
          provider: providerHealth.status
        }
      });
    })
  );

  app.get("/api/config", (req, res) => {
    const gatewayBaseUrl = resolveGatewayBaseUrl(req);

    return res.json({
      gatewayBaseUrl,
      providerBaseUrl,
      oidc: {
        clientId: env.oidcClientId,
        authorizeUrl: `${providerBaseUrl}/oauth/authorize`,
        redirectUri: `${gatewayBaseUrl}${env.oidcRedirectPath}`,
        scope: "openid profile api.read"
      },
      demo: {
        localUsers: ["demo", "admin"],
        providerUsers: ["demo", "admin"]
      }
    });
  });

  app.post(
    "/api/oidc/exchange",
    asyncHandler(async (req, res) => {
      const gatewayBaseUrl = resolveGatewayBaseUrl(req);
      const redirectUri = `${gatewayBaseUrl}${env.oidcRedirectPath}`;
      const { code, codeVerifier } = req.body;

      const tokens = await exchangeAuthorizationCode({
        providerBaseUrl,
        clientId: env.oidcClientId,
        code,
        codeVerifier,
        redirectUri
      });

      return res.json(tokens);
    })
  );

  app.post(
    "/api/auth/login",
    apiGatewayCheck,
    asyncHandler(async (req, res) => {
      return forwardJsonRequest(req, res, {
        targetUrl: `${authBaseUrl}/auth/login`
      });
    })
  );

  app.post(
    "/api/auth/refresh",
    asyncHandler(async (req, res) => {
      return forwardJsonRequest(req, res, {
        targetUrl: `${authBaseUrl}/auth/refresh`
      });
    })
  );

  app.post(
    "/api/auth/logout",
    asyncHandler(async (req, res) => {
      return forwardJsonRequest(req, res, {
        targetUrl: `${authBaseUrl}/auth/logout`
      });
    })
  );

  app.get(
    "/api/protected/profile",
    asyncHandler(async (req, res) => {
      return forwardJsonRequest(req, res, {
        targetUrl: `${resourceBaseUrl}/protected/profile`
      });
    })
  );

  app.get(
    "/api/protected/admin",
    asyncHandler(async (req, res) => {
      return forwardJsonRequest(req, res, {
        targetUrl: `${resourceBaseUrl}/protected/admin`
      });
    })
  );

  app.use((req, res) => {
    return res.status(404).json({ message: "Route not found." });
  });

  app.use((error, req, res, next) => {
    console.error(error);
    return res.status(error.statusCode || 500).json({
      message: error.message || "Internal server error."
    });
  });

  return app;
}
