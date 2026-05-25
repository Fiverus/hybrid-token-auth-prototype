import express from "express";
import bcrypt from "bcryptjs";
import cors from "cors";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import morgan from "morgan";
import { env } from "../config/env.js";
import { findProviderUserByUsername } from "../data/users.js";
import { sha256Base64Url } from "../utils/crypto.js";
import { durationToMilliseconds } from "../utils/duration.js";
import {
  consumeAuthorizationCode,
  createAuthorizationCode,
  getOrCreateProviderKeyMaterial,
  introspectProviderAccessToken,
  issueProviderAccessToken
} from "../services/provider.store.js";

function renderAuthorizePage({
  issuer,
  clientId,
  redirectUri,
  scope,
  state,
  nonce,
  codeChallenge,
  codeChallengeMethod,
  errorMessage = ""
}) {
  const errorBlock = errorMessage
    ? `<p style="color:#b91c1c;font-weight:700;">${errorMessage}</p>`
    : "";

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Local OIDC Provider</title>
    <style>
      body { font-family: Arial, sans-serif; background: #f3f4f6; margin: 0; }
      main { max-width: 560px; margin: 40px auto; background: white; padding: 24px; border-radius: 16px; box-shadow: 0 8px 24px rgba(0,0,0,0.08); }
      h1 { margin-top: 0; }
      label { display: block; margin: 12px 0; font-weight: 700; }
      input { width: 100%; padding: 10px 12px; margin-top: 6px; box-sizing: border-box; }
      button { margin-top: 16px; padding: 10px 16px; cursor: pointer; }
      code { background: #f3f4f6; padding: 2px 6px; border-radius: 6px; }
    </style>
  </head>
  <body>
    <main>
      <h1>Local OIDC Provider</h1>
      <p>This local provider issues an authorization code with PKCE for the academic prototype.</p>
      <p><strong>Issuer:</strong> <code>${issuer}</code></p>
      <p><strong>Client ID:</strong> <code>${clientId}</code></p>
      ${errorBlock}
      <form method="post" action="/oauth/authorize">
        <input type="hidden" name="client_id" value="${clientId}" />
        <input type="hidden" name="redirect_uri" value="${redirectUri}" />
        <input type="hidden" name="scope" value="${scope}" />
        <input type="hidden" name="state" value="${state}" />
        <input type="hidden" name="nonce" value="${nonce}" />
        <input type="hidden" name="code_challenge" value="${codeChallenge}" />
        <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}" />
        <label>
          Provider Username
          <input name="username" value="demo" />
        </label>
        <label>
          Provider Password
          <input name="password" type="password" value="Password123!" />
        </label>
        <button type="submit">Authorize</button>
      </form>
    </main>
  </body>
</html>`;
}

function validateAuthorizeRequest({
  clientId,
  redirectUri,
  codeChallenge,
  codeChallengeMethod,
  allowedClientId,
  allowedRedirectPath
}) {
  if (clientId !== allowedClientId) {
    return "Unknown client_id.";
  }

  if (!redirectUri || !redirectUri.endsWith(allowedRedirectPath)) {
    return "redirect_uri is not allowed.";
  }

  if (!codeChallenge || codeChallengeMethod !== "S256") {
    return "PKCE with S256 is required.";
  }

  return null;
}

export function createProviderApp({ runtimeConfig, allowedClientId, allowedRedirectPath }) {
  const app = express();
  const keyMaterial = getOrCreateProviderKeyMaterial();

  app.use(
    helmet({
      contentSecurityPolicy: false
    })
  );
  app.use(cors());
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use(morgan("dev"));

  app.get("/health", (req, res) => {
    return res.json({ status: "ok", service: "local-oidc-provider" });
  });

  app.get("/.well-known/openid-configuration", (req, res) => {
    const providerBaseUrl = runtimeConfig.getProviderBaseUrl();

    return res.json({
      issuer: providerBaseUrl,
      authorization_endpoint: `${providerBaseUrl}/oauth/authorize`,
      token_endpoint: `${providerBaseUrl}/oauth/token`,
      introspection_endpoint: `${providerBaseUrl}/oauth/introspect`,
      jwks_uri: `${providerBaseUrl}/oauth/jwks`,
      userinfo_endpoint: `${providerBaseUrl}/oauth/userinfo`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"]
    });
  });

  app.get("/oauth/jwks", (req, res) => {
    return res.json({
      keys: [keyMaterial.publicJwk]
    });
  });

  app.get("/oauth/public-key", (req, res) => {
    res.type("text/plain");
    return res.send(keyMaterial.publicKeyPem);
  });

  app.get("/oauth/authorize", (req, res) => {
    const providerBaseUrl = runtimeConfig.getProviderBaseUrl();
    const {
      client_id: clientId = "",
      redirect_uri: redirectUri = "",
      scope = "openid profile api.read",
      state = "",
      nonce = "",
      code_challenge: codeChallenge = "",
      code_challenge_method: codeChallengeMethod = "",
      response_type: responseType = ""
    } = req.query;

    if (responseType !== "code") {
      return res.status(400).send("Only response_type=code is supported.");
    }

    const validationError = validateAuthorizeRequest({
      clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
      allowedClientId,
      allowedRedirectPath
    });

    if (validationError) {
      return res.status(400).send(validationError);
    }

    return res.send(
      renderAuthorizePage({
        issuer: providerBaseUrl,
        clientId,
        redirectUri,
        scope,
        state,
        nonce,
        codeChallenge,
        codeChallengeMethod
      })
    );
  });

  app.post("/oauth/authorize", async (req, res) => {
    const providerBaseUrl = runtimeConfig.getProviderBaseUrl();
    const {
      client_id: clientId = "",
      redirect_uri: redirectUri = "",
      scope = "openid profile api.read",
      state = "",
      nonce = "",
      code_challenge: codeChallenge = "",
      code_challenge_method: codeChallengeMethod = "",
      username = "",
      password = ""
    } = req.body;

    const validationError = validateAuthorizeRequest({
      clientId,
      redirectUri,
      codeChallenge,
      codeChallengeMethod,
      allowedClientId,
      allowedRedirectPath
    });

    if (validationError) {
      return res.status(400).send(validationError);
    }

    const providerUser = findProviderUserByUsername(username.trim());

    if (!providerUser || !(await bcrypt.compare(password, providerUser.passwordHash))) {
      return res.status(401).send(
        renderAuthorizePage({
          issuer: providerBaseUrl,
          clientId,
          redirectUri,
          scope,
          state,
          nonce,
          codeChallenge,
          codeChallengeMethod,
          errorMessage: "Invalid provider credentials."
        })
      );
    }

    const code = createAuthorizationCode({
      clientId,
      redirectUri,
      scope,
      codeChallenge,
      codeChallengeMethod,
      nonce,
      state,
      user: providerUser
    });

    const redirectUrl = new URL(redirectUri);
    redirectUrl.searchParams.set("code", code);
    redirectUrl.searchParams.set("state", state);

    return res.redirect(302, redirectUrl.toString());
  });

  app.post("/oauth/token", (req, res) => {
    const providerBaseUrl = runtimeConfig.getProviderBaseUrl();
    const {
      grant_type: grantType,
      client_id: clientId,
      code,
      code_verifier: codeVerifier,
      redirect_uri: redirectUri
    } = req.body;

    if (grantType !== "authorization_code") {
      return res.status(400).json({ message: "Only authorization_code grant is supported." });
    }

    const record = consumeAuthorizationCode(code);

    if (!record) {
      return res.status(400).json({ message: "Authorization code is invalid or already used." });
    }

    if (record.expiresAt <= Date.now()) {
      return res.status(400).json({ message: "Authorization code has expired." });
    }

    if (record.clientId !== clientId || record.redirectUri !== redirectUri) {
      return res.status(400).json({ message: "Client or redirect_uri does not match." });
    }

    if (sha256Base64Url(codeVerifier) !== record.codeChallenge) {
      return res.status(400).json({ message: "PKCE verification failed." });
    }

    const { accessToken, record: accessTokenRecord } = issueProviderAccessToken({
      sub: record.sub,
      username: record.username,
      fullName: record.fullName,
      clientId,
      scope: record.scope
    });

    const idToken = jwt.sign(
      {
        sub: record.sub,
        preferred_username: record.username,
        name: record.fullName,
        nonce: record.nonce
      },
      keyMaterial.privateKeyPem,
      {
        algorithm: "RS256",
        issuer: providerBaseUrl,
        audience: clientId,
        keyid: keyMaterial.kid,
        expiresIn: env.externalIdTokenTtl
      }
    );

    return res.json({
      access_token: accessToken,
      id_token: idToken,
      token_type: "Bearer",
      expires_in: durationToMilliseconds(env.externalAccessTokenTtl, 10 * 60 * 1000) / 1000,
      scope: accessTokenRecord.scope
    });
  });

  app.post("/oauth/introspect", (req, res) => {
    const { token } = req.body;
    return res.json(introspectProviderAccessToken(token));
  });

  app.get("/oauth/userinfo", (req, res) => {
    const authorizationHeader = req.header("Authorization") || "";
    const accessToken = authorizationHeader.replace("Bearer ", "");
    const introspection = introspectProviderAccessToken(accessToken);

    if (!introspection.active) {
      return res.status(401).json({ message: "Access token is invalid." });
    }

    return res.json({
      sub: introspection.sub,
      preferred_username: introspection.username,
      name: introspection.fullName
    });
  });

  return app;
}
