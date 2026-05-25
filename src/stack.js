import fs from "node:fs";
import https from "node:https";
import { createAuthApp } from "./apps/auth.app.js";
import { createGatewayApp } from "./apps/gateway.app.js";
import { createProviderApp } from "./apps/provider.app.js";
import { createResourceApp } from "./apps/resource.app.js";
import { env } from "./config/env.js";

function getTlsOptions({ enableHttps, tlsKeyPath, tlsCertPath, tlsPfxPath, tlsPfxPassphrase }) {
  if (!enableHttps) {
    return null;
  }

  if (tlsPfxPath) {
    return {
      pfx: fs.readFileSync(tlsPfxPath),
      passphrase: tlsPfxPassphrase || undefined
    };
  }

  if (!tlsKeyPath || !tlsCertPath) {
    throw new Error(
      "ENABLE_HTTPS=true requires either TLS_PFX_PATH or both TLS_KEY_PATH and TLS_CERT_PATH."
    );
  }

  return {
    key: fs.readFileSync(tlsKeyPath),
    cert: fs.readFileSync(tlsCertPath)
  };
}

function listen(app, port, tlsOptions) {
  return new Promise((resolve) => {
    const server = tlsOptions
      ? https.createServer(tlsOptions, app).listen(port, () => resolve(server))
      : app.listen(port, () => resolve(server));
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });
}

export async function startPrototypeStack({
  gatewayPort = env.gatewayPort,
  authPort = env.authServicePort,
  resourcePort = env.resourceServicePort,
  providerPort = env.oidcProviderPort,
  enableHttps = env.enableHttps,
  tlsKeyPath = env.tlsKeyPath,
  tlsCertPath = env.tlsCertPath,
  tlsPfxPath = env.tlsPfxPath,
  tlsPfxPassphrase = env.tlsPfxPassphrase
} = {}) {
  const protocol = enableHttps ? "https" : "http";
  const tlsOptions = getTlsOptions({
    enableHttps,
    tlsKeyPath,
    tlsCertPath,
    tlsPfxPath,
    tlsPfxPassphrase
  });
  const plannedGatewayBaseUrl = `${protocol}://127.0.0.1:${gatewayPort || env.gatewayPort}`;

  const providerRuntimeConfig = {
    providerBaseUrl: "",
    getProviderBaseUrl() {
      return this.providerBaseUrl;
    }
  };
  const providerApp = createProviderApp({
    runtimeConfig: providerRuntimeConfig,
    allowedClientId: env.oidcClientId,
    allowedRedirectPath: env.oidcRedirectPath
  });
  const providerServer = await listen(providerApp, providerPort, tlsOptions);
  const resolvedProviderPort = providerServer.address().port;
  const resolvedProviderBaseUrl = `${protocol}://127.0.0.1:${resolvedProviderPort}`;
  providerRuntimeConfig.providerBaseUrl = resolvedProviderBaseUrl;

  const authApp = createAuthApp({
    providerBaseUrl: resolvedProviderBaseUrl,
    frontendOrigin: plannedGatewayBaseUrl
  });
  const authServer = await listen(authApp, authPort, tlsOptions);
  const resolvedAuthBaseUrl = `${protocol}://127.0.0.1:${authServer.address().port}`;

  const resourceApp = createResourceApp({
    frontendOrigin: plannedGatewayBaseUrl
  });
  const resourceServer = await listen(resourceApp, resourcePort, tlsOptions);
  const resolvedResourceBaseUrl = `${protocol}://127.0.0.1:${resourceServer.address().port}`;

  const runtimeConfig = {
    gatewayBaseUrl: "",
    getGatewayBaseUrl() {
      return this.gatewayBaseUrl;
    }
  };

  const gatewayApp = createGatewayApp({
    runtimeConfig,
    authBaseUrl: resolvedAuthBaseUrl,
    resourceBaseUrl: resolvedResourceBaseUrl,
    providerBaseUrl: resolvedProviderBaseUrl
  });
  const gatewayServer = await listen(gatewayApp, gatewayPort, tlsOptions);
  const resolvedGatewayBaseUrl = `${protocol}://127.0.0.1:${gatewayServer.address().port}`;
  runtimeConfig.gatewayBaseUrl = resolvedGatewayBaseUrl;

  return {
    gatewayBaseUrl: resolvedGatewayBaseUrl,
    authBaseUrl: resolvedAuthBaseUrl,
    resourceBaseUrl: resolvedResourceBaseUrl,
    providerBaseUrl: resolvedProviderBaseUrl,
    async close() {
      await Promise.all([
        closeServer(gatewayServer),
        closeServer(authServer),
        closeServer(resourceServer),
        closeServer(providerServer)
      ]);
    }
  };
}
