import { allowedClients, externalAccessTokens } from "../data/oauthStore.js";

export async function introspectToken(externalToken) {
  if (!externalToken) {
    return { active: false, reason: "External token is missing." };
  }

  const tokenData = externalAccessTokens.get(externalToken);

  if (!tokenData) {
    return { active: false, reason: "External token was not found." };
  }

  const now = Math.floor(Date.now() / 1000);

  if (!tokenData.active || tokenData.exp <= now) {
    return { active: false, reason: "External token is inactive or expired." };
  }

  return { ...tokenData, active: true };
}

export async function validateOAuthAccess({ user, clientId, introspectionResult }) {
  if (!allowedClients.has(clientId)) {
    return { authorized: false, reason: "Client is not registered." };
  }

  if (introspectionResult.client_id !== clientId) {
    return { authorized: false, reason: "Token was issued for another client." };
  }

  const tokenScopes = introspectionResult.scope.split(" ");
  const hasRequiredScope = tokenScopes.includes("api.read");

  if (!hasRequiredScope) {
    return { authorized: false, reason: "Required scope api.read is missing." };
  }

  if (!user.allowedScopes.includes("api.read")) {
    return { authorized: false, reason: "User is not allowed to use api.read scope." };
  }

  return { authorized: true, scope: introspectionResult.scope };
}
