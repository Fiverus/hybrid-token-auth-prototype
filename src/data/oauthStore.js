export const externalAccessTokens = new Map([
  [
    "external-valid-token",
    {
      active: true,
      sub: "external-user-1",
      client_id: "bachelor-client",
      scope: "openid profile api.read",
      exp: Math.floor(Date.now() / 1000) + 60 * 60
    }
  ],
  [
    "external-token-without-scope",
    {
      active: true,
      sub: "external-user-1",
      client_id: "bachelor-client",
      scope: "openid profile",
      exp: Math.floor(Date.now() / 1000) + 60 * 60
    }
  ],
  [
    "external-expired-token",
    {
      active: false,
      sub: "external-user-1",
      client_id: "bachelor-client",
      scope: "openid profile api.read",
      exp: Math.floor(Date.now() / 1000) - 60
    }
  ]
]);

export const allowedClients = new Set(["bachelor-client"]);
