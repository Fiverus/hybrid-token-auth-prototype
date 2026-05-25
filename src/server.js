import { env } from "./config/env.js";
import { startPrototypeStack } from "./stack.js";

const stack = await startPrototypeStack({
  gatewayPort: env.gatewayPort,
  authPort: env.authServicePort,
  resourcePort: env.resourceServicePort,
  providerPort: env.oidcProviderPort
});

console.log(`Gateway is running on ${stack.gatewayBaseUrl}`);
console.log(`Auth service is running on ${stack.authBaseUrl}`);
console.log(`Resource service is running on ${stack.resourceBaseUrl}`);
console.log(`OIDC provider is running on ${stack.providerBaseUrl}`);
