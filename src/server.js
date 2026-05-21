import { createApp } from "./app.js";
import { env } from "./config/env.js";

const app = createApp();

app.listen(env.port, () => {
  console.log(`Hybrid token auth prototype is running on http://localhost:${env.port}`);
});
