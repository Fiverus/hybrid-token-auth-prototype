import test from "node:test";
import assert from "node:assert/strict";
import { createApp } from "../src/app.js";

test("application can be created", () => {
  const app = createApp();
  assert.ok(app);
});
