import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import { env } from "./config/env.js";
import { authRouter } from "./routes/auth.routes.js";
import { oauthRouter } from "./routes/oauth.routes.js";
import { protectedRouter } from "./routes/protected.routes.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createApp() {
  const app = express();

  app.use(
    helmet({
      contentSecurityPolicy: false
    })
  );

  app.use(
    cors({
      origin: env.frontendOrigin,
      credentials: true
    })
  );

  app.use(express.json());
  app.use(cookieParser());
  app.use(morgan("dev"));
  app.use(express.static(path.join(__dirname, "../public")));

  app.get("/health", (req, res) => {
    return res.json({ status: "ok", service: "hybrid-token-auth-prototype" });
  });

  app.use("/api/auth", authRouter);
  app.use("/oauth", oauthRouter);
  app.use("/api/protected", protectedRouter);

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
