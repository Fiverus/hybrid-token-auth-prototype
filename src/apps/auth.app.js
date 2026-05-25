import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import { createAuthRouter } from "../routes/auth.routes.js";

export function createAuthApp({ providerBaseUrl, frontendOrigin }) {
  const app = express();

  app.use(
    helmet({
      contentSecurityPolicy: false
    })
  );
  app.use(
    cors({
      origin: frontendOrigin,
      credentials: true
    })
  );
  app.use(express.json());
  app.use(cookieParser());
  app.use(morgan("dev"));
  app.use((req, res, next) => {
    req.clientId = req.header("X-Client-Id");
    return next();
  });

  app.get("/health", (req, res) => {
    return res.json({ status: "ok", service: "auth-service" });
  });

  app.use("/auth", createAuthRouter({ providerBaseUrl }));

  app.use((error, req, res, next) => {
    console.error(error);
    return res.status(error.statusCode || 500).json({
      message: error.message || "Internal server error."
    });
  });

  return app;
}
