import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import { env } from "../config/env.js";
import { protectedRouter } from "../routes/protected.routes.js";

export function createResourceApp({ frontendOrigin }) {
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
  app.use(morgan("dev"));

  app.get("/health", (req, res) => {
    return res.json({ status: "ok", service: "resource-service" });
  });

  app.use("/protected", protectedRouter);

  app.use((error, req, res, next) => {
    console.error(error);
    return res.status(error.statusCode || 500).json({
      message: error.message || "Internal server error."
    });
  });

  return app;
}
