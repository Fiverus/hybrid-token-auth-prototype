import express from "express";
import { authenticateJwt } from "../middleware/authenticateJwt.js";

export const protectedRouter = express.Router();

protectedRouter.get("/profile", authenticateJwt, (req, res) => {
  return res.json({
    message: "Protected profile resource.",
    user: {
      id: req.user.sub,
      username: req.user.username,
      role: req.user.role,
      scope: req.user.scope
    }
  });
});

protectedRouter.get("/admin", authenticateJwt, (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin role is required." });
  }

  return res.json({ message: "Protected admin resource." });
});
