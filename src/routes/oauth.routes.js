import express from "express";
import { introspectToken } from "../services/oauth.service.js";

export const oauthRouter = express.Router();

oauthRouter.post("/introspect", async (req, res) => {
  const { token } = req.body;
  const result = await introspectToken(token);
  return res.json(result);
});
