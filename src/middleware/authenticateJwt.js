import { verifyAccessToken } from "../services/token.service.js";

export function authenticateJwt(req, res, next) {
  const authorizationHeader = req.header("Authorization");

  if (!authorizationHeader || !authorizationHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Authorization header with Bearer token is required."
    });
  }

  const accessToken = authorizationHeader.replace("Bearer ", "");

  try {
    req.user = verifyAccessToken(accessToken);
    return next();
  } catch {
    return res.status(401).json({
      message: "Access token is invalid or expired."
    });
  }
}
