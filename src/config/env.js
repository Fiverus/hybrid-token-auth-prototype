import dotenv from "dotenv";

dotenv.config();

export const env = {
  port: Number(process.env.PORT || 3000),
  nodeEnv: process.env.NODE_ENV || "development",

  jwtAccessSecret:
    process.env.JWT_ACCESS_SECRET || "replace-this-access-secret-with-long-random-value",
  jwtRefreshSecret:
    process.env.JWT_REFRESH_SECRET || "replace-this-refresh-secret-with-long-random-value",

  accessTokenTtl: process.env.ACCESS_TOKEN_TTL || "15m",
  refreshTokenTtl: process.env.REFRESH_TOKEN_TTL || "7d",

  cookieSecure: process.env.COOKIE_SECURE === "true",
  cookieSameSite: process.env.COOKIE_SAME_SITE || "lax",

  frontendOrigin: process.env.FRONTEND_ORIGIN || "http://localhost:3000"
};
