export function requireCsrf(req, res, next) {
  const csrfCookie = req.cookies.csrfToken;
  const csrfHeader = req.header("X-CSRF-Token");

  if (!csrfCookie || !csrfHeader || csrfCookie !== csrfHeader) {
    return res.status(403).json({
      message: "Valid CSRF token is required."
    });
  }

  return next();
}
