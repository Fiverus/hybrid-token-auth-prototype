export function apiGatewayCheck(req, res, next) {
  const clientId = req.header("X-Client-Id");
  const contentType = req.header("Content-Type") || "";

  if (!clientId) {
    return res.status(400).json({
      message: "API Gateway rejected the request: X-Client-Id header is missing."
    });
  }

  if (req.method === "POST" && !contentType.includes("application/json")) {
    return res.status(415).json({
      message: "API Gateway rejected the request: Content-Type must be application/json."
    });
  }

  req.gatewayValidated = true;
  req.clientId = clientId;
  return next();
}
