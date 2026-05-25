function shouldForwardResponseHeader(headerName) {
  const lowerCaseHeaderName = headerName.toLowerCase();
  return !["content-length", "transfer-encoding", "connection"].includes(lowerCaseHeaderName);
}

export async function forwardJsonRequest(req, res, { targetUrl, method = req.method }) {
  const headers = new Headers();

  for (const [headerName, headerValue] of Object.entries(req.headers)) {
    if (
      headerValue &&
      !["host", "content-length", "connection"].includes(headerName.toLowerCase())
    ) {
      headers.set(headerName, headerValue);
    }
  }

  let body;

  if (!["GET", "HEAD"].includes(method.toUpperCase())) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(req.body ?? {});
  }

  const response = await fetch(targetUrl, {
    method,
    headers,
    body
  });

  const responseBodyBuffer = Buffer.from(await response.arrayBuffer());
  res.status(response.status);

  for (const [headerName, headerValue] of response.headers.entries()) {
    if (shouldForwardResponseHeader(headerName)) {
      res.setHeader(headerName, headerValue);
    }
  }

  for (const cookie of response.headers.getSetCookie()) {
    res.append("set-cookie", cookie);
  }

  return res.send(responseBodyBuffer);
}
