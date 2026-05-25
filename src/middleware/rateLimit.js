export function createRateLimit({ windowMs, max, message }) {
  const attempts = new Map();

  return function rateLimit(req, res, next) {
    const clientKey = req.ip || req.socket.remoteAddress || "unknown";
    const now = Date.now();
    const currentEntry = attempts.get(clientKey);

    if (!currentEntry || currentEntry.expiresAt <= now) {
      attempts.set(clientKey, {
        count: 1,
        expiresAt: now + windowMs
      });

      return next();
    }

    if (currentEntry.count >= max) {
      return res.status(429).json({
        message,
        retryAfterMs: currentEntry.expiresAt - now
      });
    }

    currentEntry.count += 1;
    attempts.set(clientKey, currentEntry);
    return next();
  };
}
