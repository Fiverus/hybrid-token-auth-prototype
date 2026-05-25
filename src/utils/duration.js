export function durationToMilliseconds(duration, fallbackMs) {
  if (typeof duration !== "string") {
    return fallbackMs;
  }

  const normalizedDuration = duration.trim();
  const match = normalizedDuration.match(/^(\d+)(ms|s|m|h|d)$/i);

  if (!match) {
    const numericDuration = Number(normalizedDuration);
    return Number.isFinite(numericDuration) && numericDuration > 0 ? numericDuration : fallbackMs;
  }

  const value = Number(match[1]);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case "ms":
      return value;
    case "s":
      return value * 1000;
    case "m":
      return value * 60 * 1000;
    case "h":
      return value * 60 * 60 * 1000;
    case "d":
      return value * 24 * 60 * 60 * 1000;
    default:
      return fallbackMs;
  }
}

export function expiresAtFromDuration(duration, fallbackMs) {
  return Date.now() + durationToMilliseconds(duration, fallbackMs);
}
