import fs from "node:fs";
import path from "node:path";

export function ensureJsonFile(filePath, initialValue) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });

  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(initialValue, null, 2));
  }
}

export function readJsonFile(filePath, fallbackValue) {
  ensureJsonFile(filePath, fallbackValue);
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

export function writeJsonFile(filePath, value) {
  ensureJsonFile(filePath, value);
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}
