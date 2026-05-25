import path from "node:path";
import { fileURLToPath } from "node:url";
import { readJsonFile } from "../utils/fileStore.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const localUsersPath = path.join(__dirname, "localUsers.json");
const providerUsersPath = path.join(__dirname, "providerUsers.json");

export function getLocalUsers() {
  return readJsonFile(localUsersPath, []);
}

export function getProviderUsers() {
  return readJsonFile(providerUsersPath, []);
}

export function findUserByUsername(username) {
  return getLocalUsers().find((user) => user.username === username);
}

export function findUserById(id) {
  return getLocalUsers().find((user) => user.id === id);
}

export function findProviderUserByUsername(username) {
  return getProviderUsers().find((user) => user.username === username);
}

export function findProviderUserBySubject(sub) {
  return getProviderUsers().find((user) => user.sub === sub);
}
