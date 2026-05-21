import bcrypt from "bcryptjs";

const demoPasswordHash = bcrypt.hashSync("Password123!", 10);

export const users = [
  {
    id: "user-1",
    username: "demo",
    passwordHash: demoPasswordHash,
    role: "user",
    fullName: "Demo User",
    allowedScopes: ["openid", "profile", "api.read"]
  }
];

export function findUserByUsername(username) {
  return users.find((user) => user.username === username);
}

export function findUserById(id) {
  return users.find((user) => user.id === id);
}
