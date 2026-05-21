let accessToken = "";

const usernameInput = document.querySelector("#username");
const passwordInput = document.querySelector("#password");
const externalTokenInput = document.querySelector("#externalToken");
const clientIdInput = document.querySelector("#clientId");
const tokenOutput = document.querySelector("#tokenOutput");
const responseOutput = document.querySelector("#responseOutput");

function showResponse(data) {
  responseOutput.textContent = JSON.stringify(data, null, 2);
}

function showToken(token) {
  tokenOutput.textContent = token || "No access token yet.";
}

async function login() {
  const response = await fetch("/api/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Client-Id": clientIdInput.value
    },
    credentials: "include",
    body: JSON.stringify({
      username: usernameInput.value,
      password: passwordInput.value,
      externalToken: externalTokenInput.value
    })
  });

  const data = await response.json();

  if (response.ok) {
    accessToken = data.accessToken;
    showToken(accessToken);
  }

  showResponse(data);
}

async function getProfile() {
  const response = await fetch("/api/protected/profile", {
    method: "GET",
    headers: {
      Authorization: `Bearer ${accessToken}`
    },
    credentials: "include"
  });

  const data = await response.json();
  showResponse(data);
}

async function refreshAccessToken() {
  const response = await fetch("/api/auth/refresh", {
    method: "POST",
    credentials: "include"
  });

  const data = await response.json();

  if (response.ok) {
    accessToken = data.accessToken;
    showToken(accessToken);
  }

  showResponse(data);
}

async function logout() {
  const response = await fetch("/api/auth/logout", {
    method: "POST",
    credentials: "include"
  });

  const data = await response.json();

  accessToken = "";
  showToken(accessToken);
  showResponse(data);
}

document.querySelector("#loginButton").addEventListener("click", login);
document.querySelector("#profileButton").addEventListener("click", getProfile);
document.querySelector("#refreshButton").addEventListener("click", refreshAccessToken);
document.querySelector("#logoutButton").addEventListener("click", logout);
