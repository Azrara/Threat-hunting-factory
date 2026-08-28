// Thin API client with token handling and readable error messages.

const TOKEN_KEY = "thf.token";
const SESSION_KEY = "thf.session";

export const auth = {
  get token() {
    return localStorage.getItem(TOKEN_KEY) || "";
  },
  get session() {
    try {
      return JSON.parse(localStorage.getItem(SESSION_KEY) || "null");
    } catch (error) {
      return null;
    }
  },
  save(payload) {
    localStorage.setItem(TOKEN_KEY, payload.access_token);
    localStorage.setItem(SESSION_KEY, JSON.stringify({ user: payload.user, tenant: payload.tenant }));
  },
  update(session) {
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(SESSION_KEY);
  },
  get isAuthenticated() {
    return Boolean(this.token && this.session);
  },
};

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function parseError(response) {
  let message = `Request failed with status ${response.status}`;
  try {
    const data = await response.json();
    if (typeof data.detail === "string") message = data.detail;
    else if (Array.isArray(data.detail) && data.detail.length) message = data.detail[0].msg || message;
  } catch (error) {
    /* the body was not JSON, keep the default message */
  }
  return new ApiError(message, response.status);
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (auth.token) headers.set("Authorization", `Bearer ${auth.token}`);
  if (options.json !== undefined) {
    headers.set("Content-Type", "application/json");
    options.body = JSON.stringify(options.json);
  }
  const hadToken = Boolean(auth.token);
  const response = await fetch(path, { ...options, headers });
  if (response.status === 401) {
    // A rejected sign in is not an expired session. Only a request that
    // carried a token means the session went stale, and only then should the
    // application sign the user out and re render.
    if (!hadToken) throw await parseError(response);
    auth.clear();
    window.dispatchEvent(new CustomEvent("thf:unauthorised"));
    throw new ApiError("Your session has expired, please sign in again", 401);
  }
  if (!response.ok) throw await parseError(response);
  if (response.status === 204) return null;
  const type = response.headers.get("content-type") || "";
  return type.includes("application/json") ? response.json() : response.blob();
}

export const api = {
  health: () => request("/api/health"),
  register: (payload) => request("/api/auth/register", { method: "POST", json: payload }),
  login: (payload) => request("/api/auth/login", { method: "POST", json: payload }),
  me: () => request("/api/auth/me"),

  hypotheses: (params = {}) => request(`/api/hypotheses?${new URLSearchParams(params)}`),
  hypothesis: (id) => request(`/api/hypotheses/${encodeURIComponent(id)}`),
  dataSources: () => request("/api/data-sources"),
  rules: () => request("/api/rules"),

  hunts: (params = {}) => request(`/api/hunts?${new URLSearchParams(params)}`),
  hunt: (id) => request(`/api/hunts/${encodeURIComponent(id)}`),
  observations: (id, params = {}) =>
    request(`/api/hunts/${encodeURIComponent(id)}/observations?${new URLSearchParams(params)}`),
  deleteHunt: (id) => request(`/api/hunts/${encodeURIComponent(id)}`, { method: "DELETE" }),
  rerun: (id) => request(`/api/hunts/${encodeURIComponent(id)}/rerun`, { method: "POST" }),
  createHunt: (formData, onProgress) =>
    new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/api/hunts");
      xhr.setRequestHeader("Authorization", `Bearer ${auth.token}`);
      xhr.upload.addEventListener("progress", (event) => {
        if (onProgress && event.lengthComputable) onProgress(event.loaded / event.total);
      });
      xhr.onload = () => {
        let body = {};
        try {
          body = JSON.parse(xhr.responseText || "{}");
        } catch (error) {
          /* keep the empty object */
        }
        if (xhr.status >= 200 && xhr.status < 300) resolve(body);
        else reject(new ApiError(body.detail || `Upload failed with status ${xhr.status}`, xhr.status));
      };
      xhr.onerror = () => reject(new ApiError("The upload could not reach the server", 0));
      xhr.send(formData);
    }),

  stats: (days = 90) => request(`/api/stats/overview?days=${days}`),

  users: () => request("/api/admin/users"),
  createUser: (payload) => request("/api/admin/users", { method: "POST", json: payload }),
  updateUser: (id, payload) => request(`/api/admin/users/${id}`, { method: "PATCH", json: payload }),
  deleteUser: (id) => request(`/api/admin/users/${id}`, { method: "DELETE" }),
  audit: () => request("/api/admin/audit"),
  workspace: () => request("/api/admin/workspace"),

  async download(path, fallbackName) {
    const response = await fetch(path, { headers: { Authorization: `Bearer ${auth.token}` } });
    if (!response.ok) throw await parseError(response);
    const disposition = response.headers.get("content-disposition") || "";
    const match = disposition.match(/filename="?([^"]+)"?/);
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = match ? match[1] : fallbackName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  },
};
