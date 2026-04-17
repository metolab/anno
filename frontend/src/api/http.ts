import axios from "axios";

const baseURL = import.meta.env.VITE_API_BASE ?? "";

export const api = axios.create({
  baseURL,
  timeout: 30_000,
});

export const TOKEN_KEY = "anno_auth_token";

const storedToken = localStorage.getItem(TOKEN_KEY);
if (storedToken) {
  api.defaults.headers.common["Authorization"] = `Bearer ${storedToken}`;
}

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
      delete api.defaults.headers.common["Authorization"];
      if (window.location.pathname !== "/login") {
        window.location.href = "/login";
      }
    }
    return Promise.reject(err);
  },
);
