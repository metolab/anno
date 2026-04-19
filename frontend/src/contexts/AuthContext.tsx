import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { getAuthConfig, type AuthMode } from "../api/auth";
import { api, TOKEN_KEY } from "../api/http";

export { TOKEN_KEY };
export type { AuthMode };

interface AuthContextValue {
  token: string | null;
  authMode: AuthMode | null;
  configError: string | null;
  isReady: boolean;
  isAuthenticated: boolean;
  reloadConfig: () => Promise<void>;
  signIn: (token: string) => void;
  signOut: () => void;
}

const AuthContext = createContext<AuthContextValue>({
  token: null,
  authMode: null,
  configError: null,
  isReady: false,
  isAuthenticated: false,
  reloadConfig: async () => {},
  signIn: () => {},
  signOut: () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem(TOKEN_KEY));
  const [authMode, setAuthMode] = useState<AuthMode | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);

  const applyToken = useCallback((newToken: string | null) => {
    setToken(newToken);
    if (newToken) {
      localStorage.setItem(TOKEN_KEY, newToken);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  }, []);

  useEffect(() => {
    if (token) {
      api.defaults.headers.common["Authorization"] = `Bearer ${token}`;
    } else {
      delete api.defaults.headers.common["Authorization"];
    }
  }, [token]);

  const loadConfig = useCallback(async () => {
    setConfigError(null);
    try {
      const { auth_mode } = await getAuthConfig();
      setAuthMode(auth_mode);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setConfigError(msg || "network error");
      setAuthMode(null);
    }
  }, []);

  useEffect(() => {
    void loadConfig();
  }, [loadConfig]);

  const signIn = useCallback(
    (newToken: string) => {
      applyToken(newToken);
    },
    [applyToken],
  );

  const signOut = useCallback(() => {
    applyToken(null);
  }, [applyToken]);

  const isReady = authMode !== null || configError !== null;

  const isAuthenticated = useMemo(() => {
    if (authMode === "none") {
      return true;
    }
    if (authMode === "password" || authMode === "oidc") {
      return !!token;
    }
    return false;
  }, [authMode, token]);

  return (
    <AuthContext.Provider
      value={{
        token,
        authMode,
        configError,
        isReady,
        isAuthenticated,
        reloadConfig: loadConfig,
        signIn,
        signOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
