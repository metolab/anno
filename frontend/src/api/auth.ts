import { api } from "./http";

export type AuthMode = "none" | "password" | "oidc";

export interface AuthConfigRes {
  auth_mode: AuthMode;
}

export async function getAuthConfig(): Promise<AuthConfigRes> {
  const { data } = await api.get<AuthConfigRes>("/api/auth/config");
  return data;
}

export interface LoginRes {
  token: string;
}

export async function login(password: string): Promise<LoginRes> {
  const { data } = await api.post<LoginRes>("/api/login", { password });
  return data;
}
