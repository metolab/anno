import { api } from "./http";

export interface LoginRes {
  token: string;
}

export async function login(password: string): Promise<LoginRes> {
  const { data } = await api.post<LoginRes>("/api/login", { password });
  return data;
}
