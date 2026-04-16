import axios from "axios";

const baseURL = import.meta.env.VITE_API_BASE ?? "";

export const api = axios.create({
  baseURL,
  timeout: 30_000,
});

const TOKEN_KEY = "anno_auth_token";

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

export type ClientDto = {
  id: number;
  name: string;
  status: string;
  connected_at?: string | null;
  remote_addr?: string | null;
  http_proxy_port?: number | null;
  mappings: MappingDto[];
};

export type MappingDto = {
  server_port: number;
  protocol: string;
  target: string;
  active_connections: number;
};

export type StatsDto = {
  clients_online: number;
  clients_total: number;
  mappings_total: number;
  sessions_active: number;
  sessions_tcp: number;
  sessions_udp: number;
  queue_drops_total: number;
  bytes_up_total: number;
  bytes_down_total: number;
};

export async function fetchClients(): Promise<ClientDto[]> {
  const { data } = await api.get<ClientDto[]>("/api/clients");
  return data;
}

export async function fetchStats(): Promise<StatsDto> {
  const { data } = await api.get<StatsDto>("/api/stats");
  return data;
}

export async function addMapping(
  clientId: number,
  body: {
    server_port: number;
    protocol: string;
    target_host: string;
    target_port: number;
  },
) {
  const { data } = await api.post<MappingDto>(`/api/clients/${clientId}/mappings`, body);
  return data;
}

export async function deleteMapping(clientId: number, serverPort: number) {
  await api.delete(`/api/clients/${clientId}/mappings/${serverPort}`);
}

export async function deleteClient(clientId: number) {
  await api.delete(`/api/clients/${clientId}`);
}

export type RegistryEntryDto = {
  name: string;
  key: string;
  description?: string | null;
  created_at: number;
};

export async function fetchRegistry(): Promise<RegistryEntryDto[]> {
  const { data } = await api.get<RegistryEntryDto[]>("/api/registry");
  return data;
}

export async function createRegistryEntry(body: {
  name: string;
  description?: string;
}): Promise<RegistryEntryDto> {
  const { data } = await api.post<RegistryEntryDto>("/api/registry", body);
  return data;
}

export async function updateRegistryEntry(
  name: string,
  body: { description?: string | null },
): Promise<RegistryEntryDto> {
  const { data } = await api.put<RegistryEntryDto>(`/api/registry/${name}`, body);
  return data;
}

export async function deleteRegistryEntry(name: string): Promise<void> {
  await api.delete(`/api/registry/${name}`);
}

export async function regenerateRegistryKey(name: string): Promise<RegistryEntryDto> {
  const { data } = await api.post<RegistryEntryDto>(`/api/registry/${name}/regenerate-key`);
  return data;
}
