import { api } from "./http";

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
  control_port: number;
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
    // Optional for `http_proxy` mappings (server resolves the target
    // dynamically to the client's current local HTTP proxy port).
    target_host?: string;
    target_port?: number;
  },
) {
  const { data } = await api.post<MappingDto>(`/api/clients/${clientId}/mappings`, body);
  return data;
}

export async function deleteMapping(clientId: number, serverPort: number) {
  await api.delete(`/api/clients/${clientId}/mappings/${serverPort}`);
}

export async function disconnectClient(clientId: number) {
  await api.post(`/api/clients/${clientId}/disconnect`);
}
