import { api } from "./http";

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
