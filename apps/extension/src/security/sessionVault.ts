/** Encrypted-only local cache (persistent) and ephemeral MV3 hibernation session state (RAM-only). */

export interface StoredAccountRecord {
  user_id: string;
  server_url: string;
  email: string;
  kdf_params: {
    algorithm: string;
    memory_kib: number;
    iterations: number;
    parallelism: number;
  };
  kdf_salt_b64: string;
  key_version: number;
  encrypted_vault_key_b64: string;
  sync_revision: number;
}

export interface StoredEncryptedEnvelope {
  id: string;
  encrypted_data_b64: string;
  revision: number;
  deleted: boolean;
  updated_at: string;
}

export interface QueuedMutationRecord {
  entity_kind: "folder" | "item";
  entity_id: string;
  op: "upsert" | "delete";
  encrypted_data_b64?: string;
}

export interface EphemeralSessionEnvelope {
  seal_json: string;
  access_token: string;
  refresh_token: string;
  last_activity_ms: number;
}

export interface EncryptedLocalVaultStore {
  account: StoredAccountRecord | null;
  folders: StoredEncryptedEnvelope[];
  items: StoredEncryptedEnvelope[];
  queued_mutations: QueuedMutationRecord[];
  approved_iframe_origins: string[];
}

const LOCAL_STORE_KEY = "anvil_encrypted_vault_v1";
const SESSION_SEAL_KEY = "anvil_ephemeral_session_v1";

export async function loadEncryptedVaultStore(): Promise<EncryptedLocalVaultStore> {
  const result = await chrome.storage.local.get(LOCAL_STORE_KEY);
  const existing = result[LOCAL_STORE_KEY] as Partial<EncryptedLocalVaultStore> | undefined;
  return {
    account: existing?.account ?? null,
    folders: existing?.folders ?? [],
    items: existing?.items ?? [],
    queued_mutations: existing?.queued_mutations ?? [],
    approved_iframe_origins: existing?.approved_iframe_origins ?? [],
  };
}

export async function saveEncryptedVaultStore(store: EncryptedLocalVaultStore): Promise<void> {
  await chrome.storage.local.set({ [LOCAL_STORE_KEY]: store });
}

export async function clearAllExtensionStorage(): Promise<void> {
  await Promise.all([
    chrome.storage.local.remove(LOCAL_STORE_KEY),
    clearEphemeralSession(),
  ]);
}

export async function saveEphemeralSession(envelope: EphemeralSessionEnvelope): Promise<void> {
  if (chrome.storage.session) {
    await chrome.storage.session.set({ [SESSION_SEAL_KEY]: envelope });
  }
}

export async function loadEphemeralSession(): Promise<EphemeralSessionEnvelope | null> {
  if (!chrome.storage.session) {
    return null;
  }
  const result = await chrome.storage.session.get(SESSION_SEAL_KEY);
  return (result[SESSION_SEAL_KEY] as EphemeralSessionEnvelope | undefined) ?? null;
}

export async function clearEphemeralSession(): Promise<void> {
  if (chrome.storage.session) {
    await chrome.storage.session.remove(SESSION_SEAL_KEY);
  }
}
