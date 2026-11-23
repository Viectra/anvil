import { isLoopbackHostname } from "../security/phishingGuard.js";
import type { StoredEncryptedEnvelope } from "../security/sessionVault.js";

export interface PreloginDto {
  kdf_algorithm: string;
  kdf_memory_kib: number;
  kdf_iterations: number;
  kdf_parallelism: number;
  kdf_salt_b64: string;
}

export interface RegisterRequestPayload {
  user_id: string;
  email: string;
  kdf_params: {
    algorithm: string;
    memory_kib: number;
    iterations: number;
    parallelism: number;
  };
  kdf_salt_b64: string;
  master_auth_hash_b64: string;
  encrypted_vault_key_b64: string;
  invite_token?: string | null;
  device_name: string;
  device_platform: string;
}

export interface RegisterResponsePayload {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  user: {
    user_id: string;
    email: string;
    role: string;
    kdf_params: {
      algorithm: string;
      memory_kib: number;
      iterations: number;
      parallelism: number;
    };
    key_version: number;
    sync_revision: number;
  };
}

export interface LoginResponsePayload {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  user_id: string;
  email: string;
  role: string;
  key_version: number;
  encrypted_vault_key_b64: string;
  sync_revision: number;
}

export interface SyncResponsePayload {
  current_revision: number;
  key_version: number;
  encrypted_vault_key_b64: string;
  folders: StoredEncryptedEnvelope[];
  items: StoredEncryptedEnvelope[];
}

export interface SyncPushPayload {
  base_revision: number;
  folders_upsert: Array<{ id: string; encrypted_data_b64: string }>;
  folders_delete_ids: string[];
  items_upsert: Array<{ id: string; encrypted_data_b64: string }>;
  items_delete_ids: string[];
}

export function validateServerUrl(rawUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error("URL de serveur Anvil invalide");
  }
  const isHttps = parsed.protocol === "https:";
  const isLocalHttp = parsed.protocol === "http:" && isLoopbackHostname(parsed.hostname);
  if (!isHttps && !isLocalHttp) {
    throw new Error("Le serveur Anvil distant doit utiliser HTTPS");
  }
  return parsed.origin;
}

/** REST client communicating with self-hosted `anvil-server` with single-flight JWT refresh. */
export class ExtensionApiClient {
  private refreshInFlight: Promise<boolean> | null = null;

  constructor(
    private readonly baseUrl: string,
    private accessToken: string | null = null,
    private refreshToken: string | null = null,
    private readonly onTokensUpdated?: (access: string, refresh: string) => Promise<void>,
  ) {}

  getTokens(): { accessToken: string | null; refreshToken: string | null } {
    return { accessToken: this.accessToken, refreshToken: this.refreshToken };
  }

  async prelogin(email: string): Promise<PreloginDto> {
    return this.request<PreloginDto>("POST", "/api/v1/auth/prelogin", { email }, false);
  }

  async register(payload: RegisterRequestPayload): Promise<RegisterResponsePayload> {
    const res = await this.request<RegisterResponsePayload>(
      "POST",
      "/api/v1/auth/register",
      payload,
      false,
    );
    this.accessToken = res.access_token;
    this.refreshToken = res.refresh_token;
    if (this.onTokensUpdated) {
      await this.onTokensUpdated(res.access_token, res.refresh_token);
    }
    return res;
  }

  async login(email: string, masterAuthHashB64: string): Promise<LoginResponsePayload> {
    const res = await this.request<LoginResponsePayload>(
      "POST",
      "/api/v1/auth/login",
      {
        email,
        master_auth_hash_b64: masterAuthHashB64,
        device_name: "Anvil Browser Extension",
        device_platform: "browser_mv3",
      },
      false,
    );
    this.accessToken = res.access_token;
    this.refreshToken = res.refresh_token;
    if (this.onTokensUpdated) {
      await this.onTokensUpdated(res.access_token, res.refresh_token);
    }
    return res;
  }

  async pullSync(sinceRevision: number): Promise<SyncResponsePayload> {
    return this.request<SyncResponsePayload>(
      "GET",
      `/api/v1/vault/sync?since_revision=${encodeURIComponent(String(sinceRevision))}`,
      undefined,
      true,
    );
  }

  async pushSync(
    payload: SyncPushPayload,
  ): Promise<{ outcome: "committed"; new_revision: number } | { outcome: "conflict"; server: SyncResponsePayload }> {
    const url = `${this.baseUrl}/api/v1/vault/sync`;
    const response = await this.rawFetch("POST", url, payload, true);
    if (response.status === 409) {
      const body = (await response.json()) as { sync?: SyncResponsePayload; error?: { message: string } };
      if (body.sync) {
        return { outcome: "conflict", server: body.sync };
      }
      throw new Error(body.error?.message ?? "Conflit de révision détecté lors de la synchro");
    }
    if (!response.ok) {
      throw new Error(await extractErrorMessage(response));
    }
    const okBody = (await response.json()) as { new_revision: number };
    return { outcome: "committed", new_revision: okBody.new_revision };
  }

  private async request<T>(
    method: string,
    path: string,
    body: unknown,
    authenticated: boolean,
  ): Promise<T> {
    const response = await this.rawFetch(method, `${this.baseUrl}${path}`, body, authenticated);
    if (!response.ok) {
      throw new Error(await extractErrorMessage(response));
    }
    return (await response.json()) as T;
  }

  private async rawFetch(
    method: string,
    url: string,
    body: unknown,
    authenticated: boolean,
  ): Promise<Response> {
    const doFetch = async () => {
      const headers: Record<string, string> = {
        Accept: "application/json",
      };
      if (body !== undefined) {
        headers["Content-Type"] = "application/json";
      }
      if (authenticated && this.accessToken) {
        headers.Authorization = `Bearer ${this.accessToken}`;
      }
      return fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      });
    };

    let response = await doFetch();
    if (authenticated && response.status === 401 && this.refreshToken) {
      const refreshed = await this.singleFlightRefresh();
      if (refreshed) {
        response = await doFetch();
      }
    }
    return response;
  }

  private singleFlightRefresh(): Promise<boolean> {
    if (this.refreshInFlight) {
      return this.refreshInFlight;
    }
    this.refreshInFlight = (async () => {
      try {
        const res = await fetch(`${this.baseUrl}/api/v1/auth/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: this.refreshToken }),
        });
        if (!res.ok) {
          this.accessToken = null;
          this.refreshToken = null;
          return false;
        }
        const data = (await res.json()) as { access_token: string; refresh_token: string };
        this.accessToken = data.access_token;
        this.refreshToken = data.refresh_token;
        if (this.onTokensUpdated) {
          await this.onTokensUpdated(data.access_token, data.refresh_token);
        }
        return true;
      } catch {
        return false;
      } finally {
        this.refreshInFlight = null;
      }
    })();
    return this.refreshInFlight;
  }
}

async function extractErrorMessage(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: { message?: string } };
    return body.error?.message ?? `Erreur HTTP ${response.status}`;
  } catch {
    return `Erreur HTTP ${response.status}`;
  }
}
