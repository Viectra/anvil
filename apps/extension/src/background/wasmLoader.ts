import type {
  ImportPreviewDto,
  PasswordGenOptionsDto,
  PasswordStrengthDto,
  SaveItemInputDto,
  TotpCodeDto,
} from "@anvil/ui";
import type {
  AutofillCredentialDto,
  AutofillSecurityVerdictDto,
  UrlMatchResponseDto,
} from "../shared/messages.js";
import type {
  StoredAccountRecord,
  StoredEncryptedEnvelope,
} from "../security/sessionVault.js";

export interface WasmModuleApi {
  default: (input?: unknown) => Promise<unknown>;
  assess_page_security: (
    topFrameUrl: string,
    activeFrameUrl: string,
    isIframe: boolean,
    approvedOriginsJson: string,
  ) => string;
  extract_base_domain_wasm: (rawUrl: string) => string | undefined;
  prepare_registration_wasm: (
    email: string,
    masterPassword: string,
    kdfParamsJson: string,
  ) => string;
  derive_login_auth_wasm: (
    masterPassword: string,
    kdfSaltB64: string,
    kdfParamsJson: string,
  ) => string;
  generate_password_wasm: (optionsJson: string) => string;
  evaluate_password_wasm: (value: string) => string;
  AnvilWasmClient: new () => WasmClientInstance;
}

export interface WasmClientInstance {
  is_unlocked(): boolean;
  lock(): void;
  unlock_with_password(
    accountJson: string,
    masterPassword: string,
    foldersJson: string,
    itemsJson: string,
  ): void;
  export_ephemeral_session(ttlSeconds: bigint | number, nowUnix: bigint | number): string;
  unlock_with_ephemeral_session(
    accountJson: string,
    sealJson: string,
    nowUnix: bigint | number,
    foldersJson: string,
    itemsJson: string,
  ): void;
  apply_sync_delta(foldersJson: string, itemsJson: string): void;
  list_folders(): string;
  encrypt_folder_upsert(id: string | null | undefined, name: string): string;
  encrypt_item_upsert(inputJson: string): string;
  remove_item_local(itemId: string): string;
  remove_folder_local(folderId: string): string;
  search_items(
    query: string,
    folderId: string | null | undefined,
    favoritesOnly: boolean,
    trashedOnly: boolean,
  ): string;
  match_items_for_url(
    topFrameUrl: string,
    activeFrameUrl: string,
    isIframe: boolean,
    approvedOriginsJson: string,
  ): string;
  get_autofill_credentials(
    itemId: string,
    topFrameUrl: string,
    activeFrameUrl: string,
    isIframe: boolean,
    approvedOriginsJson: string,
    unixTimestampSeconds: bigint | number,
  ): string;
  get_item_detail(itemId: string): string;
  generate_totp(secretOrUri: string, unixTimestampSeconds: bigint | number): string;
  preview_import(
    formatJson: string,
    bytes: Uint8Array,
    backupPassword: string | null | undefined,
  ): string;
  execute_import(previewId: string, policyJson: string): string;
  export_vault(
    accountJson: string,
    format: string,
    masterPassword: string,
    backupPassword: string | null | undefined,
  ): Uint8Array;
}

let cachedModulePromise: Promise<WasmModuleApi> | null = null;
let cachedClient: WasmClientInstance | null = null;

/** Dynamically imports and initializes the `anvil-wasm` bundle once per Service Worker lifetime. */
export async function getWasmModule(): Promise<WasmModuleApi> {
  if (!cachedModulePromise) {
    cachedModulePromise = (async () => {
      const wasmModulePath = "../wasm-pkg/anvil_wasm.js";
      const mod = (await import(/* @vite-ignore */ wasmModulePath)) as WasmModuleApi;
      await mod.default();
      return mod;
    })().catch((err) => {
      cachedModulePromise = null;
      throw new Error(
        `Module anvil-wasm introuvable (exécutez wasm-pack build) : ${err instanceof Error ? err.message : String(err)}`,
      );
    });
  }
  return cachedModulePromise;
}

export async function getWasmClient(): Promise<{
  mod: WasmModuleApi;
  client: WasmClientInstance;
}> {
  const mod = await getWasmModule();
  if (!cachedClient) {
    cachedClient = new mod.AnvilWasmClient();
  }
  return { mod, client: cachedClient };
}

export function resetWasmClient(): void {
  if (cachedClient) {
    cachedClient.lock();
  }
}

export function parseWasmJson<T>(raw: string): T {
  return JSON.parse(raw) as T;
}

export type WasmHelperResult = {
  previewImport: ImportPreviewDto;
  totp: TotpCodeDto;
  pw: { value: string; strength: PasswordStrengthDto };
  genOpts: PasswordGenOptionsDto;
  saveInput: SaveItemInputDto;
  verdict: AutofillSecurityVerdictDto;
  urlMatch: UrlMatchResponseDto;
  creds: AutofillCredentialDto;
  acct: StoredAccountRecord;
  envelopes: StoredEncryptedEnvelope[];
};
