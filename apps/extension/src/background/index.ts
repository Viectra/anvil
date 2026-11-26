import type {
  FolderDto,
  ItemDetailDto,
  ItemSummaryDto,
  PasswordGenOptionsDto,
  PasswordStrengthDto,
  SaveItemInputDto,
  SyncReportDto,
  TotpCodeDto,
  VaultStatusDto,
} from "@anvil/ui";
import { normalizeHttpOrigin } from "../security/phishingGuard.js";
import {
  clearEphemeralSession,
  loadEncryptedVaultStore,
  loadEphemeralSession,
  saveEncryptedVaultStore,
  saveEphemeralSession,
  type EncryptedLocalVaultStore,
  type StoredAccountRecord,
  type StoredEncryptedEnvelope,
} from "../security/sessionVault.js";
import type {
  AutofillCredentialDto,
  CapturedSubmissionDto,
  ExtensionRequest,
  ExtensionResponse,
  UrlMatchResponseDto,
} from "../shared/messages.js";
import { ExtensionApiClient, validateServerUrl } from "./apiClient.js";
import { getWasmClient, getWasmModule, parseWasmJson, resetWasmClient } from "./wasmLoader.js";

const ALARM_INACTIVITY_CHECK = "anvil_inactivity_check";
const ALARM_PERIODIC_SYNC = "anvil_periodic_sync";
const INACTIVITY_TIMEOUT_MS = 5 * 60 * 1000;
const EPHEMERAL_SEAL_TTL_SECONDS = 300;

let accessTokenMem: string | null = null;
let refreshTokenMem: string | null = null;
let lastActivityMs = Date.now();

function nowUnixSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function buildAccountJson(acct: StoredAccountRecord): string {
  return JSON.stringify({
    user_id: acct.user_id,
    email: acct.email,
    kdf_params: acct.kdf_params,
    kdf_salt_b64: acct.kdf_salt_b64,
    key_version: acct.key_version,
    encrypted_vault_key_b64: acct.encrypted_vault_key_b64,
  });
}

async function persistEphemeralResumeState(): Promise<void> {
  const { client } = await getWasmClient();
  if (!client.is_unlocked()) {
    return;
  }
  const sealJson = client.export_ephemeral_session(EPHEMERAL_SEAL_TTL_SECONDS, nowUnixSeconds());
  await saveEphemeralSession({
    seal_json: sealJson,
    access_token: accessTokenMem ?? "",
    refresh_token: refreshTokenMem ?? "",
    last_activity_ms: lastActivityMs,
  });
}

async function ensureSessionHydrated(store: EncryptedLocalVaultStore): Promise<boolean> {
  const { client } = await getWasmClient();
  if (client.is_unlocked()) {
    return true;
  }
  if (!store.account) {
    return false;
  }
  const sealEnv = await loadEphemeralSession();
  if (!sealEnv) {
    return false;
  }
  if (Date.now() - sealEnv.last_activity_ms > INACTIVITY_TIMEOUT_MS) {
    await clearEphemeralSession();
    return false;
  }
  try {
    client.unlock_with_ephemeral_session(
      buildAccountJson(store.account),
      sealEnv.seal_json,
      nowUnixSeconds(),
      JSON.stringify(store.folders),
      JSON.stringify(store.items),
    );
    accessTokenMem = sealEnv.access_token || null;
    refreshTokenMem = sealEnv.refresh_token || null;
    lastActivityMs = sealEnv.last_activity_ms;
    return true;
  } catch {
    await clearEphemeralSession();
    return false;
  }
}

async function touchActivity(): Promise<void> {
  lastActivityMs = Date.now();
  await persistEphemeralResumeState();
}

async function lockVaultNow(): Promise<void> {
  resetWasmClient();
  accessTokenMem = null;
  refreshTokenMem = null;
  await clearEphemeralSession();
  await updateTabBadgeForActiveTab();
}

function makeApiClient(serverUrl: string): ExtensionApiClient {
  return new ExtensionApiClient(
    serverUrl,
    accessTokenMem,
    refreshTokenMem,
    async (access, refresh) => {
      accessTokenMem = access;
      refreshTokenMem = refresh;
      await persistEphemeralResumeState();
    },
  );
}

async function runSync(store: EncryptedLocalVaultStore): Promise<{
  store: EncryptedLocalVaultStore;
  report: SyncReportDto;
}> {
  if (!store.account) {
    throw new Error("Aucun compte configuré");
  }
  const { client } = await getWasmClient();
  const api = makeApiClient(store.account.server_url);

  let pushedMutations = 0;
  if (store.queued_mutations.length > 0 && accessTokenMem) {
    const pushRes = await api.pushSync({
      base_revision: store.account.sync_revision,
      folders_upsert: store.queued_mutations
        .filter((m) => m.entity_kind === "folder" && m.op === "upsert" && m.encrypted_data_b64)
        .map((m) => ({ id: m.entity_id, encrypted_data_b64: m.encrypted_data_b64 ?? "" })),
      folders_delete_ids: store.queued_mutations
        .filter((m) => m.entity_kind === "folder" && m.op === "delete")
        .map((m) => m.entity_id),
      items_upsert: store.queued_mutations
        .filter((m) => m.entity_kind === "item" && m.op === "upsert" && m.encrypted_data_b64)
        .map((m) => ({ id: m.entity_id, encrypted_data_b64: m.encrypted_data_b64 ?? "" })),
      items_delete_ids: store.queued_mutations
        .filter((m) => m.entity_kind === "item" && m.op === "delete")
        .map((m) => m.entity_id),
    });

    if (pushRes.outcome === "committed") {
      pushedMutations = store.queued_mutations.length;
      store.queued_mutations = [];
      store.account.sync_revision = pushRes.new_revision;
    }
  }

  let currentRevision = store.account.sync_revision;
  if (accessTokenMem) {
    const delta = await api.pullSync(store.account.sync_revision);
    store.folders = mergeEnvelopes(store.folders, delta.folders);
    store.items = mergeEnvelopes(store.items, delta.items);
    store.account.key_version = delta.key_version;
    store.account.encrypted_vault_key_b64 = delta.encrypted_vault_key_b64;
    store.account.sync_revision = delta.current_revision;
    currentRevision = delta.current_revision;
    if (client.is_unlocked()) {
      client.apply_sync_delta(JSON.stringify(delta.folders), JSON.stringify(delta.items));
    }
  }

  await saveEncryptedVaultStore(store);
  await persistEphemeralResumeState();

  return {
    store,
    report: {
      current_revision: currentRevision,
      pushed_mutations: pushedMutations,
      auto_merged_identical: 0,
      pending_conflicts: 0,
    },
  };
}

function mergeEnvelopes(
  existing: StoredEncryptedEnvelope[],
  incoming: StoredEncryptedEnvelope[],
): StoredEncryptedEnvelope[] {
  const map = new Map(existing.map((e) => [e.id, e]));
  for (const record of incoming) {
    if (record.deleted) {
      map.delete(record.id);
    } else {
      map.set(record.id, record);
    }
  }
  return Array.from(map.values());
}

async function getStatusDto(): Promise<VaultStatusDto> {
  const store = await loadEncryptedVaultStore();
  const unlocked = await ensureSessionHydrated(store);
  return {
    configured: store.account !== null,
    authenticated: accessTokenMem !== null,
    unlocked,
    biometric_available: false,
    biometric_enabled: false,
    server_url: store.account?.server_url ?? null,
    email: store.account?.email ?? null,
    role: store.account?.role ?? null,
    avatar_data_url: null,
    sync_revision: store.account?.sync_revision ?? 0,
    pending_conflicts: 0,
  };
}

async function updateTabBadgeForTab(tabId: number, url?: string): Promise<void> {
  try {
    const store = await loadEncryptedVaultStore();
    const unlocked = await ensureSessionHydrated(store);
    if (!unlocked) {
      await chrome.action.setBadgeText({ tabId, text: "" });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#1F2430" });
      return;
    }
    if (!url) {
      await chrome.action.setBadgeText({ tabId, text: "" });
      return;
    }
    const { client } = await getWasmClient();
    const res = parseWasmJson<UrlMatchResponseDto>(
      client.match_items_for_url(
        url,
        url,
        false,
        JSON.stringify(store.approved_iframe_origins),
      ),
    );
    if (!res.security.allowed) {
      await chrome.action.setBadgeText({ tabId, text: "!" });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: "#E04F5F" });
      return;
    }
    const count = res.items.length;
    await chrome.action.setBadgeText({ tabId, text: count > 0 ? String(count) : "" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#E07A2F" });
  } catch {
    // Non-fatal on privileged chrome:// or about: pages.
  }
}

async function updateTabBadgeForActiveTab(): Promise<void> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const active = tabs[0];
  if (active?.id !== undefined) {
    await updateTabBadgeForTab(active.id, active.url);
  }
}

async function handleRequest(
  req: ExtensionRequest,
  sender: chrome.runtime.MessageSender,
): Promise<unknown> {
  const store = await loadEncryptedVaultStore();

  switch (req.type) {
    case "anvil:status":
      return getStatusDto();

    case "anvil:register": {
      const serverUrl = validateServerUrl(req.serverUrl);
      const mod = await getWasmModule();
      const api = makeApiClient(serverUrl);
      const defaultKdf = {
        algorithm: "argon2id",
        memory_kib: 65536,
        iterations: 3,
        parallelism: 1,
      };
      const prep = parseWasmJson<{
        user_id: string;
        email: string;
        kdf_params: StoredAccountRecord["kdf_params"];
        kdf_salt_b64: string;
        master_auth_hash_b64: string;
        encrypted_vault_key_b64: string;
      }>(mod.prepare_registration_wasm(req.email, req.masterPassword, JSON.stringify(defaultKdf)));

      const regRes = await api.register({
        user_id: prep.user_id,
        email: prep.email,
        kdf_params: prep.kdf_params,
        kdf_salt_b64: prep.kdf_salt_b64,
        master_auth_hash_b64: prep.master_auth_hash_b64,
        encrypted_vault_key_b64: prep.encrypted_vault_key_b64,
        invite_token: req.inviteToken,
        device_name: "Anvil Browser Extension",
        device_platform: "browser_mv3",
      });

      const nextStore: EncryptedLocalVaultStore = {
        account: {
          user_id: regRes.user.user_id,
          server_url: serverUrl,
          email: regRes.user.email,
          kdf_params: regRes.user.kdf_params,
          kdf_salt_b64: prep.kdf_salt_b64,
          key_version: regRes.user.key_version,
          encrypted_vault_key_b64: prep.encrypted_vault_key_b64,
          sync_revision: regRes.user.sync_revision,
        },
        folders: [],
        items: [],
        queued_mutations: [],
        approved_iframe_origins: [],
      };
      await saveEncryptedVaultStore(nextStore);

      const { client } = await getWasmClient();
      client.unlock_with_password(
        buildAccountJson(nextStore.account!),
        req.masterPassword,
        "[]",
        "[]",
      );
      lastActivityMs = Date.now();
      await persistEphemeralResumeState();
      await updateTabBadgeForActiveTab();
      return getStatusDto();
    }

    case "anvil:login": {
      const serverUrl = validateServerUrl(req.serverUrl);
      const mod = await getWasmModule();
      const api = makeApiClient(serverUrl);
      const pre = await api.prelogin(req.email.trim().toLowerCase());
      const kdfParams = {
        algorithm: pre.kdf_algorithm,
        memory_kib: pre.kdf_memory_kib,
        iterations: pre.kdf_iterations,
        parallelism: pre.kdf_parallelism,
      };
      const auth = parseWasmJson<{ master_auth_hash_b64: string }>(
        mod.derive_login_auth_wasm(req.masterPassword, pre.kdf_salt_b64, JSON.stringify(kdfParams)),
      );
      const loginRes = await api.login(req.email.trim().toLowerCase(), auth.master_auth_hash_b64);

      const nextStore: EncryptedLocalVaultStore = {
        account: {
          user_id: loginRes.user_id,
          server_url: serverUrl,
          email: loginRes.email,
          kdf_params: kdfParams,
          kdf_salt_b64: pre.kdf_salt_b64,
          key_version: loginRes.key_version,
          encrypted_vault_key_b64: loginRes.encrypted_vault_key_b64,
          sync_revision: 0,
        },
        folders: [],
        items: [],
        queued_mutations: [],
        approved_iframe_origins: store.approved_iframe_origins,
      };
      const { store: syncedStore } = await runSync(nextStore);
      const { client } = await getWasmClient();
      client.unlock_with_password(
        buildAccountJson(syncedStore.account!),
        req.masterPassword,
        JSON.stringify(syncedStore.folders),
        JSON.stringify(syncedStore.items),
      );
      lastActivityMs = Date.now();
      await persistEphemeralResumeState();
      await updateTabBadgeForActiveTab();
      return getStatusDto();
    }

    case "anvil:unlock": {
      if (!store.account) {
        throw new Error("Aucun coffre local configuré");
      }
      const { client } = await getWasmClient();
      client.unlock_with_password(
        buildAccountJson(store.account),
        req.masterPassword,
        JSON.stringify(store.folders),
        JSON.stringify(store.items),
      );
      lastActivityMs = Date.now();
      await persistEphemeralResumeState();
      await updateTabBadgeForActiveTab();
      return getStatusDto();
    }

    case "anvil:lock": {
      await lockVaultNow();
      return getStatusDto();
    }

    case "anvil:sync": {
      await ensureSessionHydrated(store);
      const { report } = await runSync(store);
      await updateTabBadgeForActiveTab();
      return report;
    }

    case "anvil:list-folders": {
      const ok = await ensureSessionHydrated(store);
      if (!ok) throw new Error("Coffre verrouillé");
      const { client } = await getWasmClient();
      await touchActivity();
      return parseWasmJson<FolderDto[]>(client.list_folders());
    }

    case "anvil:save-folder": {
      const ok = await ensureSessionHydrated(store);
      if (!ok) throw new Error("Coffre verrouillé");
      const { client } = await getWasmClient();
      const out = parseWasmJson<{ folder: FolderDto; envelope: StoredEncryptedEnvelope }>(
        client.encrypt_folder_upsert(req.id, req.name),
      );
      store.folders = mergeEnvelopes(store.folders, [out.envelope]);
      store.queued_mutations.push({
        entity_kind: "folder",
        entity_id: out.envelope.id,
        op: "upsert",
        encrypted_data_b64: out.envelope.encrypted_data_b64,
      });
      await saveEncryptedVaultStore(store);
      await touchActivity();
      return out.folder;
    }

    case "anvil:delete-folder": {
      const ok = await ensureSessionHydrated(store);
      if (!ok) throw new Error("Coffre verrouillé");
      const { client } = await getWasmClient();
      const removedId = client.remove_folder_local(req.id);
      store.folders = store.folders.filter((f) => f.id !== removedId);
      store.queued_mutations.push({
        entity_kind: "folder",
        entity_id: removedId,
        op: "delete",
      });
      await saveEncryptedVaultStore(store);
      await touchActivity();
      return null;
    }

    case "anvil:list-items": {
      const ok = await ensureSessionHydrated(store);
      if (!ok) throw new Error("Coffre verrouillé");
      const { client } = await getWasmClient();
      await touchActivity();
      return parseWasmJson<ItemSummaryDto[]>(
        client.search_items(req.query, req.folderId, req.favoritesOnly, req.trashedOnly),
      );
    }

    case "anvil:get-item": {
      const ok = await ensureSessionHydrated(store);
      if (!ok) throw new Error("Coffre verrouillé");
      const { client } = await getWasmClient();
      await touchActivity();
      return parseWasmJson<ItemDetailDto>(client.get_item_detail(req.id));
    }

    case "anvil:save-item": {
      const ok = await ensureSessionHydrated(store);
      if (!ok) throw new Error("Coffre verrouillé");
      const { client } = await getWasmClient();
      const out = parseWasmJson<{ item: ItemDetailDto; envelope: StoredEncryptedEnvelope }>(
        client.encrypt_item_upsert(JSON.stringify(req.input)),
      );
      store.items = mergeEnvelopes(store.items, [out.envelope]);
      store.queued_mutations.push({
        entity_kind: "item",
        entity_id: out.envelope.id,
        op: "upsert",
        encrypted_data_b64: out.envelope.encrypted_data_b64,
      });
      await saveEncryptedVaultStore(store);
      await touchActivity();
      await updateTabBadgeForActiveTab();
      return out.item;
    }

    case "anvil:delete-item": {
      const ok = await ensureSessionHydrated(store);
      if (!ok) throw new Error("Coffre verrouillé");
      const { client } = await getWasmClient();
      const removedId = client.remove_item_local(req.id);
      store.items = store.items.filter((i) => i.id !== removedId);
      store.queued_mutations.push({
        entity_kind: "item",
        entity_id: removedId,
        op: "delete",
      });
      await saveEncryptedVaultStore(store);
      await touchActivity();
      await updateTabBadgeForActiveTab();
      return null;
    }

    case "anvil:generate-totp": {
      const ok = await ensureSessionHydrated(store);
      if (!ok) throw new Error("Coffre verrouillé");
      const { client } = await getWasmClient();
      return parseWasmJson<TotpCodeDto>(
        client.generate_totp(req.secretOrUri, req.unixTimestampSeconds),
      );
    }

    case "anvil:generate-password": {
      const mod = await getWasmModule();
      return parseWasmJson<{ value: string; strength: PasswordStrengthDto }>(
        mod.generate_password_wasm(JSON.stringify(req.options as PasswordGenOptionsDto)),
      );
    }

    case "anvil:evaluate-password": {
      const mod = await getWasmModule();
      return parseWasmJson<PasswordStrengthDto>(mod.evaluate_password_wasm(req.value));
    }

    case "anvil:match-tab-url": {
      const unlocked = await ensureSessionHydrated(store);
      const topUrl = sender.tab?.url ?? req.topFrameUrl;
      const frameUrl = sender.url ?? req.activeFrameUrl ?? topUrl;
      const isIframe =
        sender.frameId !== undefined ? sender.frameId !== 0 : req.isIframe;

      if (!unlocked) {
        const mod = await getWasmModule();
        const security = parseWasmJson<UrlMatchResponseDto["security"]>(
          mod.assess_page_security(
            topUrl,
            frameUrl,
            isIframe,
            JSON.stringify(store.approved_iframe_origins),
          ),
        );
        return { security, items: [] } satisfies UrlMatchResponseDto;
      }

      const { client } = await getWasmClient();
      return parseWasmJson<UrlMatchResponseDto>(
        client.match_items_for_url(
          topUrl,
          frameUrl,
          isIframe,
          JSON.stringify(store.approved_iframe_origins),
        ),
      );
    }

    case "anvil:get-autofill-credentials": {
      const unlocked = await ensureSessionHydrated(store);
      if (!unlocked) {
        throw new Error("Coffre verrouillé");
      }
      // Prefer authoritative Chrome sender tab/frame metadata when request comes from content script.
      const topUrl = sender.tab?.url ?? req.topFrameUrl;
      const frameUrl = sender.url ?? req.activeFrameUrl ?? topUrl;
      const isIframe =
        sender.frameId !== undefined ? sender.frameId !== 0 : req.isIframe;

      const { client } = await getWasmClient();
      await touchActivity();
      return parseWasmJson<AutofillCredentialDto>(
        client.get_autofill_credentials(
          req.itemId,
          topUrl,
          frameUrl,
          isIframe,
          JSON.stringify(store.approved_iframe_origins),
          nowUnixSeconds(),
        ),
      );
    }

    case "anvil:approve-iframe-origin": {
      const normalized = normalizeHttpOrigin(req.origin);
      if (!normalized) {
        throw new Error("Origine d'iframe invalide");
      }
      if (!store.approved_iframe_origins.includes(normalized)) {
        store.approved_iframe_origins.push(normalized);
        await saveEncryptedVaultStore(store);
      }
      return true;
    }

    case "anvil:save-captured-credential": {
      const unlocked = await ensureSessionHydrated(store);
      if (!unlocked) {
        throw new Error("Coffre verrouillé");
      }
      return upsertCapturedCredential(store, req.submission);
    }

    case "anvil:fill-active-tab": {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      const activeTab = tabs[0];
      if (!activeTab?.id) {
        throw new Error("Aucun onglet actif détecté");
      }
      await chrome.tabs.sendMessage(
        activeTab.id,
        { type: "anvil:perform-fill", itemId: req.itemId },
        { frameId: 0 },
      );
      return true;
    }
  }
}

async function upsertCapturedCredential(
  store: EncryptedLocalVaultStore,
  submission: CapturedSubmissionDto,
): Promise<ItemDetailDto> {
  const { client } = await getWasmClient();
  const origin = normalizeHttpOrigin(submission.pageUrl);
  if (!origin) {
    throw new Error("Origine HTTP(S) invalide pour l'enregistrement");
  }

  const matched = parseWasmJson<UrlMatchResponseDto>(
    client.match_items_for_url(
      submission.pageUrl,
      submission.pageUrl,
      false,
      JSON.stringify(store.approved_iframe_origins),
    ),
  );
  const normalizedUser = submission.username.trim().toLowerCase();
  const existingSummary = matched.items.find(
    (entry) => entry.subtitle.trim().toLowerCase() === normalizedUser,
  );

  let input: SaveItemInputDto;
  if (existingSummary) {
    const existing = parseWasmJson<ItemDetailDto>(client.get_item_detail(existingSummary.id));
    input = {
      id: existing.id,
      kind: existing.kind,
      title: existing.title,
      folder_id: existing.folder_id,
      favorite: existing.favorite,
      trashed_at: existing.trashed_at,
      login: {
        username: existing.login?.username || submission.username,
        email: existing.login?.email || "",
        password: submission.password,
        password_history: existing.login?.password_history ?? [],
        uris: existing.login?.uris ?? [{ uri: origin, match_mode: "base_domain" }],
        totp: existing.login?.totp ?? null,
      },
      custom_fields: existing.custom_fields,
      notes: existing.notes,
    };
  } else {
    const fallbackTitle = new URL(origin).hostname;
    input = {
      id: null,
      kind: "login",
      title: submission.pageTitle.trim() || fallbackTitle,
      folder_id: null,
      favorite: false,
      trashed_at: null,
      login: {
        username: submission.username.trim(),
        email: submission.username.includes("@") ? submission.username.trim() : "",
        password: submission.password,
        password_history: [],
        uris: [{ uri: origin, match_mode: "base_domain" }],
        totp: null,
      },
      custom_fields: [],
      notes: "",
    };
  }

  const saved = parseWasmJson<{ item: ItemDetailDto; envelope: StoredEncryptedEnvelope }>(
    client.encrypt_item_upsert(JSON.stringify(input)),
  );
  store.items = mergeEnvelopes(store.items, [saved.envelope]);
  store.queued_mutations.push({
    entity_kind: "item",
    entity_id: saved.envelope.id,
    op: "upsert",
    encrypted_data_b64: saved.envelope.encrypted_data_b64,
  });
  await saveEncryptedVaultStore(store);
  await touchActivity();
  if (accessTokenMem) {
    void runSync(store).catch(() => {});
  }
  await updateTabBadgeForActiveTab();
  return saved.item;
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(ALARM_INACTIVITY_CHECK, { periodInMinutes: 1 });
  chrome.alarms.create(ALARM_PERIODIC_SYNC, { periodInMinutes: 5 });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_INACTIVITY_CHECK) {
    if (Date.now() - lastActivityMs > INACTIVITY_TIMEOUT_MS) {
      void lockVaultNow();
    }
  } else if (alarm.name === ALARM_PERIODIC_SYNC) {
    void (async () => {
      const store = await loadEncryptedVaultStore();
      if (store.account && (await ensureSessionHydrated(store))) {
        await runSync(store).catch(() => {});
      }
    })();
  }
});

chrome.idle.onStateChanged.addListener((newState) => {
  if (newState === "locked") {
    void lockVaultNow();
  }
});

chrome.commands.onCommand.addListener((command) => {
  if (command === "lock-vault") {
    void lockVaultNow();
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  void chrome.tabs.get(tabId, (tab) => {
    void updateTabBadgeForTab(tabId, tab.url);
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === "complete") {
    void updateTabBadgeForTab(tabId, tab.url);
  }
});

chrome.runtime.onMessage.addListener(
  (
    message: ExtensionRequest,
    sender: chrome.runtime.MessageSender,
    sendResponse: (resp: ExtensionResponse) => void,
  ) => {
    handleRequest(message, sender)
      .then((data) => sendResponse({ ok: true, data }))
      .catch((err) =>
        sendResponse({
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        }),
      );
    return true;
  },
);
