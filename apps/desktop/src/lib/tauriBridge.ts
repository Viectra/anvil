import type {
  AnvilClientBridge,
  ClipboardToastDto,
  ConflictItemDto,
  ConflictResolutionKind,
  DuplicatePolicy,
  FolderDto,
  ImportPreviewDto,
  ImportReportDto,
  ImportSourceKind,
  ItemDetailDto,
  ItemSummaryDto,
  PasswordGenOptionsDto,
  PasswordStrengthDto,
  SaveItemInputDto,
  SyncReportDto,
  TotpCodeDto,
  VaultStatusDto,
  WindowChromeStateDto,
} from "@anvil/ui";

interface TauriInternals {
  invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
  transformCallback?: (callback: (payload: unknown) => void, once?: boolean) => number;
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: TauriInternals;
  }
}

interface HttpBridgeEnvelope<T> {
  ok: boolean;
  data?: T;
  error?: string;
}

async function invokeIpc<T>(command: string, payload: Record<string, unknown> = {}): Promise<T> {
  const internals = window.__TAURI_INTERNALS__;
  if (internals && typeof internals.invoke === "function") {
    return internals.invoke<T>(command, payload);
  }

  let response: Response;
  try {
    response = await fetch("/api/desktop-ipc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command, payload }),
    });
  } catch {
    throw new Error(
      `Desktop IPC host unreachable for command '${command}' (start anvil-desktop with --http-bridge via scripts/run-desktop.ps1)`,
    );
  }

  let envelope: HttpBridgeEnvelope<T>;
  try {
    envelope = (await response.json()) as HttpBridgeEnvelope<T>;
  } catch {
    throw new Error(`Invalid IPC response from desktop host (HTTP ${response.status})`);
  }

  if (!response.ok || !envelope.ok) {
    throw new Error(envelope.error ?? `Desktop IPC error (HTTP ${response.status})`);
  }

  return envelope.data as T;
}

/** Tauri v2 IPC implementation of `AnvilClientBridge`. */
export class TauriAnvilBridge implements AnvilClientBridge {
  status(): Promise<VaultStatusDto> {
    return invokeIpc<VaultStatusDto>("cmd_status");
  }

  register(
    serverUrl: string,
    email: string,
    masterPassword: string,
    inviteToken: string | null,
  ): Promise<VaultStatusDto> {
    return invokeIpc<VaultStatusDto>("cmd_register", {
      serverUrl,
      email,
      masterPassword,
      inviteToken,
    });
  }

  login(serverUrl: string, email: string, masterPassword: string): Promise<VaultStatusDto> {
    return invokeIpc<VaultStatusDto>("cmd_login", {
      serverUrl,
      email,
      masterPassword,
    });
  }

  unlockWithPassword(masterPassword: string): Promise<VaultStatusDto> {
    return invokeIpc<VaultStatusDto>("cmd_unlock_password", { masterPassword });
  }

  unlockWithBiometric(): Promise<VaultStatusDto> {
    return invokeIpc<VaultStatusDto>("cmd_unlock_biometric");
  }

  enableBiometric(masterPassword: string): Promise<VaultStatusDto> {
    return invokeIpc<VaultStatusDto>("cmd_enable_biometric", { masterPassword });
  }

  lock(): Promise<VaultStatusDto> {
    return invokeIpc<VaultStatusDto>("cmd_lock");
  }

  listFolders(): Promise<FolderDto[]> {
    return invokeIpc<FolderDto[]>("cmd_list_folders");
  }

  saveFolder(name: string, id: string | null = null): Promise<FolderDto> {
    return invokeIpc<FolderDto>("cmd_save_folder", { id, name });
  }

  deleteFolder(id: string): Promise<void> {
    return invokeIpc<void>("cmd_delete_folder", { id });
  }

  listItems(
    query: string,
    folderId: string | null,
    favoritesOnly: boolean,
    trashedOnly: boolean,
  ): Promise<ItemSummaryDto[]> {
    return invokeIpc<ItemSummaryDto[]>("cmd_list_items", {
      query,
      folderId,
      favoritesOnly,
      trashedOnly,
    });
  }

  getItem(id: string): Promise<ItemDetailDto> {
    return invokeIpc<ItemDetailDto>("cmd_get_item", { id });
  }

  saveItem(input: SaveItemInputDto): Promise<ItemDetailDto> {
    return invokeIpc<ItemDetailDto>("cmd_save_item", { input });
  }

  deleteItem(id: string): Promise<void> {
    return invokeIpc<void>("cmd_delete_item", { id });
  }

  uploadItemLogo(itemId: string, bytes: number[]): Promise<ItemDetailDto> {
    return invokeIpc<ItemDetailDto>("cmd_upload_item_logo", { itemId, bytes });
  }

  copySecret(label: string, value: string): Promise<ClipboardToastDto> {
    return invokeIpc<ClipboardToastDto>("cmd_copy_secret", { label, value });
  }

  generateTotp(secretOrUri: string, unixTimestampSeconds: number): Promise<TotpCodeDto> {
    return invokeIpc<TotpCodeDto>("cmd_generate_totp", {
      secretOrUri,
      unixTimestampSeconds,
    });
  }

  generatePassword(
    options: PasswordGenOptionsDto,
  ): Promise<{ value: string; strength: PasswordStrengthDto }> {
    return invokeIpc<{ value: string; strength: PasswordStrengthDto }>("cmd_generate_password", {
      options,
    });
  }

  evaluatePassword(value: string): Promise<PasswordStrengthDto> {
    return invokeIpc<PasswordStrengthDto>("cmd_evaluate_password", { value });
  }

  previewImport(
    format: ImportSourceKind,
    bytes: number[],
    backupPassword: string | null,
  ): Promise<ImportPreviewDto> {
    return invokeIpc<ImportPreviewDto>("cmd_preview_import", {
      format,
      bytes,
      backupPassword,
    });
  }

  executeImport(previewId: string, policy: DuplicatePolicy): Promise<ImportReportDto> {
    return invokeIpc<ImportReportDto>("cmd_execute_import", { previewId, policy });
  }

  exportVault(
    format: "anvil" | "bitwarden_json" | "csv",
    masterPassword: string,
    backupPassword: string | null,
  ): Promise<number[]> {
    return invokeIpc<number[]>("cmd_export_vault", {
      format,
      masterPassword,
      backupPassword,
    });
  }

  syncNow(): Promise<SyncReportDto> {
    return invokeIpc<SyncReportDto>("cmd_sync");
  }

  listConflicts(): Promise<ConflictItemDto[]> {
    return invokeIpc<ConflictItemDto[]>("cmd_list_conflicts");
  }

  resolveConflict(
    conflictId: string,
    resolution: ConflictResolutionKind,
  ): Promise<SyncReportDto> {
    return invokeIpc<SyncReportDto>("cmd_resolve_conflict", {
      conflictId,
      resolution,
    });
  }

  getWindowChrome(): Promise<WindowChromeStateDto> {
    return invokeIpc<WindowChromeStateDto>("cmd_window_chrome");
  }

  minimizeWindow(): Promise<void> {
    return invokeIpc<void>("cmd_window_minimize");
  }

  toggleMaximizeWindow(): Promise<void> {
    return invokeIpc<void>("cmd_window_toggle_maximize");
  }

  closeWindow(): Promise<void> {
    return invokeIpc<void>("cmd_window_close");
  }

  async openExternalUrl(url: string): Promise<void> {
    const validated = await invokeIpc<string>("cmd_open_external_url", { url });
    if (!window.__TAURI_INTERNALS__ && typeof validated === "string" && validated.length > 0) {
      window.open(validated, "_blank", "noopener,noreferrer");
    }
  }
}

export interface DesktopEventHandlers {
  onVaultLocked: () => void;
  onClipboardCleared: () => void;
  onWindowState: (state: WindowChromeStateDto) => void;
}

/** Subscribes to native window & session-lock notifications emitted into the webview. */
export function subscribeDesktopEvents(handlers: DesktopEventHandlers): () => void {
  const lockedListener = () => handlers.onVaultLocked();
  const clipboardListener = () => handlers.onClipboardCleared();
  const windowStateListener = (event: Event) => {
    const detail = (event as CustomEvent<WindowChromeStateDto | undefined>).detail;
    if (detail) {
      handlers.onWindowState(detail);
    }
  };

  window.addEventListener("anvil://vault-locked", lockedListener);
  window.addEventListener("anvil://clipboard-cleared", clipboardListener);
  window.addEventListener("anvil://window-state", windowStateListener);

  const internals = window.__TAURI_INTERNALS__;
  const unlisteners: Array<() => void> = [];
  if (internals && typeof internals.transformCallback === "function") {
    const registerTauriEvent = async (
      eventName: string,
      callback: (payload: unknown) => void,
    ) => {
      try {
        const handlerId = internals.transformCallback?.(callback);
        if (handlerId === undefined) return;
        const eventId = await invokeIpc<number>("plugin:event|listen", {
          event: eventName,
          target: { kind: "Any" },
          handler: handlerId,
        });
        unlisteners.push(() => {
          void invokeIpc("plugin:event|unlisten", { event: eventName, eventId });
        });
      } catch {
        // Standalone dev environments without Tauri event plugin still receive DOM events.
      }
    };

    void registerTauriEvent("anvil://vault-locked", () => handlers.onVaultLocked());
    void registerTauriEvent("anvil://clipboard-cleared", () => handlers.onClipboardCleared());
    void registerTauriEvent("anvil://window-state", (payload) => {
      if (payload && typeof payload === "object") {
        handlers.onWindowState(payload as WindowChromeStateDto);
      }
    });
  }

  return () => {
    window.removeEventListener("anvil://vault-locked", lockedListener);
    window.removeEventListener("anvil://clipboard-cleared", clipboardListener);
    window.removeEventListener("anvil://window-state", windowStateListener);
    for (const unlisten of unlisteners) {
      unlisten();
    }
  };
}
