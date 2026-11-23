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
} from "@anvil/ui";
import type {
  ExtensionRequest,
  ExtensionResponse,
  UrlMatchResponseDto,
} from "../shared/messages.js";

function callBackground<T>(req: ExtensionRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(req, (resp: ExtensionResponse<T> | undefined) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!resp) {
        reject(new Error("Aucune réponse du worker d'arrière-plan"));
        return;
      }
      if (!resp.ok) {
        reject(new Error(resp.error));
        return;
      }
      resolve(resp.data);
    });
  });
}

/** `AnvilClientBridge` backed by the MV3 Service Worker & `anvil-wasm` linear memory. */
export class ExtensionAnvilBridge implements AnvilClientBridge {
  status(): Promise<VaultStatusDto> {
    return callBackground<VaultStatusDto>({ type: "anvil:status" });
  }

  register(
    serverUrl: string,
    email: string,
    masterPassword: string,
    inviteToken: string | null,
  ): Promise<VaultStatusDto> {
    return callBackground<VaultStatusDto>({
      type: "anvil:register",
      serverUrl,
      email,
      masterPassword,
      inviteToken,
    });
  }

  login(serverUrl: string, email: string, masterPassword: string): Promise<VaultStatusDto> {
    return callBackground<VaultStatusDto>({
      type: "anvil:login",
      serverUrl,
      email,
      masterPassword,
    });
  }

  unlockWithPassword(masterPassword: string): Promise<VaultStatusDto> {
    return callBackground<VaultStatusDto>({
      type: "anvil:unlock",
      masterPassword,
    });
  }

  unlockWithBiometric(): Promise<VaultStatusDto> {
    return Promise.reject(new Error("Biométrie non disponible dans l'extension navigateur"));
  }

  enableBiometric(_masterPassword: string): Promise<VaultStatusDto> {
    return Promise.reject(new Error("Biométrie non disponible dans l'extension navigateur"));
  }

  lock(): Promise<VaultStatusDto> {
    return callBackground<VaultStatusDto>({ type: "anvil:lock" });
  }

  listFolders(): Promise<FolderDto[]> {
    return callBackground<FolderDto[]>({ type: "anvil:list-folders" });
  }

  saveFolder(name: string, id: string | null = null): Promise<FolderDto> {
    return callBackground<FolderDto>({ type: "anvil:save-folder", id, name });
  }

  deleteFolder(id: string): Promise<void> {
    return callBackground<void>({ type: "anvil:delete-folder", id });
  }

  listItems(
    query: string,
    folderId: string | null,
    favoritesOnly: boolean,
    trashedOnly: boolean,
  ): Promise<ItemSummaryDto[]> {
    return callBackground<ItemSummaryDto[]>({
      type: "anvil:list-items",
      query,
      folderId,
      favoritesOnly,
      trashedOnly,
    });
  }

  getItem(id: string): Promise<ItemDetailDto> {
    return callBackground<ItemDetailDto>({ type: "anvil:get-item", id });
  }

  saveItem(input: SaveItemInputDto): Promise<ItemDetailDto> {
    return callBackground<ItemDetailDto>({ type: "anvil:save-item", input });
  }

  deleteItem(id: string): Promise<void> {
    return callBackground<void>({ type: "anvil:delete-item", id });
  }

  uploadItemLogo(_itemId: string, _bytes: number[]): Promise<ItemDetailDto> {
    return Promise.reject(new Error("Import de logo personnalisé réservé à l'application Desktop"));
  }

  async copySecret(label: string, value: string): Promise<ClipboardToastDto> {
    await navigator.clipboard.writeText(value);
    const clearAfterSeconds = 30;
    const expiresAtMs = Date.now() + clearAfterSeconds * 1000;
    window.setTimeout(() => {
      void navigator.clipboard.readText().then((cur) => {
        if (cur === value) {
          return navigator.clipboard.writeText("");
        }
        return undefined;
      }).catch(() => {});
    }, clearAfterSeconds * 1000);
    return {
      label,
      clear_after_seconds: clearAfterSeconds,
      expires_at_ms: expiresAtMs,
    };
  }

  generateTotp(secretOrUri: string, unixTimestampSeconds: number): Promise<TotpCodeDto> {
    return callBackground<TotpCodeDto>({
      type: "anvil:generate-totp",
      secretOrUri,
      unixTimestampSeconds,
    });
  }

  generatePassword(
    options: PasswordGenOptionsDto,
  ): Promise<{ value: string; strength: PasswordStrengthDto }> {
    return callBackground<{ value: string; strength: PasswordStrengthDto }>({
      type: "anvil:generate-password",
      options,
    });
  }

  evaluatePassword(value: string): Promise<PasswordStrengthDto> {
    return callBackground<PasswordStrengthDto>({ type: "anvil:evaluate-password", value });
  }

  previewImport(
    _format: ImportSourceKind,
    _bytes: number[],
    _backupPassword: string | null,
  ): Promise<ImportPreviewDto> {
    return Promise.reject(new Error("Utilisez l'application Anvil Desktop pour l'import complet"));
  }

  executeImport(_previewId: string, _policy: DuplicatePolicy): Promise<ImportReportDto> {
    return Promise.reject(new Error("Utilisez l'application Anvil Desktop pour l'import complet"));
  }

  exportVault(): Promise<number[]> {
    return Promise.reject(new Error("Utilisez l'application Anvil Desktop pour l'export complet"));
  }

  syncNow(): Promise<SyncReportDto> {
    return callBackground<SyncReportDto>({ type: "anvil:sync" });
  }

  listConflicts(): Promise<ConflictItemDto[]> {
    return Promise.resolve([]);
  }

  resolveConflict(
    _conflictId: string,
    _resolution: ConflictResolutionKind,
  ): Promise<SyncReportDto> {
    return this.syncNow();
  }

  async getActiveTabMatches(): Promise<{ url: string; match: UrlMatchResponseDto } | null> {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tabs[0]?.url;
    if (!url) return null;
    const match = await callBackground<UrlMatchResponseDto>({
      type: "anvil:match-tab-url",
      topFrameUrl: url,
      activeFrameUrl: url,
      isIframe: false,
    });
    return { url, match };
  }

  fillActiveTab(itemId: string): Promise<boolean> {
    return callBackground<boolean>({ type: "anvil:fill-active-tab", itemId });
  }
}
