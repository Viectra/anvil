import type {
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
} from "./types.js";

/** Transport-neutral bridge implemented natively via Tauri IPC or browser WASM. */
export interface AnvilClientBridge {
  status(): Promise<VaultStatusDto>;
  register(
    serverUrl: string,
    email: string,
    masterPassword: string,
    inviteToken: string | null,
  ): Promise<VaultStatusDto>;
  login(serverUrl: string, email: string, masterPassword: string): Promise<VaultStatusDto>;
  unlockWithPassword(masterPassword: string): Promise<VaultStatusDto>;
  unlockWithBiometric(): Promise<VaultStatusDto>;
  enableBiometric(masterPassword: string): Promise<VaultStatusDto>;
  disableBiometric?(): Promise<VaultStatusDto>;
  logout?(): Promise<VaultStatusDto>;
  changeEmail?(currentPassword: string, newEmail: string): Promise<VaultStatusDto>;
  uploadAvatar?(bytes: number[]): Promise<VaultStatusDto>;
  deleteAvatar?(): Promise<VaultStatusDto>;
  lock(): Promise<VaultStatusDto>;
  listFolders(): Promise<FolderDto[]>;
  saveFolder(name: string, id?: string | null): Promise<FolderDto>;
  deleteFolder(id: string): Promise<void>;
  listItems(query: string, folderId: string | null, favoritesOnly: boolean, trashedOnly: boolean): Promise<ItemSummaryDto[]>;
  getItem(id: string): Promise<ItemDetailDto>;
  saveItem(input: SaveItemInputDto): Promise<ItemDetailDto>;
  deleteItem(id: string): Promise<void>;
  uploadItemLogo(itemId: string, bytes: number[]): Promise<ItemDetailDto>;
  copySecret(label: string, value: string): Promise<ClipboardToastDto>;
  generateTotp(secretOrUri: string, unixTimestampSeconds: number): Promise<TotpCodeDto>;
  generatePassword(options: PasswordGenOptionsDto): Promise<{ value: string; strength: PasswordStrengthDto }>;
  evaluatePassword(value: string): Promise<PasswordStrengthDto>;
  previewImport(format: ImportSourceKind, bytes: number[], backupPassword: string | null): Promise<ImportPreviewDto>;
  executeImport(previewId: string, policy: DuplicatePolicy): Promise<ImportReportDto>;
  exportVault(format: "anvil" | "bitwarden_json" | "csv", masterPassword: string, backupPassword: string | null): Promise<number[]>;
  syncNow(): Promise<SyncReportDto>;
  listConflicts(): Promise<ConflictItemDto[]>;
  resolveConflict(conflictId: string, resolution: ConflictResolutionKind): Promise<SyncReportDto>;
  getWindowChrome?(): Promise<WindowChromeStateDto>;
  minimizeWindow?(): Promise<void>;
  toggleMaximizeWindow?(): Promise<void>;
  closeWindow?(): Promise<void>;
  openExternalUrl?(url: string): Promise<void>;
}

export type NavFilter =
  | { kind: "all" }
  | { kind: "favorites" }
  | { kind: "recents" }
  | { kind: "folder"; folderId: string }
  | { kind: "trash" };

export class VaultStore {
  status = $state<VaultStatusDto>({
    configured: false,
    authenticated: false,
    unlocked: false,
    biometric_available: false,
    biometric_enabled: false,
    server_url: null,
    email: null,
    role: null,
    avatar_data_url: null,
    sync_revision: 0,
    pending_conflicts: 0,
  });

  folders = $state<FolderDto[]>([]);
  items = $state<ItemSummaryDto[]>([]);
  selectedItemId = $state<string | null>(null);
  selectedItem = $state<ItemDetailDto | null>(null);
  conflicts = $state<ConflictItemDto[]>([]);
  navFilter = $state<NavFilter>({ kind: "all" });
  searchQuery = $state("");
  syncing = $state(false);
  busy = $state(false);
  errorMessage = $state<string | null>(null);
  clipboardToast = $state<ClipboardToastDto | null>(null);
  revealSelectedPassword = $state(false);

  folderCounts = $derived.by(() => {
    const counts = new Map<string, number>();
    for (const item of this.items) {
      if (!item.trashed && item.folder_id) {
        counts.set(item.folder_id, (counts.get(item.folder_id) ?? 0) + 1);
      }
    }
    return counts;
  });

  favoriteCount = $derived(
    this.items.filter((item) => !item.trashed && item.favorite).length,
  );

  constructor(readonly bridge: AnvilClientBridge) {}

  async refreshStatus(): Promise<void> {
    this.status = await this.bridge.status();
    if (!this.status.unlocked) {
      this.purgeEphemeralState();
    } else {
      await Promise.all([this.reloadVaultData(), this.reloadConflicts()]);
    }
  }

  /** Clears all decrypted metadata and active item details immediately upon lock. */
  purgeEphemeralState(): void {
    this.items = [];
    this.folders = [];
    this.selectedItem = null;
    this.selectedItemId = null;
    this.conflicts = [];
    this.revealSelectedPassword = false;
    this.searchQuery = "";
  }

  async reloadVaultData(): Promise<void> {
    const folderId = this.navFilter.kind === "folder" ? this.navFilter.folderId : null;
    const favoritesOnly = this.navFilter.kind === "favorites";
    const trashedOnly = this.navFilter.kind === "trash";
    const [folders, items] = await Promise.all([
      this.bridge.listFolders(),
      this.bridge.listItems(this.searchQuery, folderId, favoritesOnly, trashedOnly),
    ]);
    this.folders = folders;
    this.items =
      this.navFilter.kind === "recents"
        ? [...items].sort((a, b) => b.updated_at.localeCompare(a.updated_at)).slice(0, 25)
        : items;

    if (this.selectedItemId) {
      const stillVisible = this.items.some((i) => i.id === this.selectedItemId);
      if (stillVisible) {
        this.selectedItem = await this.bridge.getItem(this.selectedItemId);
      } else {
        this.selectedItemId = null;
        this.selectedItem = null;
      }
    }
    if (!this.selectedItemId && this.items.length > 0) {
      const first = this.items[0];
      if (first) {
        await this.selectItem(first.id);
      }
    }
  }

  async reloadConflicts(): Promise<void> {
    this.conflicts = await this.bridge.listConflicts();
  }

  async selectItem(itemId: string): Promise<void> {
    this.selectedItemId = itemId;
    this.revealSelectedPassword = false;
    this.selectedItem = await this.bridge.getItem(itemId);
  }

  async lockNow(): Promise<void> {
    this.status = await this.bridge.lock();
    this.purgeEphemeralState();
  }

  async syncNow(): Promise<void> {
    if (this.syncing || !this.status.unlocked) {
      return;
    }
    this.syncing = true;
    this.errorMessage = null;
    try {
      await this.bridge.syncNow();
      await this.refreshStatus();
    } catch (err) {
      this.errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      this.syncing = false;
    }
  }

  async copySecret(label: string, value: string): Promise<void> {
    if (!value) {
      return;
    }
    this.clipboardToast = await this.bridge.copySecret(label, value);
  }

  async toggleFavorite(item: ItemDetailDto): Promise<void> {
    const updated = await this.bridge.saveItem({
      id: item.id,
      kind: item.kind,
      title: item.title,
      folder_id: item.folder_id,
      favorite: !item.favorite,
      trashed_at: item.trashed_at,
      login: item.login,
      custom_fields: item.custom_fields,
      notes: item.notes,
    });
    this.selectedItem = updated;
    await this.reloadVaultData();
  }
}
