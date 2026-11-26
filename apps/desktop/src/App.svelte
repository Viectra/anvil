<script lang="ts">
  import {
    ConflictCompareModal,
    CustomTitlebar,
    ImportWizardModal,
    ItemDetail,
    PasswordGeneratorModal,
    Sidebar,
    UnlockScreen,
    VaultList,
    VaultStore,
    registerKeyboardShortcuts,
    type ConflictResolutionKind,
    type NavFilter,
    type PasswordStrengthDto,
    type SaveItemInputDto,
    type WindowChromeStateDto,
  } from "@anvil/ui";
  import { onMount } from "svelte";
  import { TauriAnvilBridge, subscribeDesktopEvents } from "./lib/tauriBridge.js";

  const bridge = new TauriAnvilBridge();
  const store = new VaultStore(bridge);

  let chrome = $state<WindowChromeStateDto>({
    platform: "windows",
    is_maximized: false,
    is_focused: true,
  });

  let searchInputRef = $state<HTMLInputElement | null>(null);
  let editingNew = $state(false);
  let showGeneratorModal = $state(false);
  let showImportModal = $state(false);
  let showConflictsModal = $state(false);
  let selectedStrength = $state<PasswordStrengthDto | null>(null);
  let clipboardRemainingSec = $state(0);

  const detectPlatform = (): WindowChromeStateDto["platform"] => {
    const ua = navigator.userAgent.toLowerCase();
    if (ua.includes("mac")) return "macos";
    if (ua.includes("linux")) return "linux";
    return "windows";
  };

  const refreshChrome = async () => {
    if (bridge.getWindowChrome) {
      try {
        chrome = await bridge.getWindowChrome();
        return;
      } catch {
        // Fallback when running standalone outside native window host.
      }
    }
    chrome = {
      ...chrome,
      platform: detectPlatform(),
      is_focused: document.hasFocus(),
    };
  };

  $effect(() => {
    const pw = store.selectedItem?.login?.password ?? "";
    if (!pw || !store.status.unlocked) {
      selectedStrength = null;
      return;
    }
    let cancelled = false;
    void bridge.evaluatePassword(pw).then((res) => {
      if (!cancelled) {
        selectedStrength = res;
      }
    });
    return () => {
      cancelled = true;
    };
  });

  $effect(() => {
    const toast = store.clipboardToast;
    if (!toast) {
      clipboardRemainingSec = 0;
      return;
    }
    const updateRemaining = () => {
      const rem = Math.max(0, Math.ceil((toast.expires_at_ms - Date.now()) / 1000));
      clipboardRemainingSec = rem;
      if (rem === 0) {
        store.clipboardToast = null;
      }
    };
    updateRemaining();
    const timer = window.setInterval(updateRemaining, 500);
    return () => window.clearInterval(timer);
  });

  const runAction = async (fn: () => Promise<void>) => {
    store.busy = true;
    store.errorMessage = null;
    try {
      await fn();
    } catch (err) {
      store.errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      store.busy = false;
    }
  };

  const handleSelectFilter = async (filter: NavFilter) => {
    editingNew = false;
    store.navFilter = filter;
    await store.reloadVaultData();
  };

  const handleSearchChange = async (value: string) => {
    store.searchQuery = value;
    if (store.status.unlocked) {
      await store.reloadVaultData();
    }
  };

  const moveSelection = async (delta: -1 | 1) => {
    if (!store.status.unlocked || store.items.length === 0) return;
    const currentIndex = store.items.findIndex((item) => item.id === store.selectedItemId);
    const nextIndex =
      currentIndex < 0
        ? 0
        : Math.max(0, Math.min(store.items.length - 1, currentIndex + delta));
    const nextItem = store.items[nextIndex];
    if (nextItem) {
      editingNew = false;
      await store.selectItem(nextItem.id);
    }
  };

  const handleSaveItem = async (input: SaveItemInputDto) => {
    const saved = await bridge.saveItem(input);
    editingNew = false;
    store.selectedItemId = saved.id;
    store.selectedItem = saved;
    await store.reloadVaultData();
  };

  const handleDeleteItem = async (id: string) => {
    await bridge.deleteItem(id);
    if (store.selectedItemId === id) {
      store.selectedItemId = null;
      store.selectedItem = null;
    }
    await store.reloadVaultData();
  };

  const handleUploadLogo = async (itemId: string, bytes: number[]) => {
    const updated = await bridge.uploadItemLogo(itemId, bytes);
    store.selectedItem = updated;
    await store.reloadVaultData();
  };

  const handleResolveConflict = async (conflictId: string, resolution: ConflictResolutionKind) => {
    await bridge.resolveConflict(conflictId, resolution);
    await store.refreshStatus();
    if (store.conflicts.length === 0) {
      showConflictsModal = false;
    }
  };

  onMount(() => {
    chrome.platform = detectPlatform();
    void refreshChrome();
    void store.refreshStatus().catch((err) => {
      store.errorMessage = err instanceof Error ? err.message : String(err);
    });

    const onFocus = () => {
      chrome = { ...chrome, is_focused: true };
    };
    const onBlur = () => {
      chrome = { ...chrome, is_focused: false };
    };
    const onResize = () => {
      void refreshChrome();
    };

    window.addEventListener("focus", onFocus);
    window.addEventListener("blur", onBlur);
    window.addEventListener("resize", onResize);

    const unsubscribeEvents = subscribeDesktopEvents({
      onVaultLocked: () => {
        editingNew = false;
        showGeneratorModal = false;
        showImportModal = false;
        showConflictsModal = false;
        store.purgeEphemeralState();
        store.status = { ...store.status, unlocked: false };
      },
      onClipboardCleared: () => {
        store.clipboardToast = null;
      },
      onWindowState: (nextChrome) => {
        chrome = nextChrome;
      },
    });

    const unregisterShortcuts = registerKeyboardShortcuts(window, {
      focusSearch: () => {
        searchInputRef?.focus();
        searchInputRef?.select();
      },
      newItem: () => {
        if (store.status.unlocked) {
          editingNew = true;
        }
      },
      copyPassword: () => {
        const pw = store.selectedItem?.login?.password;
        if (store.status.unlocked && pw) {
          void store.copySecret("Mot de passe", pw);
        }
      },
      copyUsername: () => {
        const user =
          store.selectedItem?.login?.username || store.selectedItem?.login?.email;
        if (store.status.unlocked && user) {
          void store.copySecret("Identifiant", user);
        }
      },
      copyTotp: () => {
        const totp = store.selectedItem?.login?.totp?.secret_base32;
        if (store.status.unlocked && totp) {
          void bridge
            .generateTotp(totp, Math.floor(Date.now() / 1000))
            .then((res) => store.copySecret("Code TOTP", res.code));
        }
      },
      lockVault: () => {
        if (store.status.unlocked) {
          editingNew = false;
          void store.lockNow();
        }
      },
      openGenerator: () => {
        if (store.status.unlocked) {
          showGeneratorModal = true;
        }
      },
      moveSelection: (delta) => {
        void moveSelection(delta);
      },
      activateSelection: () => {
        if (store.selectedItem?.login?.password) {
          void store.copySecret("Mot de passe", store.selectedItem.login.password);
        }
      },
      escape: () => {
        showGeneratorModal = false;
        showImportModal = false;
        showConflictsModal = false;
        editingNew = false;
      },
    });

    return () => {
      window.removeEventListener("focus", onFocus);
      window.removeEventListener("blur", onBlur);
      window.removeEventListener("resize", onResize);
      unsubscribeEvents();
      unregisterShortcuts();
    };
  });
</script>

<div
  class="flex h-screen w-screen flex-col overflow-hidden bg-[var(--bg-void)] text-[var(--text-primary)] select-none"
  style:border={chrome.is_maximized ? "none" : "1px solid var(--border-subtle)"}
>
  <CustomTitlebar
    {chrome}
    unlocked={store.status.unlocked}
    syncing={store.syncing}
    syncRevision={store.status.sync_revision}
    pendingConflicts={store.status.pending_conflicts}
    searchQuery={store.searchQuery}
    bind:searchInputRef
    onSearchChange={(value) => void handleSearchChange(value)}
    onSync={() => void store.syncNow()}
    onLock={() => {
      editingNew = false;
      void store.lockNow();
    }}
    onMinimize={() => void bridge.minimizeWindow?.()}
    onToggleMaximize={() => void bridge.toggleMaximizeWindow?.().then(refreshChrome)}
    onClose={() => void bridge.closeWindow?.()}
  />

  {#if store.errorMessage}
    <div class="flex items-center justify-between border-b border-[var(--status-danger)]/40 bg-[var(--status-danger)]/15 px-4 py-1.5 text-[12px] text-[var(--status-danger)]">
      <span>{store.errorMessage}</span>
      <button type="button" onclick={() => (store.errorMessage = null)} class="font-semibold">
        Fermer
      </button>
    </div>
  {/if}

  {#if !store.status.unlocked}
    <UnlockScreen
      status={store.status}
      busy={store.busy}
      errorMessage={store.errorMessage}
      onUnlockPassword={(pw) =>
        runAction(async () => {
          await bridge.unlockWithPassword(pw);
          await store.refreshStatus();
        })}
      onUnlockBiometric={() =>
        runAction(async () => {
          await bridge.unlockWithBiometric();
          await store.refreshStatus();
        })}
      onLogout={() =>
        runAction(async () => {
          await bridge.logout?.();
          await store.refreshStatus();
        })}
      onLogin={(url, email, pw) =>
        runAction(async () => {
          await bridge.login(url, email, pw);
          await store.refreshStatus();
        })}
      onRegister={(url, email, pw, invite) =>
        runAction(async () => {
          await bridge.register(url, email, pw, invite);
          await store.refreshStatus();
        })}
    />
  {:else}
    <main class="flex min-h-0 flex-1 overflow-hidden">
      <Sidebar
        folders={store.folders}
        folderCounts={store.folderCounts}
        totalCount={store.items.filter((item) => !item.trashed).length}
        favoriteCount={store.favoriteCount}
        pendingConflicts={store.conflicts.length}
        activeFilter={store.navFilter}
        userEmail={store.status.email}
        userRole={store.status.role}
        avatarDataUrl={store.status.avatar_data_url}
        onSelectFilter={(filter) => void handleSelectFilter(filter)}
        onCreateFolder={(name) => {
          void bridge.saveFolder(name, null).then(() => store.reloadVaultData());
        }}
        onOpenGenerator={() => (showGeneratorModal = true)}
        onOpenImportExport={() => (showImportModal = true)}
        onOpenConflicts={() => (showConflictsModal = true)}
      />

      <VaultList
        items={store.items}
        selectedItemId={store.selectedItemId}
        onSelect={(id) => {
          editingNew = false;
          void store.selectItem(id);
        }}
        onNewItem={() => (editingNew = true)}
      />

      <ItemDetail
        item={store.selectedItem}
        folders={store.folders}
        {editingNew}
        revealed={store.revealSelectedPassword}
        strength={selectedStrength}
        onToggleReveal={() => (store.revealSelectedPassword = !store.revealSelectedPassword)}
        onToggleFavorite={(item) => void store.toggleFavorite(item)}
        onCopy={(label, value) => void store.copySecret(label, value)}
        onSave={handleSaveItem}
        onDelete={handleDeleteItem}
        onUploadLogo={handleUploadLogo}
        onGenerateTotp={(secretOrUri, ts) => bridge.generateTotp(secretOrUri, ts)}
        onOpenUrl={(url) => void bridge.openExternalUrl?.(url)}
        onCancelNew={() => (editingNew = false)}
      />
    </main>
  {/if}

  {#if store.clipboardToast && clipboardRemainingSec > 0}
    <div class="pointer-events-none fixed right-5 bottom-5 z-40">
      <div class="pointer-events-auto flex items-center gap-3 rounded-[8px] border border-[var(--border-focus)] bg-[var(--bg-elevated)] px-3.5 py-2 text-[12.5px] shadow-lg">
        <span class="h-2 w-2 rounded-full bg-[var(--accent-forge)]"></span>
        <span>
          <strong>{store.clipboardToast.label}</strong> copié — purge dans
          <span class="font-mono font-semibold text-[var(--accent-forge)]">
            {clipboardRemainingSec}s
          </span>
        </span>
      </div>
    </div>
  {/if}

  <PasswordGeneratorModal
    open={showGeneratorModal}
    onGenerate={(opts) => bridge.generatePassword(opts)}
    onCopy={(label, value) => store.copySecret(label, value)}
    onClose={() => (showGeneratorModal = false)}
  />

  <ImportWizardModal
    open={showImportModal}
    onPreviewImport={(fmt, bytes, backupPw) => bridge.previewImport(fmt, bytes, backupPw)}
    onExecuteImport={async (previewId, policy) => {
      const report = await bridge.executeImport(previewId, policy);
      await store.reloadVaultData();
      return report;
    }}
    onExportVault={(fmt, masterPw, backupPw) => bridge.exportVault(fmt, masterPw, backupPw)}
    onClose={() => (showImportModal = false)}
  />

  <ConflictCompareModal
    open={showConflictsModal}
    conflicts={store.conflicts}
    onResolve={handleResolveConflict}
    onClose={() => (showConflictsModal = false)}
  />
</div>
