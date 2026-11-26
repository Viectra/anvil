<script lang="ts">
  import type { WindowChromeStateDto } from "../lib/types.js";

  interface Props {
    chrome: WindowChromeStateDto;
    unlocked: boolean;
    syncing: boolean;
    syncRevision: number;
    pendingConflicts: number;
    searchQuery: string;
    searchInputRef?: HTMLInputElement | null;
    onSearchChange: (value: string) => void;
    onSync: () => void;
    onLock: () => void;
    onMinimize: () => void;
    onToggleMaximize: () => void;
    onClose: () => void;
  }

  let {
    chrome,
    unlocked,
    syncing,
    syncRevision,
    pendingConflicts,
    searchQuery,
    searchInputRef = $bindable(null),
    onSearchChange,
    onSync,
    onLock,
    onMinimize,
    onToggleMaximize,
    onClose,
  }: Props = $props();

  const handleSpacerDblClick = (event: MouseEvent) => {
    const target = event.target as HTMLElement | null;
    if (target?.dataset.tauriDragRegion !== undefined) {
      onToggleMaximize();
    }
  };
</script>

<header
  class="flex h-[40px] w-full shrink-0 items-center justify-between border-b border-[var(--border-subtle)] transition-colors"
  style:background-color={chrome.is_focused ? "var(--bg-void)" : "#0F1116"}
>
  <div
    data-tauri-drag-region
    ondblclick={handleSpacerDblClick}
    role="presentation"
    class="flex h-full items-center gap-3 pr-3 transition-opacity"
    class:opacity-65={!chrome.is_focused}
    style:padding-left={chrome.platform === "macos" ? "76px" : "14px"}
  >
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="28" height="28" fill="none" aria-hidden="true">
      <path d="M22 6H42L54 16V35L32 58L10 35V16L22 6Z" fill="#232329" stroke="#3C3C47" stroke-width="2.4" />
      <path d="M14 25.5H47.5V27.6H41.5L37.5 31V38.2L43.5 43V46H20.5V43L26.5 38.2V31L21.5 27.8L14 25.5Z" fill="#F4F4F7" />
      <path d="M13.5 22.5H48V26H14.5L13.5 22.5Z" fill="#7C6DFA" />
    </svg>
    <span class="text-[16px] font-bold tracking-tight text-[var(--text-primary)]">Anvil</span>

    {#if unlocked}
      <span
        class="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium"
        style:background-color={pendingConflicts > 0 ? "rgba(229, 169, 60, 0.14)" : "var(--accent-steel-muted)"}
        style:color={pendingConflicts > 0 ? "var(--status-warning)" : "var(--accent-steel)"}
      >
        <span
          class="h-1.5 w-1.5 rounded-full"
          style:background-color={syncing
            ? "var(--accent-forge)"
            : pendingConflicts > 0
              ? "var(--status-warning)"
              : "var(--status-secure)"}
        ></span>
        {syncing ? "Sync..." : pendingConflicts > 0 ? `${pendingConflicts} conflit(s)` : `Rev ${syncRevision}`}
      </span>
    {/if}
  </div>

  <div
    data-tauri-drag-region
    ondblclick={handleSpacerDblClick}
    role="presentation"
    class="h-full min-w-[16px] flex-1"
  ></div>

  <div class="mx-2 flex w-full max-w-[420px] items-center">
    {#if unlocked}
      <div class="relative w-full">
        <input
          bind:this={searchInputRef}
          data-anvil-search="true"
          type="text"
          value={searchQuery}
          oninput={(e) => onSearchChange(e.currentTarget.value)}
          placeholder="Rechercher un compte, URL, email..."
          aria-label="Rechercher dans le coffre"
          class="h-[28px] w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] pl-3 pr-14 text-[12.5px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--border-focus)] focus:outline-none"
        />
        <span class="anvil-kbd pointer-events-none absolute right-1.5 top-1/2 -translate-y-1/2">
          Ctrl+K
        </span>
      </div>
    {/if}
  </div>

  <div
    data-tauri-drag-region
    ondblclick={handleSpacerDblClick}
    role="presentation"
    class="h-full min-w-[16px] flex-1"
  ></div>

  <div class="flex h-full items-center transition-opacity" class:opacity-65={!chrome.is_focused}>
    {#if unlocked}
      <button
        type="button"
        onclick={onSync}
        title="Synchroniser maintenant"
        aria-label="Synchroniser"
        class="flex h-[28px] w-[30px] items-center justify-center rounded-[5px] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
      >
        <svg class:animate-spin={syncing} viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 12a9 9 0 1 1-3-6.7L21 8" />
          <path d="M21 3v5h-5" />
        </svg>
      </button>

      <button
        type="button"
        onclick={onLock}
        title="Verrouiller (Ctrl+L)"
        aria-label="Verrouiller le coffre"
        class="mr-2 ml-1 flex h-[28px] w-[30px] items-center justify-center rounded-[5px] text-[var(--text-secondary)] hover:bg-[var(--accent-forge-muted)] hover:text-[var(--accent-forge)]"
      >
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="4" y="11" width="16" height="10" rx="2" />
          <path d="M8 11V7a4 4 0 0 1 8 0v4" />
        </svg>
      </button>
    {/if}

    {#if chrome.platform !== "macos"}
      <button
        type="button"
        onclick={onMinimize}
        aria-label="Réduire"
        class="flex h-[40px] w-[46px] items-center justify-center text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
      >
        <svg viewBox="0 0 12 12" width="11" height="11" stroke="currentColor" stroke-width="1.2">
          <line x1="1" y1="6" x2="11" y2="6" />
        </svg>
      </button>
      <button
        type="button"
        onclick={onToggleMaximize}
        aria-label={chrome.is_maximized ? "Restaurer" : "Agrandir"}
        class="flex h-[40px] w-[46px] items-center justify-center text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
      >
        {#if chrome.is_maximized}
          <svg viewBox="0 0 12 12" width="11" height="11" fill="none" stroke="currentColor" stroke-width="1.2">
            <rect x="3" y="1" width="8" height="8" />
            <path d="M1 3v8h8" />
          </svg>
        {:else}
          <svg viewBox="0 0 12 12" width="11" height="11" fill="none" stroke="currentColor" stroke-width="1.2">
            <rect x="1.5" y="1.5" width="9" height="9" />
          </svg>
        {/if}
      </button>
      <button
        type="button"
        onclick={onClose}
        aria-label="Fermer"
        class="flex h-[40px] w-[46px] items-center justify-center text-[var(--text-secondary)] hover:bg-[var(--status-danger)] hover:text-white"
      >
        <svg viewBox="0 0 12 12" width="11" height="11" stroke="currentColor" stroke-width="1.3">
          <line x1="2" y1="2" x2="10" y2="10" />
          <line x1="10" y1="2" x2="2" y2="10" />
        </svg>
      </button>
    {/if}
  </div>
</header>
