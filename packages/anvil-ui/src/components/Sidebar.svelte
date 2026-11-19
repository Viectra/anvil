<script lang="ts">
  import type { NavFilter } from "../lib/bridge.svelte.js";
  import type { FolderDto } from "../lib/types.js";

  interface Props {
    folders: FolderDto[];
    folderCounts: Map<string, number>;
    totalCount: number;
    favoriteCount: number;
    pendingConflicts: number;
    activeFilter: NavFilter;
    onSelectFilter: (filter: NavFilter) => void;
    onCreateFolder: (name: string) => void;
    onOpenGenerator: () => void;
    onOpenImportExport: () => void;
    onOpenConflicts: () => void;
  }

  let {
    folders,
    folderCounts,
    totalCount,
    favoriteCount,
    pendingConflicts,
    activeFilter,
    onSelectFilter,
    onCreateFolder,
    onOpenGenerator,
    onOpenImportExport,
    onOpenConflicts,
  }: Props = $props();

  let addingFolder = $state(false);
  let newFolderName = $state("");

  const submitFolder = (event: SubmitEvent) => {
    event.preventDefault();
    const trimmed = newFolderName.trim();
    if (!trimmed) return;
    onCreateFolder(trimmed);
    newFolderName = "";
    addingFolder = false;
  };

  const isSelected = (kind: NavFilter["kind"], folderId?: string): boolean => {
    if (activeFilter.kind !== kind) return false;
    if (kind === "folder") return activeFilter.kind === "folder" && activeFilter.folderId === folderId;
    return true;
  };
</script>

<aside class="anvil-scroll flex h-full w-[220px] shrink-0 flex-col justify-between overflow-y-auto border-r border-[var(--border-subtle)] bg-[var(--bg-void)] px-2.5 py-3">
  <div class="space-y-5">
    <section>
      <div class="px-2 pb-1.5 text-[11px] font-semibold tracking-wider text-[var(--text-muted)] uppercase">
        Coffre
      </div>
      <nav class="space-y-0.5">
        <button
          type="button"
          onclick={() => onSelectFilter({ kind: "all" })}
          class="flex w-full items-center justify-between rounded-[6px] px-2.5 py-1.5 text-left text-[13px] transition-colors"
          style:background-color={isSelected("all") ? "var(--accent-forge-muted)" : "transparent"}
          style:color={isSelected("all") ? "var(--accent-forge)" : "var(--text-secondary)"}
        >
          <span>Tous les comptes</span>
          <span class="text-[11px] text-[var(--text-muted)]">{totalCount}</span>
        </button>
        <button
          type="button"
          onclick={() => onSelectFilter({ kind: "favorites" })}
          class="flex w-full items-center justify-between rounded-[6px] px-2.5 py-1.5 text-left text-[13px] transition-colors"
          style:background-color={isSelected("favorites") ? "var(--accent-forge-muted)" : "transparent"}
          style:color={isSelected("favorites") ? "var(--accent-forge)" : "var(--text-secondary)"}
        >
          <span>Favoris</span>
          <span class="text-[11px] text-[var(--text-muted)]">{favoriteCount}</span>
        </button>
        <button
          type="button"
          onclick={() => onSelectFilter({ kind: "recents" })}
          class="flex w-full items-center justify-between rounded-[6px] px-2.5 py-1.5 text-left text-[13px] transition-colors"
          style:background-color={isSelected("recents") ? "var(--accent-forge-muted)" : "transparent"}
          style:color={isSelected("recents") ? "var(--accent-forge)" : "var(--text-secondary)"}
        >
          <span>Récents</span>
        </button>
      </nav>
    </section>

    <section>
      <div class="flex items-center justify-between px-2 pb-1.5">
        <span class="text-[11px] font-semibold tracking-wider text-[var(--text-muted)] uppercase">
          Dossiers
        </span>
        <button
          type="button"
          onclick={() => (addingFolder = !addingFolder)}
          aria-label="Nouveau dossier"
          class="rounded px-1.5 text-[14px] text-[var(--text-muted)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
        >
          +
        </button>
      </div>

      {#if addingFolder}
        <form onsubmit={submitFolder} class="mb-2 px-1">
          <input
            type="text"
            bind:value={newFolderName}
            placeholder="Nom du dossier..."
            class="w-full rounded-[5px] border border-[var(--border-focus)] bg-[var(--bg-surface)] px-2 py-1 text-[12.5px] text-[var(--text-primary)] focus:outline-none"
          />
        </form>
      {/if}

      <nav class="space-y-0.5">
        {#each folders as folder (folder.id)}
          <button
            type="button"
            onclick={() => onSelectFilter({ kind: "folder", folderId: folder.id })}
            class="flex w-full items-center justify-between rounded-[6px] px-2.5 py-1.5 text-left text-[13px] transition-colors"
            style:background-color={isSelected("folder", folder.id)
              ? "var(--accent-forge-muted)"
              : "transparent"}
            style:color={isSelected("folder", folder.id)
              ? "var(--accent-forge)"
              : "var(--text-secondary)"}
          >
            <span class="truncate">{folder.name}</span>
            <span class="text-[11px] text-[var(--text-muted)]">{folderCounts.get(folder.id) ?? 0}</span>
          </button>
        {/each}
      </nav>
    </section>

    <section>
      <div class="px-2 pb-1.5 text-[11px] font-semibold tracking-wider text-[var(--text-muted)] uppercase">
        Système
      </div>
      <nav class="space-y-0.5">
        <button
          type="button"
          onclick={() => onSelectFilter({ kind: "trash" })}
          class="flex w-full items-center justify-between rounded-[6px] px-2.5 py-1.5 text-left text-[13px] transition-colors"
          style:background-color={isSelected("trash") ? "var(--accent-forge-muted)" : "transparent"}
          style:color={isSelected("trash") ? "var(--accent-forge)" : "var(--text-secondary)"}
        >
          <span>Corbeille</span>
        </button>
        <button
          type="button"
          onclick={onOpenGenerator}
          class="flex w-full items-center justify-between rounded-[6px] px-2.5 py-1.5 text-left text-[13px] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
        >
          <span>Générateur</span>
          <span class="anvil-kbd">Ctrl+Shift+G</span>
        </button>
        <button
          type="button"
          onclick={onOpenImportExport}
          class="flex w-full items-center justify-between rounded-[6px] px-2.5 py-1.5 text-left text-[13px] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
        >
          <span>Import / Export</span>
        </button>
        {#if pendingConflicts > 0}
          <button
            type="button"
            onclick={onOpenConflicts}
            class="flex w-full items-center justify-between rounded-[6px] px-2.5 py-1.5 text-left text-[13px] font-medium"
            style:background-color="rgba(229, 169, 60, 0.14)"
            style:color="var(--status-warning)"
          >
            <span>Conflits à résoudre</span>
            <span>{pendingConflicts}</span>
          </button>
        {/if}
      </nav>
    </section>
  </div>
</aside>
