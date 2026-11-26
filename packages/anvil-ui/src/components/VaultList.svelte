<script lang="ts">
  import type { ItemSummaryDto } from "../lib/types.js";

  interface Props {
    items: ItemSummaryDto[];
    selectedItemId: string | null;
    onSelect: (id: string) => void;
    onNewItem: () => void;
  }

  let { items, selectedItemId, onSelect, onNewItem }: Props = $props();
</script>

<section class="flex h-full w-[280px] shrink-0 flex-col border-r border-[var(--border-subtle)] bg-[var(--bg-surface)]">
  <div class="flex h-[46px] shrink-0 items-center justify-between border-b border-[var(--border-subtle)] px-3.5">
    <span class="text-[11.5px] font-semibold tracking-wider text-[var(--text-secondary)] uppercase">
      Comptes ({items.length})
    </span>
    <button
      type="button"
      onclick={onNewItem}
      title="Nouvelle fiche (Ctrl+N)"
      class="rounded-[6px] bg-[var(--accent-forge)] px-2.5 py-1 text-[12px] font-semibold text-white transition-colors hover:bg-[var(--accent-forge-hover)]"
    >
      + Nouveau
    </button>
  </div>

  <div class="anvil-scroll flex-1 space-y-1 overflow-y-auto p-2">
    {#if items.length === 0}
      <div class="px-3 py-8 text-center text-[12.5px] text-[var(--text-muted)]">
        Aucune fiche dans cette vue.
      </div>
    {/if}

    {#each items as item (item.id)}
      {@const active = item.id === selectedItemId}
      <button
        type="button"
        onclick={() => onSelect(item.id)}
        class="flex w-full items-center gap-3 rounded-[8px] border px-2.5 py-2 text-left transition-colors"
        style:background-color={active ? "var(--bg-active)" : "transparent"}
        style:border-color={active ? "var(--border-focus)" : "transparent"}
      >
        <div
          class="flex h-8 w-8 shrink-0 items-center justify-center rounded-[7px] border border-[var(--border-subtle)] text-[11.5px] font-bold tracking-tight"
          style:background-color="var(--bg-elevated)"
          style:color={item.fallback_color}
        >
          {item.fallback_initials}
        </div>

        <div class="min-w-0 flex-1">
          <div class="flex items-center justify-between gap-1.5">
            <span class="truncate text-[13.5px] font-medium text-[var(--text-primary)]">
              {item.title}
            </span>
            <div class="flex shrink-0 items-center gap-1">
              {#if item.has_totp}
                <span
                  class="rounded bg-[var(--accent-steel-muted)] px-1 py-0.5 text-[10px] font-semibold text-[var(--accent-steel)]"
                >
                  2FA
                </span>
              {/if}
              {#if item.favorite}
                <span class="text-[12px] text-[var(--accent-forge)]" aria-label="Favori">★</span>
              {/if}
            </div>
          </div>
          <div class="truncate text-[12px] text-[var(--text-secondary)]">
            {item.subtitle || (item.kind === "secure_note" ? "Note chiffrée" : "Aucun identifiant")}
          </div>
        </div>
      </button>
    {/each}
  </div>
</section>
