<script lang="ts">
  import type { ConflictItemDto, ConflictResolutionKind } from "../lib/types.js";

  interface Props {
    open: boolean;
    conflicts: ConflictItemDto[];
    onResolve: (conflictId: string, resolution: ConflictResolutionKind) => Promise<void>;
    onClose: () => void;
  }

  let { open, conflicts, onResolve, onClose }: Props = $props();
</script>

{#if open}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Résolution des conflits de synchronisation">
    <div class="w-full max-w-[680px] rounded-[12px] border border-[var(--border-default)] bg-[var(--bg-elevated)] p-6">
      <div class="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
        <h2 class="text-[18px] font-semibold text-[var(--text-primary)]">
          Conflits de synchronisation ({conflicts.length})
        </h2>
        <button type="button" onclick={onClose} class="text-[var(--text-muted)] hover:text-[var(--text-primary)]">✕</button>
      </div>

      <div class="anvil-scroll mt-4 max-h-[60vh] space-y-3 overflow-y-auto">
        {#if conflicts.length === 0}
          <div class="py-6 text-center text-[13px] text-[var(--text-muted)]">
            Tous les conflits sont résolus.
          </div>
        {/if}

        {#each conflicts as conflict (conflict.conflict_id)}
          <div class="space-y-3 rounded-[8px] border border-[var(--border-default)] bg-[var(--bg-surface)] p-4">
            <div class="flex items-center justify-between">
              <span class="font-semibold text-[var(--text-primary)]">{conflict.title}</span>
              <span class="text-[11.5px] text-[var(--status-warning)]">
                Révision serveur #{conflict.server_revision}
              </span>
            </div>

            <div class="grid grid-cols-2 gap-3 text-[12px]">
              <div class="rounded-[6px] border border-[var(--border-subtle)] bg-[var(--bg-void)] p-2.5">
                <div class="font-semibold text-[var(--accent-forge)]">Version locale</div>
                <div class="mt-1 whitespace-pre-wrap text-[var(--text-secondary)]">
                  {conflict.local_summary}
                </div>
              </div>
              <div class="rounded-[6px] border border-[var(--border-subtle)] bg-[var(--bg-void)] p-2.5">
                <div class="font-semibold text-[var(--accent-steel)]">Version serveur</div>
                <div class="mt-1 whitespace-pre-wrap text-[var(--text-secondary)]">
                  {conflict.server_deleted ? "Supprimée sur le serveur" : conflict.server_summary}
                </div>
              </div>
            </div>

            <div class="flex flex-wrap justify-end gap-2 text-[12px]">
              <button
                type="button"
                onclick={() => void onResolve(conflict.conflict_id, "keep_local")}
                class="rounded-[6px] border border-[var(--accent-forge)] px-3 py-1 text-[var(--accent-forge)] hover:bg-[var(--accent-forge-muted)]"
              >
                Garder locale
              </button>
              <button
                type="button"
                onclick={() => void onResolve(conflict.conflict_id, "keep_server")}
                class="rounded-[6px] border border-[var(--accent-steel)] px-3 py-1 text-[var(--accent-steel)] hover:bg-[var(--accent-steel-muted)]"
              >
                Garder serveur
              </button>
              <button
                type="button"
                onclick={() => void onResolve(conflict.conflict_id, "duplicate_both")}
                class="rounded-[6px] bg-[var(--bg-hover)] px-3 py-1 font-medium text-[var(--text-primary)] hover:bg-[var(--bg-active)]"
              >
                Dupliquer les deux
              </button>
            </div>
          </div>
        {/each}
      </div>
    </div>
  </div>
{/if}
