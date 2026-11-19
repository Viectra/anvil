<script lang="ts">
  import { tokenizePassword } from "../lib/passwordHighlight.js";
  import type { PasswordStrengthDto } from "../lib/types.js";

  interface Props {
    value: string;
    revealed: boolean;
    strength?: PasswordStrengthDto | null;
    onToggleReveal: () => void;
    onCopy: () => void;
  }

  let { value, revealed, strength = null, onToggleReveal, onCopy }: Props = $props();

  const segments = $derived(revealed ? tokenizePassword(value) : []);

  const segmentColor = (kind: "alpha" | "digit" | "symbol"): string => {
    if (kind === "digit") return "var(--pw-digit)";
    if (kind === "symbol") return "var(--pw-symbol)";
    return "var(--pw-alpha)";
  };

  const strengthLabel = (score: number): { label: string; color: string } => {
    if (score >= 4) return { label: "Excellente", color: "var(--status-secure)" };
    if (score === 3) return { label: "Forte", color: "var(--status-secure)" };
    if (score === 2) return { label: "Moyenne", color: "var(--status-warning)" };
    return { label: "Faible", color: "var(--status-danger)" };
  };
</script>

<div class="rounded-[8px] border border-[var(--border-default)] bg-[var(--bg-elevated)] p-3">
  <div class="flex items-center justify-between gap-2">
    <div class="min-w-0 flex-1 overflow-x-auto">
      {#if revealed}
        <div class="anvil-mono-secret anvil-selectable text-[14px] leading-relaxed break-all">
          {#each segments as seg}
            <span style:color={segmentColor(seg.kind)}>{seg.text}</span>
          {/each}
        </div>
      {:else}
        <div class="anvil-mono-secret text-[14px] tracking-[0.18em] text-[var(--text-secondary)]">
          ••••••••••••••
        </div>
      {/if}
    </div>

    <div class="flex shrink-0 items-center gap-1.5">
      <button
        type="button"
        onclick={onToggleReveal}
        class="rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2.5 py-1 text-[12px] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]"
      >
        {revealed ? "Masquer" : "Afficher"}
      </button>
      <button
        type="button"
        onclick={onCopy}
        class="rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2.5 py-1 text-[12px] text-[var(--text-primary)] hover:border-[var(--accent-forge)] hover:text-[var(--accent-forge)]"
      >
        Copier
      </button>
    </div>
  </div>

  {#if strength}
    {@const info = strengthLabel(strength.score)}
    <div class="mt-2 flex items-center justify-between text-[11.5px] text-[var(--text-muted)]">
      <span>
        Force :
        <span class="font-semibold" style:color={info.color}>{info.label}</span>
        ({Math.round(strength.entropy_bits)} bits)
      </span>
      <span>{strength.crack_time_display}</span>
    </div>
  {/if}
</div>
