<script lang="ts">
  import { tokenizePassword } from "../lib/passwordHighlight.js";
  import type { PasswordGenOptionsDto, PasswordStrengthDto } from "../lib/types.js";

  interface Props {
    open: boolean;
    onGenerate: (opts: PasswordGenOptionsDto) => Promise<{ value: string; strength: PasswordStrengthDto }>;
    onCopy: (label: string, value: string) => Promise<void>;
    onClose: () => void;
  }

  let { open, onGenerate, onCopy, onClose }: Props = $props();

  let options = $state<PasswordGenOptionsDto>({
    mode: "password",
    length: 20,
    uppercase: true,
    lowercase: true,
    digits: true,
    symbols: true,
    exclude_ambiguous: false,
    word_count: 5,
    separator: "-",
    capitalize: true,
    include_number: true,
  });

  let preview = $state("");
  let strength = $state<PasswordStrengthDto | null>(null);

  const regenerate = async () => {
    const res = await onGenerate(options);
    preview = res.value;
    strength = res.strength;
  };

  $effect(() => {
    if (open) {
      void regenerate();
    } else {
      preview = "";
      strength = null;
    }
  });

  const segments = $derived(tokenizePassword(preview));
</script>

{#if open}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Générateur de mot de passe">
    <div class="w-full max-w-[480px] rounded-[12px] border border-[var(--border-default)] bg-[var(--bg-elevated)] p-6">
      <div class="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
        <h2 class="text-[18px] font-semibold text-[var(--text-primary)]">Générateur Forge</h2>
        <button type="button" onclick={onClose} class="text-[var(--text-muted)] hover:text-[var(--text-primary)]">✕</button>
      </div>

      <div class="mt-4 flex gap-2 text-[12.5px]">
        <button
          type="button"
          onclick={() => {
            options.mode = "password";
            void regenerate();
          }}
          class="flex-1 rounded-[6px] border py-1.5 font-medium"
          style:border-color={options.mode === "password" ? "var(--accent-forge)" : "var(--border-default)"}
          style:color={options.mode === "password" ? "var(--accent-forge)" : "var(--text-secondary)"}
        >
          Mot de passe aléatoire
        </button>
        <button
          type="button"
          onclick={() => {
            options.mode = "passphrase";
            void regenerate();
          }}
          class="flex-1 rounded-[6px] border py-1.5 font-medium"
          style:border-color={options.mode === "passphrase" ? "var(--accent-forge)" : "var(--border-default)"}
          style:color={options.mode === "passphrase" ? "var(--accent-forge)" : "var(--text-secondary)"}
        >
          Passphrase EFF
        </button>
      </div>

      <div class="mt-4 rounded-[8px] border border-[var(--border-default)] bg-[var(--bg-void)] p-4">
        <div class="anvil-mono-secret anvil-selectable min-h-[44px] text-[15px] leading-relaxed break-all">
          {#each segments as seg}
            <span
              style:color={seg.kind === "digit"
                ? "var(--pw-digit)"
                : seg.kind === "symbol"
                  ? "var(--pw-symbol)"
                  : "var(--pw-alpha)"}
            >
              {seg.text}
            </span>
          {/each}
        </div>
        {#if strength}
          <div class="mt-2 flex items-center justify-between text-[11.5px] text-[var(--text-muted)]">
            <span>Entropie : {Math.round(strength.entropy_bits)} bits</span>
            <span>{strength.crack_time_display}</span>
          </div>
        {/if}
      </div>

      {#if options.mode === "password"}
        <div class="mt-4 space-y-3 text-[12.5px] text-[var(--text-secondary)]">
          <label class="flex items-center justify-between gap-3">
            <span>Longueur ({options.length})</span>
            <input
              type="range"
              min="8"
              max="64"
              bind:value={options.length}
              onchange={() => void regenerate()}
              class="w-48 accent-[var(--accent-forge)]"
            />
          </label>
          <div class="grid grid-cols-2 gap-2">
            <label class="flex items-center gap-2"><input type="checkbox" bind:checked={options.uppercase} onchange={() => void regenerate()} /> Majuscules (A-Z)</label>
            <label class="flex items-center gap-2"><input type="checkbox" bind:checked={options.lowercase} onchange={() => void regenerate()} /> Minuscules (a-z)</label>
            <label class="flex items-center gap-2"><input type="checkbox" bind:checked={options.digits} onchange={() => void regenerate()} /> Chiffres (0-9)</label>
            <label class="flex items-center gap-2"><input type="checkbox" bind:checked={options.symbols} onchange={() => void regenerate()} /> Symboles (!@#)</label>
            <label class="col-span-2 flex items-center gap-2"><input type="checkbox" bind:checked={options.exclude_ambiguous} onchange={() => void regenerate()} /> Exclure caractères ambigus (0/O, 1/l/I)</label>
          </div>
        </div>
      {:else}
        <div class="mt-4 space-y-3 text-[12.5px] text-[var(--text-secondary)]">
          <label class="flex items-center justify-between gap-3">
            <span>Nombre de mots ({options.word_count})</span>
            <input
              type="range"
              min="3"
              max="10"
              bind:value={options.word_count}
              onchange={() => void regenerate()}
              class="w-48 accent-[var(--accent-forge)]"
            />
          </label>
          <div class="grid grid-cols-2 gap-2">
            <label class="flex items-center gap-2"><input type="checkbox" bind:checked={options.capitalize} onchange={() => void regenerate()} /> Capitaliser</label>
            <label class="flex items-center gap-2"><input type="checkbox" bind:checked={options.include_number} onchange={() => void regenerate()} /> Ajouter un chiffre</label>
          </div>
        </div>
      {/if}

      <div class="mt-5 flex justify-end gap-2">
        <button
          type="button"
          onclick={() => void regenerate()}
          class="rounded-[6px] border border-[var(--border-default)] px-3.5 py-1.5 text-[12.5px] text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
        >
          Régénérer
        </button>
        <button
          type="button"
          onclick={() => void onCopy("Mot de passe généré", preview)}
          class="rounded-[6px] bg-[var(--accent-forge)] px-4 py-1.5 text-[12.5px] font-semibold text-[#0B0C0F] hover:bg-[var(--accent-forge-hover)]"
        >
          Copier (auto-clear 30s)
        </button>
      </div>
    </div>
  </div>
{/if}
