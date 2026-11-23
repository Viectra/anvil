<script lang="ts">
  import type { QrScanResultDto } from "../lib/mobileBridge.js";

  interface Props {
    open: boolean;
    title: string;
    onScanCamera: () => Promise<string>;
    onParsePayload: (raw: string) => Promise<QrScanResultDto>;
    onResolved: (result: QrScanResultDto, raw: string) => Promise<void>;
    onClose: () => void;
  }

  let { open, title, onScanCamera, onParsePayload, onResolved, onClose }: Props = $props();

  let rawInput = $state("");
  let busy = $state(false);
  let errorMsg = $state<string | null>(null);

  const processRaw = async (raw: string) => {
    busy = true;
    errorMsg = null;
    try {
      const parsed = await onParsePayload(raw);
      await onResolved(parsed, raw);
      rawInput = "";
      onClose();
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
    }
  };

  const launchCamera = async () => {
    busy = true;
    errorMsg = null;
    try {
      const scanned = await onScanCamera();
      rawInput = scanned;
      await processRaw(scanned);
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
    }
  };
</script>

{#if open}
  <div class="fixed inset-0 z-50 flex items-end justify-center bg-black/75 sm:items-center sm:p-4" role="dialog" aria-modal="true" aria-label={title}>
    <div class="w-full max-w-[440px] rounded-t-[16px] border border-[var(--border-default)] bg-[var(--bg-elevated)] p-5 sm:rounded-[12px]">
      <div class="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
        <h2 class="text-[16px] font-semibold text-[var(--text-primary)]">{title}</h2>
        <button type="button" onclick={onClose} class="min-h-[36px] min-w-[36px] text-[var(--text-muted)]">✕</button>
      </div>

      <div class="mt-4 space-y-4">
        <button
          type="button"
          onclick={() => void launchCamera()}
          disabled={busy}
          class="flex min-h-[48px] w-full items-center justify-center rounded-[10px] bg-[var(--accent-forge)] px-4 text-[14px] font-semibold text-[#0B0C0F] disabled:opacity-50"
        >
          Scanner avec la caméra
        </button>

        <div class="space-y-1.5">
          <label for="anvil-qr-manual" class="block text-[12px] text-[var(--text-secondary)]">
            Ou coller une URI (`anvil://setup?...` ou `otpauth://totp/...`)
          </label>
          <textarea
            id="anvil-qr-manual"
            bind:value={rawInput}
            rows="3"
            placeholder="otpauth://totp/GitHub:user?secret=..."
            class="w-full rounded-[8px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 font-mono text-[12px] text-[var(--text-primary)] focus:border-[var(--accent-forge)] focus:outline-none"
          ></textarea>
        </div>

        {#if errorMsg}
          <div class="rounded-[6px] border border-[var(--status-danger)]/40 bg-[var(--status-danger)]/15 px-3 py-2 text-[12px] text-[var(--status-danger)]">
            {errorMsg}
          </div>
        {/if}

        <button
          type="button"
          onclick={() => void processRaw(rawInput)}
          disabled={busy || !rawInput.trim()}
          class="min-h-[44px] w-full rounded-[8px] border border-[var(--border-default)] bg-[var(--bg-surface)] text-[13px] font-semibold text-[var(--text-primary)] disabled:opacity-45"
        >
          Valider le QR code
        </button>
      </div>
    </div>
  </div>
{/if}
