<script lang="ts">
  import { TotpRing, type ItemDetailDto, type TotpCodeDto } from "@anvil/ui";

  interface Props {
    totpItems: ItemDetailDto[];
    generateCode: (secretOrUri: string, unixTimestampSeconds: number) => Promise<TotpCodeDto>;
    onCopy: (label: string, value: string) => Promise<void>;
    onOpenQrAttach: () => void;
  }

  let { totpItems, generateCode, onCopy, onOpenQrAttach }: Props = $props();
</script>

<section class="space-y-3 p-4">
  <div class="flex items-center justify-between">
    <h2 class="text-[15px] font-semibold text-[var(--text-primary)]">
      Codes 2FA en direct ({totpItems.length})
    </h2>
    <button
      type="button"
      onclick={onOpenQrAttach}
      class="min-h-[36px] rounded-[8px] bg-[var(--accent-forge)] px-3 text-[12px] font-semibold text-[#0B0C0F]"
    >
      + Scanner QR
    </button>
  </div>

  {#if totpItems.length === 0}
    <div class="rounded-[10px] border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-6 text-center text-[13px] text-[var(--text-muted)]">
      Aucun compte 2FA configuré. Scannez un QR code `otpauth://totp/...` sur une fiche ou ici.
    </div>
  {:else}
    <div class="space-y-2.5">
      {#each totpItems as entry (entry.id)}
        {#if entry.login?.totp}
          <div class="rounded-[10px] border border-[var(--border-default)] bg-[var(--bg-surface)] p-3.5">
            <div class="mb-2 flex items-center justify-between">
              <div class="min-w-0">
                <div class="truncate text-[14px] font-semibold text-[var(--text-primary)]">
                  {entry.title}
                </div>
                <div class="truncate text-[11.5px] text-[var(--text-muted)]">
                  {entry.login.username || entry.login.email}
                </div>
              </div>
              <span class="rounded bg-[var(--accent-steel-muted)] px-2 py-0.5 text-[10.5px] font-mono text-[var(--accent-steel)]">
                {entry.login.totp.algorithm}
              </span>
            </div>
            <TotpRing
              secretOrUri={entry.login.totp.secret_base32}
              {generateCode}
              onCopy={(code) => void onCopy(`Code TOTP (${entry.title})`, code)}
            />
          </div>
        {/if}
      {/each}
    </div>
  {/if}
</section>
