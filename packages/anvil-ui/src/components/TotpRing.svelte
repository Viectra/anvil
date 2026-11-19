<script lang="ts">
  import type { TotpCodeDto } from "../lib/types.js";

  interface Props {
    secretOrUri: string;
    generateCode: (secretOrUri: string, unixTimestampSeconds: number) => Promise<TotpCodeDto>;
    onCopy: (code: string) => void;
  }

  let { secretOrUri, generateCode, onCopy }: Props = $props();

  let totp = $state<TotpCodeDto>({ code: "------", remaining_seconds: 30, period_seconds: 30 });

  $effect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const next = await generateCode(secretOrUri, Math.floor(Date.now() / 1000));
        if (!cancelled) {
          totp = next;
        }
      } catch {
        if (!cancelled) {
          totp = { code: "------", remaining_seconds: 0, period_seconds: 30 };
        }
      }
    };

    void tick();
    const timer = setInterval(() => {
      void tick();
    }, 1000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  });

  const formattedCode = $derived.by(() => {
    const c = totp.code;
    if (c.length === 6) return `${c.slice(0, 3)} ${c.slice(3)}`;
    if (c.length === 8) return `${c.slice(0, 4)} ${c.slice(4)}`;
    return c;
  });

  const isLow = $derived(totp.remaining_seconds > 0 && totp.remaining_seconds <= 5);
  const progressRatio = $derived(
    totp.period_seconds > 0 ? totp.remaining_seconds / totp.period_seconds : 0,
  );
  const circumference = 2 * Math.PI * 13;
  const dashOffset = $derived(circumference * (1 - progressRatio));
</script>

<div class="flex items-center justify-between rounded-[8px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-3.5 py-2.5">
  <div class="flex items-center gap-3">
    <svg viewBox="0 0 34 34" width="34" height="34" class="-rotate-90" aria-hidden="true">
      <circle cx="17" cy="17" r="13" fill="none" stroke="var(--border-subtle)" stroke-width="3" />
      <circle
        cx="17"
        cy="17"
        r="13"
        fill="none"
        stroke={isLow ? "var(--status-warning)" : "var(--accent-forge)"}
        stroke-width="3"
        stroke-linecap="round"
        stroke-dasharray={circumference}
        stroke-dashoffset={dashOffset}
      />
    </svg>
    <div>
      <div
        class="anvil-mono-secret anvil-selectable text-[24px] leading-none font-bold tracking-[0.12em]"
        style:color={isLow ? "var(--status-warning)" : "var(--text-primary)"}
      >
        {formattedCode}
      </div>
      <div class="mt-1 text-[11px] text-[var(--text-muted)]">
        Expire dans {totp.remaining_seconds}s
      </div>
    </div>
  </div>

  <button
    type="button"
    onclick={() => onCopy(totp.code)}
    class="rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-1.5 text-[12px] font-medium text-[var(--text-primary)] hover:border-[var(--accent-forge)] hover:text-[var(--accent-forge)]"
  >
    Copier 2FA
  </button>
</div>
