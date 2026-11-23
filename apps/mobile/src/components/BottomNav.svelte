<script lang="ts">
  export type MobileTab = "vault" | "totp" | "generator" | "settings";

  interface Props {
    activeTab: MobileTab;
    onSelect: (tab: MobileTab) => void;
  }

  let { activeTab, onSelect }: Props = $props();

  const tabs: Array<{ id: MobileTab; label: string }> = [
    { id: "vault", label: "Coffre" },
    { id: "totp", label: "2FA / TOTP" },
    { id: "generator", label: "Générateur" },
    { id: "settings", label: "Sécurité" },
  ];
</script>

<nav
  aria-label="Navigation principale"
  class="flex shrink-0 items-center justify-around border-t border-[var(--border-subtle)] bg-[var(--bg-void)] px-2 pt-2 pb-[max(0.5rem,env(safe-area-inset-bottom))]"
>
  {#each tabs as tab}
    {@const active = activeTab === tab.id}
    <button
      type="button"
      onclick={() => onSelect(tab.id)}
      class="flex min-h-[44px] flex-1 flex-col items-center justify-center rounded-[8px] px-2 text-[12px] font-medium transition-colors"
      style:color={active ? "var(--accent-forge)" : "var(--text-muted)"}
      style:background-color={active ? "var(--accent-forge-muted)" : "transparent"}
    >
      {tab.label}
    </button>
  {/each}
</nav>
