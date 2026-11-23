<script lang="ts">
  import {
    PasswordField,
    PasswordGeneratorModal,
    TotpRing,
    UnlockScreen,
    VaultStore,
    registerKeyboardShortcuts,
    type PasswordStrengthDto,
  } from "@anvil/ui";
  import { onMount } from "svelte";
  import type { UrlMatchResponseDto } from "../shared/messages.js";
  import { ExtensionAnvilBridge } from "./extensionBridge.js";

  const bridge = new ExtensionAnvilBridge();
  const store = new VaultStore(bridge);

  let activeTabUrl = $state("");
  let tabMatch = $state<UrlMatchResponseDto | null>(null);
  let selectedStrength = $state<PasswordStrengthDto | null>(null);
  let showGenerator = $state(false);
  let searchInputEl = $state<HTMLInputElement | null>(null);

  const refreshActiveTab = async () => {
    try {
      const res = await bridge.getActiveTabMatches();
      if (res) {
        activeTabUrl = res.url;
        tabMatch = res.match;
      } else {
        activeTabUrl = "";
        tabMatch = null;
      }
    } catch {
      tabMatch = null;
    }
  };

  $effect(() => {
    const pw = store.selectedItem?.login?.password ?? "";
    if (!pw || !store.status.unlocked) {
      selectedStrength = null;
      return;
    }
    let cancelled = false;
    void bridge.evaluatePassword(pw).then((strength) => {
      if (!cancelled) {
        selectedStrength = strength;
      }
    });
    return () => {
      cancelled = true;
    };
  });

  const handleSearch = async (value: string) => {
    store.searchQuery = value;
    if (store.status.unlocked) {
      await store.reloadVaultData();
    }
  };

  const runAction = async (fn: () => Promise<void>) => {
    store.busy = true;
    store.errorMessage = null;
    try {
      await fn();
      await refreshActiveTab();
    } catch (err) {
      store.errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      store.busy = false;
    }
  };

  const securityBadgeText = (): { label: string; tone: string } => {
    const sec = tabMatch?.security;
    if (!sec) return { label: "Onglet courant", tone: "text-[var(--text-muted)]" };
    if (!sec.allowed) return { label: sec.reasons[0] ?? "Domaine bloqué", tone: "text-[var(--status-danger)]" };
    if (sec.risk_level === "warn_http") return { label: "HTTP non chiffré", tone: "text-[var(--status-warning)]" };
    return {
      label: sec.registrable_domain ?? sec.host ?? "Site vérifié",
      tone: "text-[var(--status-secure)]",
    };
  };

  onMount(() => {
    void store
      .refreshStatus()
      .then(() => refreshActiveTab())
      .catch((err) => {
        store.errorMessage = err instanceof Error ? err.message : String(err);
      });

    const unregister = registerKeyboardShortcuts(window, {
      focusSearch: () => {
        searchInputEl?.focus();
        searchInputEl?.select();
      },
      newItem: () => {},
      copyPassword: () => {
        const pw = store.selectedItem?.login?.password;
        if (store.status.unlocked && pw) {
          void store.copySecret("Mot de passe", pw);
        }
      },
      copyUsername: () => {
        const user =
          store.selectedItem?.login?.username || store.selectedItem?.login?.email;
        if (store.status.unlocked && user) {
          void store.copySecret("Identifiant", user);
        }
      },
      copyTotp: () => {
        const totp = store.selectedItem?.login?.totp?.secret_base32;
        if (store.status.unlocked && totp) {
          void bridge
            .generateTotp(totp, Math.floor(Date.now() / 1000))
            .then((res) => store.copySecret("Code TOTP", res.code));
        }
      },
      lockVault: () => {
        if (store.status.unlocked) {
          void store.lockNow();
          tabMatch = null;
        }
      },
      openGenerator: () => {
        showGenerator = true;
      },
      moveSelection: () => {},
      activateSelection: () => {
        if (store.selectedItemId) {
          void bridge.fillActiveTab(store.selectedItemId);
        }
      },
      escape: () => {
        showGenerator = false;
      },
    });

    return () => unregister();
  });
</script>

<div class="flex h-full w-full flex-col bg-[var(--bg-void)] text-[var(--text-primary)]">
  <header class="flex h-[42px] shrink-0 items-center justify-between border-b border-[var(--border-subtle)] px-3">
    <div class="flex items-center gap-2">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" fill="#E63946">
        <path
          fill-rule="evenodd"
          clip-rule="evenodd"
          d="M8.2 2.5H15.8L20.5 6.4V13.4L12 21.8L3.5 13.4V6.4L8.2 2.5ZM5.5 8.8H18.5V10.6H16L14.3 12.1V15L16.5 16.8V18H7.5V16.8L9.7 15V12.1L8 10.6L5.5 9.8V8.8Z"
        />
      </svg>
      <span class="text-[13px] font-semibold tracking-tight">Anvil</span>
      {#if store.status.unlocked}
        <span class="rounded bg-[var(--bg-elevated)] px-1.5 py-0.5 text-[10.5px] font-mono text-[var(--text-muted)]">
          rev {store.status.sync_revision}
        </span>
      {/if}
    </div>

    <div class="flex items-center gap-1.5">
      <button
        type="button"
        onclick={() => (showGenerator = true)}
        title="Générateur"
        class="rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2 py-1 text-[11px] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
      >
        Générer
      </button>
      {#if store.status.unlocked}
        <button
          type="button"
          onclick={() => void store.syncNow().then(refreshActiveTab)}
          disabled={store.syncing}
          class="rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2 py-1 text-[11px] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
        >
          {store.syncing ? "…" : "Sync"}
        </button>
        <button
          type="button"
          onclick={() => {
            void store.lockNow();
            tabMatch = null;
          }}
          title="Verrouiller (Ctrl+L)"
          class="rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2 py-1 text-[11px] text-[var(--status-danger)] hover:bg-[var(--bg-hover)]"
        >
          Lock
        </button>
      {/if}
    </div>
  </header>

  {#if store.errorMessage}
    <div class="border-b border-[var(--status-danger)]/40 bg-[var(--status-danger)]/15 px-3 py-1.5 text-[11.5px] text-[var(--status-danger)]">
      {store.errorMessage}
    </div>
  {/if}

  {#if !store.status.unlocked}
    <UnlockScreen
      status={store.status}
      busy={store.busy}
      errorMessage={store.errorMessage}
      onUnlockPassword={(pw) =>
        runAction(async () => {
          await bridge.unlockWithPassword(pw);
          await store.refreshStatus();
        })}
      onUnlockBiometric={() => Promise.resolve()}
      onLogin={(url, email, pw) =>
        runAction(async () => {
          await bridge.login(url, email, pw);
          await store.refreshStatus();
        })}
      onRegister={(url, email, pw, invite) =>
        runAction(async () => {
          await bridge.register(url, email, pw, invite);
          await store.refreshStatus();
        })}
    />
  {:else}
    <div class="flex min-h-0 flex-1 flex-col">
      <div class="flex items-center justify-between border-b border-[var(--border-subtle)] bg-[var(--bg-surface)] px-3 py-1.5 text-[11.5px]">
        <span class={`truncate font-medium ${securityBadgeText().tone}`}>
          {securityBadgeText().label}
        </span>
        <span class="max-w-[140px] truncate font-mono text-[10.5px] text-[var(--text-muted)]">
          {activeTabUrl}
        </span>
      </div>

      <div class="border-b border-[var(--border-subtle)] p-2.5">
        <input
          bind:this={searchInputEl}
          type="search"
          data-anvil-search="true"
          value={store.searchQuery}
          oninput={(event) => void handleSearch(event.currentTarget.value)}
          placeholder="Rechercher dans Anvil (Ctrl+K)…"
          class="w-full rounded-[7px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2.5 py-1.5 text-[12.5px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-forge)] focus:outline-none"
        />
      </div>

      <div class="anvil-scroll min-h-0 flex-1 space-y-3 overflow-y-auto p-2.5">
        {#if tabMatch && tabMatch.items.length > 0 && !store.searchQuery}
          <section class="space-y-1.5">
            <div class="px-1 text-[10.5px] font-semibold tracking-wider text-[var(--accent-forge)] uppercase">
              Identifiants pour ce site ({tabMatch.items.length})
            </div>
            {#each tabMatch.items as item (item.id)}
              <div class="flex items-center justify-between gap-2 rounded-[8px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2.5 py-2">
                <button
                  type="button"
                  onclick={() => void store.selectItem(item.id)}
                  class="flex min-w-0 flex-1 items-center gap-2 text-left"
                >
                  <span
                    class="flex h-7 w-7 shrink-0 items-center justify-center rounded-[6px] bg-[var(--bg-elevated)] text-[11px] font-bold"
                    style:color={item.fallback_color}
                  >
                    {item.fallback_initials}
                  </span>
                  <div class="min-w-0 flex-1">
                    <div class="truncate text-[12.5px] font-medium">{item.title}</div>
                    <div class="truncate text-[11px] text-[var(--text-muted)]">{item.subtitle}</div>
                  </div>
                </button>
                <button
                  type="button"
                  onclick={() => void bridge.fillActiveTab(item.id)}
                  class="shrink-0 rounded-[6px] bg-[var(--accent-forge)] px-2.5 py-1 text-[11px] font-semibold text-[#0B0C0F] hover:bg-[var(--accent-forge-hover)]"
                >
                  Remplir
                </button>
              </div>
            {/each}
          </section>
        {/if}

        <section class="space-y-1">
          <div class="px-1 text-[10.5px] font-semibold tracking-wider text-[var(--text-muted)] uppercase">
            Coffre ({store.items.length})
          </div>
          {#each store.items as item (item.id)}
            {@const active = item.id === store.selectedItemId}
            <button
              type="button"
              onclick={() => void store.selectItem(item.id)}
              class="flex w-full items-center gap-2 rounded-[7px] border px-2 py-1.5 text-left"
              style:background-color={active ? "var(--bg-active)" : "transparent"}
              style:border-color={active ? "var(--border-focus)" : "transparent"}
            >
              <span
                class="flex h-6 w-6 shrink-0 items-center justify-center rounded-[5px] bg-[var(--bg-elevated)] text-[10.5px] font-bold"
                style:color={item.fallback_color}
              >
                {item.fallback_initials}
              </span>
              <div class="min-w-0 flex-1">
                <div class="truncate text-[12.5px] font-medium">{item.title}</div>
                <div class="truncate text-[11px] text-[var(--text-muted)]">{item.subtitle}</div>
              </div>
              {#if item.has_totp}
                <span class="rounded bg-[var(--accent-steel-muted)] px-1 py-0.5 text-[10px] font-mono text-[var(--accent-steel)]">
                  2FA
                </span>
              {/if}
            </button>
          {/each}
        </section>

        {#if store.selectedItem?.login}
          <section class="space-y-2 border-t border-[var(--border-subtle)] pt-2.5">
            <div class="flex items-center justify-between gap-2">
              <span class="truncate text-[12.5px] font-semibold">{store.selectedItem.title}</span>
              <button
                type="button"
                onclick={() => {
                  const user =
                    store.selectedItem?.login?.username || store.selectedItem?.login?.email;
                  if (user) void store.copySecret("Identifiant", user);
                }}
                class="rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2 py-1 text-[11px] text-[var(--text-secondary)]"
              >
                Copier user
              </button>
            </div>

            <PasswordField
              value={store.selectedItem.login.password}
              revealed={store.revealSelectedPassword}
              strength={selectedStrength}
              onToggleReveal={() =>
                (store.revealSelectedPassword = !store.revealSelectedPassword)}
              onCopy={() =>
                void store.copySecret(
                  "Mot de passe",
                  store.selectedItem?.login?.password ?? "",
                )}
            />

            {#if store.selectedItem.login.totp}
              <TotpRing
                secretOrUri={store.selectedItem.login.totp.secret_base32}
                generateCode={(secret, ts) => bridge.generateTotp(secret, ts)}
                onCopy={(code) => void store.copySecret("Code TOTP", code)}
              />
            {/if}
          </section>
        {/if}
      </div>

      {#if store.clipboardToast}
        <div class="border-t border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-1.5 text-[11px] text-[var(--accent-forge)]">
          {store.clipboardToast.label} copié — purge dans {store.clipboardToast.clear_after_seconds}s
        </div>
      {/if}
    </div>
  {/if}

  <PasswordGeneratorModal
    open={showGenerator}
    onGenerate={(opts) => bridge.generatePassword(opts)}
    onCopy={(label, value) => store.copySecret(label, value)}
    onClose={() => (showGenerator = false)}
  />
</div>
