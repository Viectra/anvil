<script lang="ts">
  import {
    PasswordField,
    PasswordGeneratorModal,
    TotpRing,
    UnlockScreen,
    VaultStore,
    type ItemDetailDto,
    type PasswordStrengthDto,
  } from "@anvil/ui";
  import { onMount } from "svelte";
  import BottomNav, { type MobileTab } from "./components/BottomNav.svelte";
  import MobileTotpSheet from "./components/MobileTotpSheet.svelte";
  import QrScannerModal from "./components/QrScannerModal.svelte";
  import {
    MobileAnvilBridge,
    type MobileStatusDto,
    type QrScanResultDto,
  } from "./lib/mobileBridge.js";

  const bridge = new MobileAnvilBridge();
  const store = new VaultStore(bridge);

  let mobileStatus = $state<MobileStatusDto>({
    configured: false,
    authenticated: false,
    unlocked: false,
    biometric_available: false,
    biometric_enabled: false,
    biometric_kind: "simulated_hardware",
    server_url: null,
    email: null,
    sync_revision: 0,
    pending_conflicts: 0,
    flag_secure_enabled: true,
    lock_on_background: true,
  });

  let activeTab = $state<MobileTab>("vault");
  let showQrModal = $state(false);
  let qrMode = $state<"onboarding" | "totp">("onboarding");
  let showGeneratorModal = $state(false);
  let selectedStrength = $state<PasswordStrengthDto | null>(null);
  let totpDetails = $state<ItemDetailDto[]>([]);
  let onboardPrefill = $state<{ serverUrl?: string; email?: string; invite?: string }>({});
  let biometricSetupPw = $state("");

  const syncAllStatus = async () => {
    mobileStatus = await bridge.status();
    store.status = mobileStatus;
    if (mobileStatus.unlocked) {
      await store.reloadVaultData();
      const totpRows = store.items.filter((i) => i.has_totp);
      totpDetails = await Promise.all(totpRows.map((i) => bridge.getItem(i.id)));
    } else {
      store.purgeEphemeralState();
      totpDetails = [];
    }
  };

  $effect(() => {
    const pw = store.selectedItem?.login?.password ?? "";
    if (!pw || !store.status.unlocked) {
      selectedStrength = null;
      return;
    }
    let cancelled = false;
    void bridge.evaluatePassword(pw).then((res) => {
      if (!cancelled) {
        selectedStrength = res;
      }
    });
    return () => {
      cancelled = true;
    };
  });

  const handleQrResolved = async (result: QrScanResultDto, raw: string) => {
    if (result.kind === "onboarding") {
      onboardPrefill = {
        serverUrl: result.payload.server_url,
        email: result.payload.email ?? undefined,
        invite: result.payload.invite_token ?? undefined,
      };
      return;
    }
    if (result.kind === "totp" && store.selectedItemId) {
      const updated = await bridge.attachTotpFromQr(store.selectedItemId, raw);
      store.selectedItem = updated;
      await syncAllStatus();
    }
  };

  onMount(() => {
    void syncAllStatus().catch((err) => {
      store.errorMessage = err instanceof Error ? err.message : String(err);
    });

    const onVisibilityChange = () => {
      if (document.visibilityState === "hidden" && store.status.unlocked) {
        void bridge.notifyAppBackgrounded().then((st) => {
          mobileStatus = st;
          store.status = st;
          if (!st.unlocked) {
            store.purgeEphemeralState();
            totpDetails = [];
          }
        });
      }
    };

    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  });
</script>

<div class="flex h-screen w-screen flex-col bg-[var(--bg-void)] text-[var(--text-primary)] select-none">
  <header class="flex h-[52px] shrink-0 items-center justify-between border-b border-[var(--border-subtle)] px-4 pt-[env(safe-area-inset-top)]">
    <div class="flex items-center gap-2">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="20" height="20" fill="#E63946">
        <path
          fill-rule="evenodd"
          clip-rule="evenodd"
          d="M8.2 2.5H15.8L20.5 6.4V13.4L12 21.8L3.5 13.4V6.4L8.2 2.5ZM5.5 8.8H18.5V10.6H16L14.3 12.1V15L16.5 16.8V18H7.5V16.8L9.7 15V12.1L8 10.6L5.5 9.8V8.8Z"
        />
      </svg>
      <span class="text-[15px] font-semibold">Anvil Mobile</span>
    </div>

    {#if mobileStatus.unlocked}
      <div class="flex items-center gap-2">
        <button
          type="button"
          onclick={() => void store.syncNow().then(syncAllStatus)}
          class="min-h-[34px] rounded-[7px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2.5 text-[12px]"
        >
          Sync
        </button>
        <button
          type="button"
          onclick={() => {
            void store.lockNow().then(() => {
              totpDetails = [];
            });
          }}
          class="min-h-[34px] rounded-[7px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2.5 text-[12px] text-[var(--status-danger)]"
        >
          Verrouiller
        </button>
      </div>
    {:else}
      <button
        type="button"
        onclick={() => {
          qrMode = "onboarding";
          showQrModal = true;
        }}
        class="min-h-[34px] rounded-[7px] border border-[var(--accent-forge)] px-2.5 text-[12px] font-medium text-[var(--accent-forge)]"
      >
        QR Serveur
      </button>
    {/if}
  </header>

  {#if !mobileStatus.unlocked}
    <div class="min-h-0 flex-1 overflow-y-auto">
      {#if onboardPrefill.serverUrl}
        <div class="mx-4 mt-3 rounded-[8px] border border-[var(--accent-forge)]/50 bg-[var(--accent-forge-muted)] px-3 py-2 text-[12px]">
          QR détecté : <strong>{onboardPrefill.serverUrl}</strong>
          {#if onboardPrefill.email}({onboardPrefill.email}){/if}
        </div>
      {/if}
      <UnlockScreen
        status={mobileStatus}
        busy={store.busy}
        errorMessage={store.errorMessage}
        onUnlockPassword={async (pw) => {
          await bridge.unlockWithPassword(pw);
          await syncAllStatus();
        }}
        onUnlockBiometric={async () => {
          await bridge.unlockWithBiometric();
          await syncAllStatus();
        }}
        onLogin={async (url, email, pw) => {
          await bridge.login(onboardPrefill.serverUrl ?? url, onboardPrefill.email ?? email, pw);
          await syncAllStatus();
        }}
        onRegister={async (url, email, pw, invite) => {
          await bridge.register(
            onboardPrefill.serverUrl ?? url,
            onboardPrefill.email ?? email,
            pw,
            onboardPrefill.invite ?? invite,
          );
          await syncAllStatus();
        }}
      />
    </div>
  {:else}
    <main class="anvil-scroll min-h-0 flex-1 overflow-y-auto">
      {#if activeTab === "vault"}
        <div class="space-y-3 p-4">
          <input
            type="search"
            value={store.searchQuery}
            oninput={(event) => {
              store.searchQuery = event.currentTarget.value;
              void store.reloadVaultData();
            }}
            placeholder="Rechercher un compte…"
            class="min-h-[44px] w-full rounded-[10px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3.5 text-[14px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-forge)] focus:outline-none"
          />

          <div class="space-y-1.5">
            {#each store.items as item (item.id)}
              <button
                type="button"
                onclick={() => void store.selectItem(item.id)}
                class="flex min-h-[54px] w-full items-center gap-3 rounded-[10px] border px-3 py-2 text-left"
                style:background-color={store.selectedItemId === item.id ? "var(--bg-active)" : "var(--bg-surface)"}
                style:border-color={store.selectedItemId === item.id ? "var(--border-focus)" : "var(--border-subtle)"}
              >
                <span
                  class="flex h-9 w-9 shrink-0 items-center justify-center rounded-[8px] bg-[var(--bg-elevated)] text-[12px] font-bold"
                  style:color={item.fallback_color}
                >
                  {item.fallback_initials}
                </span>
                <div class="min-w-0 flex-1">
                  <div class="truncate text-[14px] font-medium">{item.title}</div>
                  <div class="truncate text-[12px] text-[var(--text-muted)]">{item.subtitle}</div>
                </div>
              </button>
            {/each}
          </div>

          {#if store.selectedItem?.login}
            <div class="space-y-3 rounded-[12px] border border-[var(--border-default)] bg-[var(--bg-elevated)] p-4">
              <div class="flex items-center justify-between">
                <h3 class="text-[16px] font-semibold">{store.selectedItem.title}</h3>
                <button
                  type="button"
                  onclick={() => {
                    qrMode = "totp";
                    showQrModal = true;
                  }}
                  class="rounded-[7px] border border-[var(--border-default)] px-2.5 py-1 text-[11.5px] text-[var(--accent-steel)]"
                >
                  + QR 2FA
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
                  generateCode={(s, ts) => bridge.generateTotp(s, ts)}
                  onCopy={(c) => void store.copySecret("Code TOTP", c)}
                />
              {/if}
            </div>
          {/if}
        </div>
      {:else if activeTab === "totp"}
        <MobileTotpSheet
          totpItems={totpDetails}
          generateCode={(s, ts) => bridge.generateTotp(s, ts)}
          onCopy={(l, v) => store.copySecret(l, v)}
          onOpenQrAttach={() => {
            qrMode = "totp";
            showQrModal = true;
          }}
        />
      {:else if activeTab === "generator"}
        <div class="p-4">
          <button
            type="button"
            onclick={() => (showGeneratorModal = true)}
            class="min-h-[48px] w-full rounded-[10px] bg-[var(--accent-forge)] text-[14px] font-semibold text-[#0B0C0F]"
          >
            Ouvrir le générateur Forge
          </button>
        </div>
      {:else}
        <section class="space-y-4 p-4 text-[13px]">
          <div class="rounded-[10px] border border-[var(--border-default)] bg-[var(--bg-surface)] p-4 space-y-3">
            <h2 class="font-semibold text-[var(--text-primary)]">Confidentialité & Enclave</h2>
            <label class="flex items-center justify-between gap-2">
              <span>Blocage captures (`FLAG_SECURE`)</span>
              <input
                type="checkbox"
                checked={mobileStatus.flag_secure_enabled}
                onchange={(e) =>
                  void bridge
                    .setPrivacySettings(e.currentTarget.checked, mobileStatus.lock_on_background)
                    .then((st) => (mobileStatus = st))}
              />
            </label>
            <label class="flex items-center justify-between gap-2">
              <span>Verrouiller en arrière-plan</span>
              <input
                type="checkbox"
                checked={mobileStatus.lock_on_background}
                onchange={(e) =>
                  void bridge
                    .setPrivacySettings(mobileStatus.flag_secure_enabled, e.currentTarget.checked)
                    .then((st) => (mobileStatus = st))}
              />
            </label>
          </div>

          <div class="rounded-[10px] border border-[var(--border-default)] bg-[var(--bg-surface)] p-4 space-y-2.5">
            <h2 class="font-semibold text-[var(--text-primary)]">
              Biométrie ({mobileStatus.biometric_kind})
            </h2>
            <p class="text-[12px] text-[var(--text-muted)]">
              Scelle uniquement la `VaultKey` dans l'enclave matérielle OS.
            </p>
            <input
              type="password"
              bind:value={biometricSetupPw}
              placeholder="Master Password pour activer"
              class="min-h-[40px] w-full rounded-[8px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-3"
            />
            <button
              type="button"
              onclick={() =>
                void bridge.enableBiometric(biometricSetupPw).then((st) => {
                  mobileStatus = st;
                  biometricSetupPw = "";
                })}
              disabled={!biometricSetupPw}
              class="min-h-[42px] w-full rounded-[8px] bg-[var(--accent-forge)] font-semibold text-[#0B0C0F] disabled:opacity-45"
            >
              Activer déverrouillage biométrique
            </button>
          </div>
        </section>
      {/if}
    </main>

    <BottomNav {activeTab} onSelect={(tab) => (activeTab = tab)} />
  {/if}

  <QrScannerModal
    open={showQrModal}
    title={qrMode === "onboarding" ? "QR Code Serveur Anvil" : "Scanner QR 2FA (TOTP)"}
    onScanCamera={() => bridge.scanQrWithCamera()}
    onParsePayload={(raw) => bridge.parseQrPayload(raw)}
    onResolved={handleQrResolved}
    onClose={() => (showQrModal = false)}
  />

  <PasswordGeneratorModal
    open={showGeneratorModal}
    onGenerate={(opts) => bridge.generatePassword(opts)}
    onCopy={(label, value) => store.copySecret(label, value)}
    onClose={() => (showGeneratorModal = false)}
  />
</div>
