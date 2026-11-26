<script lang="ts">
  import type { VaultStatusDto } from "../lib/types.js";

  interface Props {
    status: VaultStatusDto;
    busy: boolean;
    errorMessage: string | null;
    onUnlockPassword: (password: string) => Promise<void>;
    onUnlockBiometric: () => Promise<void>;
    onLogout?: () => Promise<void>;
    onLogin: (serverUrl: string, email: string, password: string) => Promise<void>;
    onRegister: (serverUrl: string, email: string, password: string, inviteToken: string | null) => Promise<void>;
  }

  let {
    status,
    busy,
    errorMessage,
    onUnlockPassword,
    onUnlockBiometric,
    onLogout,
    onLogin,
    onRegister,
  }: Props = $props();

  const defaultServerUrl = (): string => {
    if (status.server_url) return status.server_url;
    return "";
  };

  let mode = $state<"unlock" | "login" | "register">(status.configured ? "unlock" : "login");
  let serverUrl = $state(defaultServerUrl());
  let email = $state(status.email ?? "");
  let password = $state("");
  let inviteToken = $state("");
  let showLogoutConfirm = $state(false);

  $effect(() => {
    if (status.configured) {
      if (mode !== "unlock") mode = "unlock";
      serverUrl = status.server_url ?? serverUrl;
      email = status.email ?? email;
    } else if (mode === "unlock") {
      mode = "login";
    }
  });

  const handleSubmit = async (event: SubmitEvent) => {
    event.preventDefault();
    const secret = password;
    password = "";
    if (!secret) return;

    if (mode === "unlock") {
      await onUnlockPassword(secret);
    } else if (mode === "login") {
      await onLogin(serverUrl.trim(), email.trim(), secret);
    } else {
      await onRegister(serverUrl.trim(), email.trim(), secret, inviteToken.trim() || null);
    }
  };

  const confirmLogout = async () => {
    showLogoutConfirm = false;
    password = "";
    if (onLogout) {
      await onLogout();
    }
    mode = "login";
  };
</script>

<div class="flex h-full flex-1 items-center justify-center bg-[var(--bg-surface)] p-6">
  <div class="w-full max-w-[408px] rounded-[14px] border border-[#35353e] bg-[var(--bg-elevated)] p-7 shadow-2xl">
    {#if mode === "unlock"}
      <div class="mb-5 flex flex-col items-center text-center">
        <div class="mb-3 flex h-[92px] w-[92px] items-center justify-center overflow-hidden rounded-[10px] border-2 border-[#3c3c47] bg-[#dcdce2]">
          {#if status.avatar_data_url}
            <img src={status.avatar_data_url} alt={status.email ?? "Avatar"} class="h-full w-full object-cover" />
          {:else}
            <svg viewBox="0 0 24 24" width="44" height="44" fill="none" aria-hidden="true">
              <circle cx="12" cy="8" r="4" fill="#525260" />
              <path d="M4 20c0-4 3.6-6.5 8-6.5s8 2.5 8 6.5" fill="#525260" />
            </svg>
          {/if}
        </div>
        <div class="text-[14px] font-semibold text-[var(--text-primary)]">{status.email ?? "-"}</div>
        <span
          class="mt-1.5 inline-flex items-center rounded-full px-2 py-0.5 text-[10.5px] font-bold uppercase"
          style:background-color={status.role === "admin" ? "var(--accent-forge-muted)" : "rgba(255,255,255,0.08)"}
          style:color={status.role === "admin" ? "#c2baff" : "var(--text-secondary)"}
        >
          {status.role === "admin" ? "Admin" : "User"}
        </span>
        <div class="mt-1 text-[12px] text-[var(--text-secondary)]">{status.server_url ?? ""}</div>
      </div>
    {:else}
      <div class="mb-5 flex flex-col items-center text-center">
        <div class="mb-3 flex h-[88px] w-[88px] items-center justify-center rounded-[10px] border border-[#464654] bg-[#dcdce2]">
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="56" height="56" fill="none" role="img" aria-label="Anvil">
            <path d="M22 6H42L54 16V35L32 58L10 35V16L22 6Z" fill="#232329" stroke="#3C3C47" stroke-width="2.4" />
            <path d="M14 25.5H47.5V27.6H41.5L37.5 31V38.2L43.5 43V46H20.5V43L26.5 38.2V31L21.5 27.8L14 25.5Z" fill="#F4F4F7" />
            <path d="M13.5 22.5H48V26H14.5L13.5 22.5Z" fill="#7C6DFA" />
          </svg>
        </div>
        <p class="text-[12.5px] text-[var(--text-secondary)]">
          {mode === "register" ? "Créer un compte sur une instance Anvil" : "Connexion à une instance Anvil"}
        </p>
      </div>
      <div class="mb-2.5 text-[12.5px] font-semibold text-[var(--text-secondary)]">
        {mode === "register" ? "SignIn" : "Login"}
      </div>
    {/if}

    {#if errorMessage}
      <div class="mb-3 rounded-[7px] border border-[var(--status-danger)] bg-[rgba(229,72,88,0.14)] px-3 py-2 text-[12.5px] text-[#ffb2ba]">
        {errorMessage}
      </div>
    {/if}

    <form onsubmit={handleSubmit} class="space-y-3">
      {#if mode !== "unlock"}
        <input
          type="url"
          bind:value={serverUrl}
          required
          placeholder="URL"
          class="w-full rounded-[7px] border-2 border-transparent bg-[#dcdce2] px-3 py-2 text-[13px] font-medium text-[#16161a] placeholder:text-[#62626d] focus:border-[var(--accent-forge)] focus:outline-none"
        />
        <input
          type="email"
          bind:value={email}
          required
          placeholder="Email"
          class="w-full rounded-[7px] border-2 border-transparent bg-[#dcdce2] px-3 py-2 text-[13px] font-medium text-[#16161a] placeholder:text-[#62626d] focus:border-[var(--accent-forge)] focus:outline-none"
        />
        <input
          type="password"
          bind:value={password}
          required
          placeholder="Password"
          autocomplete={mode === "register" ? "new-password" : "current-password"}
          class="w-full rounded-[7px] border-2 border-transparent bg-[#dcdce2] px-3 py-2 text-[13px] font-medium text-[#16161a] placeholder:text-[#62626d] focus:border-[var(--accent-forge)] focus:outline-none"
        />
        {#if mode === "register"}
          <input
            type="text"
            bind:value={inviteToken}
            placeholder="Invite Token (optionnel)"
            class="anvil-mono-secret w-full rounded-[7px] border-2 border-transparent bg-[#dcdce2] px-3 py-2 text-[13px] font-medium text-[#16161a] placeholder:text-[#62626d] focus:border-[var(--accent-forge)] focus:outline-none"
          />
        {/if}
      {:else}
        <label class="block space-y-1 text-[12px] text-[var(--text-secondary)]">
          <span>MasterPassword</span>
          <input
            type="password"
            bind:value={password}
            required
            placeholder="MasterPassword"
            autocomplete="current-password"
            class="w-full rounded-[7px] border-2 border-transparent bg-[#dcdce2] px-3 py-2 text-[13px] font-medium text-[#16161a] placeholder:text-[#62626d] focus:border-[var(--accent-forge)] focus:outline-none"
          />
        </label>
      {/if}

      <button
        type="submit"
        disabled={busy}
        class="w-full rounded-[7px] bg-[var(--accent-forge)] py-2.5 text-[13.5px] font-semibold text-white transition-colors hover:bg-[var(--accent-forge-hover)] disabled:opacity-60"
      >
        {busy ? "Connexion..." : mode === "unlock" ? "Unlock" : mode === "register" ? "SignIn" : "Login"}
      </button>

      {#if mode === "unlock" && status.biometric_available && status.biometric_enabled}
        <button
          type="button"
          disabled={busy}
          onclick={() => onUnlockBiometric()}
          class="w-full rounded-[7px] border border-[var(--border-default)] bg-[rgba(255,255,255,0.03)] py-2 text-[13px] font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
        >
          Unlock with Windows Hello
        </button>
      {/if}
    </form>

    {#if mode === "unlock"}
      <div class="my-3 text-center text-[12px] text-[var(--text-secondary)]">or</div>
      <button
        type="button"
        disabled={busy}
        onclick={() => (showLogoutConfirm = true)}
        class="w-full rounded-[7px] bg-[#dcdce2] py-2.5 text-[13.5px] font-semibold text-[#16161a] hover:bg-[#eaeaf0] disabled:opacity-60"
      >
        Login
      </button>
    {:else}
      <div class="mt-3 flex items-center justify-end gap-1.5 text-[12px] text-[var(--text-secondary)]">
        <span>{mode === "register" ? "Already have an account ?" : "No account ?"}</span>
        <button
          type="button"
          disabled={busy}
          onclick={() => (mode = mode === "register" ? "login" : "register")}
          class="font-semibold text-[var(--accent-forge)] hover:underline"
        >
          {mode === "register" ? "Login" : "SignIn"}
        </button>
      </div>
    {/if}
  </div>
</div>

{#if showLogoutConfirm}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
    <div class="w-full max-w-[360px] rounded-[14px] border border-[#2b2b34] bg-[#111114] p-7 text-center shadow-2xl">
      <div class="mb-2 text-[30px] font-extrabold text-[var(--text-primary)]">!</div>
      <h2 class="text-[19px] font-bold text-[var(--text-primary)]">Se Deconnecter</h2>
      <p class="mt-1.5 mb-5 text-[12.5px] text-[var(--text-secondary)]">
        Etes-Vous sur de vouloir vous deconnecter ?
      </p>
      <button
        type="button"
        disabled={busy}
        onclick={() => void confirmLogout()}
        class="mb-2.5 w-full rounded-[7px] bg-[var(--accent-forge)] py-2.5 text-[13.5px] font-semibold text-white hover:bg-[var(--accent-forge-hover)]"
      >
        Se Deconnecter
      </button>
      <button
        type="button"
        disabled={busy}
        onclick={() => (showLogoutConfirm = false)}
        class="w-full rounded-[7px] bg-[#dcdce2] py-2.5 text-[13.5px] font-semibold text-[#16161a] hover:bg-[#eaeaf0]"
      >
        Annuler
      </button>
    </div>
  </div>
{/if}
