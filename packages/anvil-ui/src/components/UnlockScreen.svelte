<script lang="ts">
  import type { VaultStatusDto } from "../lib/types.js";

  interface Props {
    status: VaultStatusDto;
    busy: boolean;
    errorMessage: string | null;
    onUnlockPassword: (password: string) => Promise<void>;
    onUnlockBiometric: () => Promise<void>;
    onLogin: (serverUrl: string, email: string, password: string) => Promise<void>;
    onRegister: (serverUrl: string, email: string, password: string, inviteToken: string | null) => Promise<void>;
  }

  let {
    status,
    busy,
    errorMessage,
    onUnlockPassword,
    onUnlockBiometric,
    onLogin,
    onRegister,
  }: Props = $props();

  const defaultServerUrl = (): string => {
    if (status.server_url) return status.server_url;
    if (
      typeof window !== "undefined" &&
      (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost")
    ) {
      return "http://127.0.0.1:8080";
    }
    return "https://";
  };

  let mode = $state<"unlock" | "login" | "register">(status.configured ? "unlock" : "login");
  let serverUrl = $state(defaultServerUrl());
  let email = $state(status.email ?? "");
  let password = $state("");
  let inviteToken = $state("");

  $effect(() => {
    if (status.configured && mode === "login" && !password) {
      serverUrl = status.server_url ?? serverUrl;
      email = status.email ?? email;
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
</script>

<div class="flex h-full flex-1 items-center justify-center bg-[var(--bg-surface)] p-6">
  <div class="w-full max-w-[400px] rounded-[12px] border border-[var(--border-default)] bg-[var(--bg-elevated)] p-7">
    <div class="flex flex-col items-center text-center">
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="56" height="56" fill="none" role="img" aria-label="Anvil">
        <defs>
          <linearGradient id="unlock-bg" x1="12" y1="6" x2="52" y2="58" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#191C24" />
            <stop offset="100%" stop-color="#0E1015" />
          </linearGradient>
          <linearGradient id="unlock-ember" x1="13.5" y1="22.5" x2="48" y2="26" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#B91C2E" />
            <stop offset="55%" stop-color="#E63946" />
            <stop offset="100%" stop-color="#F26A3D" />
          </linearGradient>
          <linearGradient id="unlock-steel" x1="20" y1="25" x2="44" y2="46" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stop-color="#F1F3F7" />
            <stop offset="100%" stop-color="#B5BECB" />
          </linearGradient>
        </defs>
        <path d="M22 6H42L54 16V35L32 58L10 35V16L22 6Z" fill="url(#unlock-bg)" stroke="#2E3444" stroke-width="2" stroke-linejoin="round" />
        <path d="M22 6H42" stroke="#D63242" stroke-width="2.2" stroke-linecap="round" />
        <path d="M32 12.5L35.6 16.8L32 20L28.4 16.8L32 12.5Z" fill="#E63946" />
        <path d="M14 25.5H47.5V27.6H41.5L37.5 31V38.2L43.5 43V46H20.5V43L26.5 38.2V31L21.5 27.8L14 25.5Z" fill="url(#unlock-steel)" />
        <path d="M13.5 22.5H48V26H14.5L13.5 22.5Z" fill="url(#unlock-ember)" />
      </svg>

      <h1 class="mt-3 text-[20px] font-semibold text-[var(--text-primary)]">Anvil</h1>
      <p class="mt-1 text-[12.5px] text-[var(--text-secondary)]">
        {#if mode === "unlock"}
          Déverrouillez votre coffre chiffré localement.
        {:else if mode === "login"}
          Connexion à votre instance auto-hébergée.
        {:else}
          Créer un nouveau coffre Zero-Knowledge.
        {/if}
      </p>
    </div>

    <div class="mt-5 flex rounded-[7px] border border-[var(--border-subtle)] bg-[var(--bg-void)] p-1 text-[12px]">
      {#if status.configured}
        <button
          type="button"
          onclick={() => (mode = "unlock")}
          class="flex-1 rounded-[5px] py-1.5 font-medium"
          style:background-color={mode === "unlock" ? "var(--bg-elevated)" : "transparent"}
          style:color={mode === "unlock" ? "var(--text-primary)" : "var(--text-muted)"}
        >
          Déverrouiller
        </button>
      {/if}
      <button
        type="button"
        onclick={() => (mode = "login")}
        class="flex-1 rounded-[5px] py-1.5 font-medium"
        style:background-color={mode === "login" ? "var(--bg-elevated)" : "transparent"}
        style:color={mode === "login" ? "var(--text-primary)" : "var(--text-muted)"}
      >
        Connexion
      </button>
      <button
        type="button"
        onclick={() => (mode = "register")}
        class="flex-1 rounded-[5px] py-1.5 font-medium"
        style:background-color={mode === "register" ? "var(--bg-elevated)" : "transparent"}
        style:color={mode === "register" ? "var(--text-primary)" : "var(--text-muted)"}
      >
        Inscription
      </button>
    </div>

    {#if errorMessage}
      <div class="mt-4 rounded-[7px] border border-[var(--status-danger)] bg-[rgba(224,79,95,0.1)] px-3 py-2 text-[12.5px] text-[var(--status-danger)]">
        {errorMessage}
      </div>
    {/if}

    <form onsubmit={handleSubmit} class="mt-4 space-y-3.5">
      {#if mode !== "unlock"}
        <label class="block space-y-1 text-[12px] text-[var(--text-secondary)]">
          <span>URL du serveur Anvil</span>
          <input
            type="url"
            bind:value={serverUrl}
            required
            placeholder="https://vault.exemple.fr"
            class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 text-[13px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
          />
        </label>
        <label class="block space-y-1 text-[12px] text-[var(--text-secondary)]">
          <span>Email</span>
          <input
            type="email"
            bind:value={email}
            required
            class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 text-[13px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
          />
        </label>
      {:else if status.email}
        <div class="rounded-[6px] border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-3 py-2 text-[12.5px] text-[var(--text-secondary)]">
          Compte : <span class="font-medium text-[var(--text-primary)]">{status.email}</span>
        </div>
      {/if}

      {#if mode === "register"}
        <label class="block space-y-1 text-[12px] text-[var(--text-secondary)]">
          <span>Jeton d'invitation (si requis)</span>
          <input
            type="text"
            bind:value={inviteToken}
            class="anvil-mono-secret w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 text-[13px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
          />
        </label>
      {/if}

      <label class="block space-y-1 text-[12px] text-[var(--text-secondary)]">
        <span>Mot de passe maître</span>
        <input
          type="password"
          bind:value={password}
          required
          autocomplete="current-password"
          class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 text-[13px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
        />
      </label>

      <button
        type="submit"
        disabled={busy}
        class="w-full rounded-[7px] bg-[var(--accent-forge)] py-2 text-[13.5px] font-semibold text-[#0B0C0F] transition-colors hover:bg-[var(--accent-forge-hover)] disabled:opacity-60"
      >
        {busy
          ? "Dérivation Argon2id..."
          : mode === "unlock"
            ? "Déverrouiller le coffre"
            : mode === "login"
              ? "Se connecter"
              : "Créer le compte"}
      </button>

      {#if mode === "unlock" && status.biometric_enabled}
        <button
          type="button"
          disabled={busy}
          onclick={() => onUnlockBiometric()}
          class="w-full rounded-[7px] border border-[var(--border-default)] bg-[var(--bg-surface)] py-2 text-[13px] font-medium text-[var(--text-primary)] hover:border-[var(--accent-steel)]"
        >
          Déverrouiller par biométrie OS
        </button>
      {/if}
    </form>
  </div>
</div>
