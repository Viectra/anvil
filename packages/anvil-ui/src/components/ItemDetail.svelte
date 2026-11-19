<script lang="ts">
  import type {
    FolderDto,
    ItemDetailDto,
    ItemKind,
    PasswordStrengthDto,
    SaveItemInputDto,
    TotpCodeDto,
  } from "../lib/types.js";
  import PasswordField from "./PasswordField.svelte";
  import TotpRing from "./TotpRing.svelte";

  interface Props {
    item: ItemDetailDto | null;
    folders: FolderDto[];
    editingNew: boolean;
    revealed: boolean;
    strength: PasswordStrengthDto | null;
    onToggleReveal: () => void;
    onToggleFavorite: (item: ItemDetailDto) => void;
    onCopy: (label: string, value: string) => void;
    onSave: (input: SaveItemInputDto) => Promise<void>;
    onDelete: (id: string) => Promise<void>;
    onUploadLogo: (itemId: string, bytes: number[]) => Promise<void>;
    onGenerateTotp: (secretOrUri: string, unixSeconds: number) => Promise<TotpCodeDto>;
    onOpenUrl: (url: string) => void;
    onCancelNew: () => void;
  }

  let {
    item,
    folders,
    editingNew,
    revealed,
    strength,
    onToggleReveal,
    onToggleFavorite,
    onCopy,
    onSave,
    onDelete,
    onUploadLogo,
    onGenerateTotp,
    onOpenUrl,
    onCancelNew,
  }: Props = $props();

  let isEditing = $state(false);
  let showHistory = $state(false);
  let saving = $state(false);

  let formTitle = $state("");
  let formKind = $state<ItemKind>("login");
  let formFolderId = $state<string>("");
  let formUsername = $state("");
  let formEmail = $state("");
  let formPassword = $state("");
  let formUrl = $state("");
  let formTotp = $state("");
  let formNotes = $state("");

  $effect(() => {
    if (editingNew) {
      isEditing = true;
      formTitle = "";
      formKind = "login";
      formFolderId = "";
      formUsername = "";
      formEmail = "";
      formPassword = "";
      formUrl = "";
      formTotp = "";
      formNotes = "";
      showHistory = false;
    } else if (item) {
      isEditing = false;
      formTitle = item.title;
      formKind = item.kind;
      formFolderId = item.folder_id ?? "";
      formUsername = item.login?.username ?? "";
      formEmail = item.login?.email ?? "";
      formPassword = item.login?.password ?? "";
      formUrl = item.login?.uris[0]?.uri ?? "";
      formTotp = item.login?.totp?.secret_base32 ?? "";
      formNotes = item.notes;
      showHistory = false;
    }
  });

  const handleSubmit = async (event: SubmitEvent) => {
    event.preventDefault();
    if (!formTitle.trim()) return;
    saving = true;
    try {
      const cleanedTotp = formTotp.trim();
      await onSave({
        id: editingNew ? null : item?.id ?? null,
        kind: formKind,
        title: formTitle.trim(),
        folder_id: formFolderId || null,
        favorite: item?.favorite ?? false,
        trashed_at: item?.trashed_at ?? null,
        login:
          formKind === "login"
            ? {
                username: formUsername.trim(),
                email: formEmail.trim(),
                password: formPassword,
                password_history: item?.login?.password_history ?? [],
                uris: formUrl.trim()
                  ? [{ uri: formUrl.trim(), match_mode: "base_domain" }]
                  : [],
                totp: cleanedTotp
                  ? {
                      secret_base32: cleanedTotp,
                      algorithm: item?.login?.totp?.algorithm ?? "SHA1",
                      digits: item?.login?.totp?.digits ?? 6,
                      period_seconds: item?.login?.totp?.period_seconds ?? 30,
                      issuer: item?.login?.totp?.issuer ?? null,
                      label: item?.login?.totp?.label ?? null,
                    }
                  : null,
              }
            : null,
        custom_fields: item?.custom_fields ?? [],
        notes: formNotes,
      });
      formPassword = "";
      formTotp = "";
      isEditing = false;
    } finally {
      saving = false;
    }
  };

  const handleLogoFile = async (event: Event) => {
    if (!item) return;
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    const bytes = Array.from(new Uint8Array(await file.arrayBuffer()));
    await onUploadLogo(item.id, bytes);
    input.value = "";
  };
</script>

<main class="anvil-scroll flex h-full flex-1 flex-col overflow-y-auto bg-[var(--bg-surface)] px-7 py-6">
  {#if !item && !editingNew}
    <div class="flex h-full flex-col items-center justify-center text-center text-[var(--text-muted)]">
      <div class="text-[15px] font-medium text-[var(--text-secondary)]">Sélectionnez une fiche</div>
      <div class="mt-1 text-[12.5px]">Utilisez ↑ / ↓ pour naviguer ou Ctrl+K pour rechercher.</div>
    </div>
  {:else if isEditing}
    <form onsubmit={handleSubmit} class="mx-auto w-full max-w-[640px] space-y-4">
      <div class="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
        <h2 class="text-[18px] font-semibold text-[var(--text-primary)]">
          {editingNew ? "Nouvelle fiche" : `Modifier — ${item?.title}`}
        </h2>
        <div class="flex gap-2">
          <button
            type="button"
            onclick={() => {
              if (editingNew) onCancelNew();
              else isEditing = false;
            }}
            class="rounded-[6px] border border-[var(--border-default)] px-3 py-1.5 text-[12.5px] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
          >
            Annuler
          </button>
          <button
            type="submit"
            disabled={saving}
            class="rounded-[6px] bg-[var(--accent-forge)] px-4 py-1.5 text-[12.5px] font-semibold text-[#0B0C0F] hover:bg-[var(--accent-forge-hover)] disabled:opacity-60"
          >
            {saving ? "Chiffrement..." : "Enregistrer"}
          </button>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-3">
        <label class="space-y-1 text-[12px] text-[var(--text-secondary)]">
          <span>Titre *</span>
          <input
            type="text"
            bind:value={formTitle}
            required
            class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-3 py-2 text-[13.5px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
          />
        </label>
        <label class="space-y-1 text-[12px] text-[var(--text-secondary)]">
          <span>Dossier</span>
          <select
            bind:value={formFolderId}
            class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-3 py-2 text-[13.5px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
          >
            <option value="">Aucun dossier</option>
            {#each folders as f (f.id)}
              <option value={f.id}>{f.name}</option>
            {/each}
          </select>
        </label>
      </div>

      {#if editingNew}
        <div class="flex gap-2 text-[12.5px]">
          <button
            type="button"
            onclick={() => (formKind = "login")}
            class="rounded-[6px] border px-3 py-1.5"
            style:border-color={formKind === "login" ? "var(--accent-forge)" : "var(--border-default)"}
            style:color={formKind === "login" ? "var(--accent-forge)" : "var(--text-secondary)"}
          >
            Identifiant
          </button>
          <button
            type="button"
            onclick={() => (formKind = "secure_note")}
            class="rounded-[6px] border px-3 py-1.5"
            style:border-color={formKind === "secure_note" ? "var(--accent-forge)" : "var(--border-default)"}
            style:color={formKind === "secure_note" ? "var(--accent-forge)" : "var(--text-secondary)"}
          >
            Note sécurisée
          </button>
        </div>
      {/if}

      {#if formKind === "login"}
        <div class="grid grid-cols-2 gap-3">
          <label class="space-y-1 text-[12px] text-[var(--text-secondary)]">
            <span>Identifiant</span>
            <input
              type="text"
              bind:value={formUsername}
              class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-3 py-2 text-[13.5px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
            />
          </label>
          <label class="space-y-1 text-[12px] text-[var(--text-secondary)]">
            <span>Email</span>
            <input
              type="email"
              bind:value={formEmail}
              class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-3 py-2 text-[13.5px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
            />
          </label>
        </div>

        <label class="block space-y-1 text-[12px] text-[var(--text-secondary)]">
          <span>Mot de passe</span>
          <input
            type="text"
            bind:value={formPassword}
            class="anvil-mono-secret w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-3 py-2 text-[13.5px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
          />
        </label>

        <div class="grid grid-cols-2 gap-3">
          <label class="space-y-1 text-[12px] text-[var(--text-secondary)]">
            <span>URL du site</span>
            <input
              type="url"
              bind:value={formUrl}
              placeholder="https://example.com"
              class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-3 py-2 text-[13.5px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
            />
          </label>
          <label class="space-y-1 text-[12px] text-[var(--text-secondary)]">
            <span>Secret TOTP / URI otpauth://</span>
            <input
              type="text"
              bind:value={formTotp}
              placeholder="JBSWY3DPEHPK3PXP ou otpauth://..."
              class="anvil-mono-secret w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-3 py-2 text-[13.5px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
            />
          </label>
        </div>
      {/if}

      <label class="block space-y-1 text-[12px] text-[var(--text-secondary)]">
        <span>Notes chiffrées</span>
        <textarea
          rows="4"
          bind:value={formNotes}
          class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-3 py-2 text-[13.5px] text-[var(--text-primary)] focus:border-[var(--border-focus)] focus:outline-none"
        ></textarea>
      </label>
    </form>
  {:else if item}
    <div class="mx-auto w-full max-w-[660px] space-y-5">
      <div class="flex items-start justify-between gap-4 border-b border-[var(--border-subtle)] pb-4">
        <div class="flex items-center gap-3.5">
          {#if item.logo.data_url}
            <img
              src={item.logo.data_url}
              alt={item.title}
              class="h-11 w-11 rounded-[10px] border border-[var(--border-default)] object-cover"
            />
          {:else}
            <div
              class="flex h-11 w-11 items-center justify-center rounded-[10px] border border-[var(--border-default)] bg-[var(--bg-elevated)] text-[14px] font-bold"
              style:color={item.logo.fallback_color}
            >
              {item.title.slice(0, 2).toUpperCase()}
            </div>
          {/if}

          <div>
            <h1 class="text-[17px] font-semibold text-[var(--text-primary)]">{item.title}</h1>
            {#if item.login?.uris[0]}
              <button
                type="button"
                onclick={() => onOpenUrl(item.login!.uris[0]!.uri)}
                class="mt-0.5 text-[12.5px] text-[var(--accent-steel)] hover:underline"
              >
                {item.login.uris[0].uri} ↗
              </button>
            {/if}
          </div>
        </div>

        <div class="flex shrink-0 items-center gap-2">
          <label class="cursor-pointer rounded-[6px] border border-[var(--border-default)] px-2.5 py-1.5 text-[12px] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]">
            Logo
            <input type="file" accept="image/png,image/jpeg,image/webp" onchange={handleLogoFile} class="hidden" />
          </label>
          <button
            type="button"
            onclick={() => onToggleFavorite(item)}
            aria-label="Basculer favori"
            class="rounded-[6px] border border-[var(--border-default)] px-2.5 py-1.5 text-[12.5px]"
            style:color={item.favorite ? "var(--accent-forge)" : "var(--text-secondary)"}
          >
            {item.favorite ? "★" : "☆"}
          </button>
          <button
            type="button"
            onclick={() => (isEditing = true)}
            class="rounded-[6px] border border-[var(--border-default)] px-3 py-1.5 text-[12.5px] text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
          >
            Modifier
          </button>
          <button
            type="button"
            onclick={() => onDelete(item.id)}
            class="rounded-[6px] border border-[var(--border-default)] px-3 py-1.5 text-[12.5px] text-[var(--status-danger)] hover:bg-[rgba(224,79,95,0.12)]"
          >
            Supprimer
          </button>
        </div>
      </div>

      {#if item.login}
        <div class="space-y-3">
          {#if item.login.username}
            <div class="flex items-center justify-between rounded-[8px] border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3.5 py-2.5">
              <div>
                <div class="text-[11px] font-medium text-[var(--text-muted)] uppercase">Identifiant</div>
                <div class="anvil-selectable mt-0.5 text-[13.5px] text-[var(--text-primary)]">
                  {item.login.username}
                </div>
              </div>
              <button
                type="button"
                onclick={() => onCopy("Identifiant", item.login!.username)}
                class="rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2.5 py-1 text-[12px] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              >
                Copier
              </button>
            </div>
          {/if}

          {#if item.login.email}
            <div class="flex items-center justify-between rounded-[8px] border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3.5 py-2.5">
              <div>
                <div class="text-[11px] font-medium text-[var(--text-muted)] uppercase">Email</div>
                <div class="anvil-selectable mt-0.5 text-[13.5px] text-[var(--text-primary)]">
                  {item.login.email}
                </div>
              </div>
              <button
                type="button"
                onclick={() => onCopy("Email", item.login!.email)}
                class="rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-2.5 py-1 text-[12px] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              >
                Copier
              </button>
            </div>
          {/if}

          {#if item.login.password}
            <div class="space-y-1.5">
              <div class="text-[11px] font-medium text-[var(--text-muted)] uppercase">Mot de passe</div>
              <PasswordField
                value={item.login.password}
                {revealed}
                {strength}
                {onToggleReveal}
                onCopy={() => onCopy("Mot de passe", item.login!.password)}
              />
            </div>
          {/if}

          {#if item.login.totp}
            <div class="space-y-1.5">
              <div class="text-[11px] font-medium text-[var(--text-muted)] uppercase">Code 2FA (TOTP)</div>
              <TotpRing
                secretOrUri={item.login.totp.secret_base32}
                generateCode={onGenerateTotp}
                onCopy={(code) => onCopy("Code TOTP", code)}
              />
            </div>
          {/if}
        </div>
      {/if}

      {#if item.notes}
        <div class="space-y-1.5">
          <div class="text-[11px] font-medium text-[var(--text-muted)] uppercase">Notes chiffrées</div>
          <div class="anvil-selectable whitespace-pre-wrap rounded-[8px] border border-[var(--border-subtle)] bg-[var(--bg-elevated)] p-3.5 text-[13px] text-[var(--text-secondary)]">
            {item.notes}
          </div>
        </div>
      {/if}

      {#if item.login && item.login.password_history.length > 0}
        <div>
          <button
            type="button"
            onclick={() => (showHistory = !showHistory)}
            class="text-[12px] font-medium text-[var(--text-muted)] hover:text-[var(--text-primary)]"
          >
            {showHistory ? "▼" : "▶"} Historique des mots de passe ({item.login.password_history.length})
          </button>
          {#if showHistory}
            <div class="mt-2 space-y-1.5">
              {#each item.login.password_history as hist}
                <div class="flex items-center justify-between rounded-[6px] border border-[var(--border-subtle)] bg-[var(--bg-elevated)] px-3 py-1.5 text-[12px]">
                  <span class="text-[var(--text-muted)]">{hist.changed_at}</span>
                  <button
                    type="button"
                    onclick={() => onCopy("Ancien mot de passe", hist.password)}
                    class="text-[var(--accent-steel)] hover:underline"
                  >
                    Copier
                  </button>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/if}
    </div>
  {/if}
</main>
