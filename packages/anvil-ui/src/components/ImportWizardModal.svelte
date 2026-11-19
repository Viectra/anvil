<script lang="ts">
  import type {
    DuplicatePolicy,
    ImportPreviewDto,
    ImportReportDto,
    ImportSourceKind,
  } from "../lib/types.js";

  interface Props {
    open: boolean;
    onPreviewImport: (format: ImportSourceKind, bytes: number[], backupPassword: string | null) => Promise<ImportPreviewDto>;
    onExecuteImport: (previewId: string, policy: DuplicatePolicy) => Promise<ImportReportDto>;
    onExportVault: (format: "anvil" | "bitwarden_json" | "csv", masterPassword: string, backupPassword: string | null) => Promise<number[]>;
    onClose: () => void;
  }

  let { open, onPreviewImport, onExecuteImport, onExportVault, onClose }: Props = $props();

  let tab = $state<"import" | "export">("import");
  let format = $state<ImportSourceKind>("bitwarden_json");
  let selectedBytes = $state<number[] | null>(null);
  let selectedFileName = $state("");
  let backupPassword = $state("");
  let policy = $state<DuplicatePolicy>("skip");
  let preview = $state<ImportPreviewDto | null>(null);
  let report = $state<ImportReportDto | null>(null);

  let exportFormat = $state<"anvil" | "bitwarden_json" | "csv">("anvil");
  let exportMasterPw = $state("");
  let exportBackupPw = $state("");
  let errorMsg = $state<string | null>(null);

  const handleFile = async (event: Event) => {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    selectedFileName = file.name;
    selectedBytes = Array.from(new Uint8Array(await file.arrayBuffer()));
    preview = null;
    report = null;
    errorMsg = null;
  };

  const runDryRun = async () => {
    if (!selectedBytes) return;
    errorMsg = null;
    try {
      preview = await onPreviewImport(format, selectedBytes, backupPassword || null);
      backupPassword = "";
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : String(err);
    }
  };

  const commitImport = async () => {
    if (!preview) return;
    errorMsg = null;
    try {
      report = await onExecuteImport(preview.preview_id, policy);
      preview = null;
      selectedBytes = null;
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : String(err);
    }
  };

  const runExport = async () => {
    const mp = exportMasterPw;
    const bp = exportBackupPw.trim() || null;
    exportMasterPw = "";
    exportBackupPw = "";
    if (!mp) return;
    errorMsg = null;
    try {
      const bytes = await onExportVault(exportFormat, mp, bp);
      const blob = new Blob([new Uint8Array(bytes)], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download =
        exportFormat === "anvil"
          ? "anvil-backup.anvil"
          : exportFormat === "bitwarden_json"
            ? "anvil-export-bitwarden.json"
            : "anvil-export-plaintext.csv";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      errorMsg = err instanceof Error ? err.message : String(err);
    }
  };
</script>

{#if open}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" role="dialog" aria-modal="true" aria-label="Import et Export">
    <div class="w-full max-w-[560px] rounded-[12px] border border-[var(--border-default)] bg-[var(--bg-elevated)] p-6">
      <div class="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
        <h2 class="text-[18px] font-semibold text-[var(--text-primary)]">Import / Export du coffre</h2>
        <button type="button" onclick={onClose} class="text-[var(--text-muted)] hover:text-[var(--text-primary)]">✕</button>
      </div>

      <div class="mt-4 flex gap-2 text-[12.5px]">
        <button
          type="button"
          onclick={() => (tab = "import")}
          class="flex-1 rounded-[6px] border py-1.5 font-medium"
          style:border-color={tab === "import" ? "var(--accent-forge)" : "var(--border-default)"}
          style:color={tab === "import" ? "var(--accent-forge)" : "var(--text-secondary)"}
        >
          Importer
        </button>
        <button
          type="button"
          onclick={() => (tab = "export")}
          class="flex-1 rounded-[6px] border py-1.5 font-medium"
          style:border-color={tab === "export" ? "var(--accent-forge)" : "var(--border-default)"}
          style:color={tab === "export" ? "var(--accent-forge)" : "var(--text-secondary)"}
        >
          Exporter
        </button>
      </div>

      {#if errorMsg}
        <div class="mt-3 rounded-[6px] border border-[var(--status-danger)] bg-[rgba(224,79,95,0.1)] px-3 py-2 text-[12px] text-[var(--status-danger)]">
          {errorMsg}
        </div>
      {/if}

      {#if tab === "import"}
        <div class="mt-4 space-y-3 text-[12.5px]">
          <label class="block space-y-1 text-[var(--text-secondary)]">
            <span>Source d'import</span>
            <select
              bind:value={format}
              class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 text-[var(--text-primary)]"
            >
              <option value="bitwarden_json">Bitwarden JSON (clair)</option>
              <option value="bitwarden_encrypted_json">Bitwarden JSON chiffré (encType=2)</option>
              <option value="bitwarden_csv">Bitwarden CSV</option>
              <option value="chrome_csv">Chrome / Edge / Brave / Firefox CSV</option>
              <option value="keepass_xml">KeePass / KeePassXC XML 2.x</option>
              <option value="keepass_csv">KeePass / KeePassXC CSV</option>
              <option value="onepassword_1pux">1Password Archive (.1pux)</option>
              <option value="onepassword_csv">1Password CSV</option>
              <option value="proton_pass_csv">Proton Pass / Dashlane CSV</option>
            </select>
          </label>

          <label class="block space-y-1 text-[var(--text-secondary)]">
            <span>Fichier d'export {selectedFileName ? `(${selectedFileName})` : ""}</span>
            <input type="file" onchange={handleFile} class="block w-full text-[12px] text-[var(--text-secondary)]" />
          </label>

          {#if format === "bitwarden_encrypted_json"}
            <label class="block space-y-1 text-[var(--text-secondary)]">
              <span>Mot de passe de sauvegarde Bitwarden</span>
              <input
                type="password"
                bind:value={backupPassword}
                class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 text-[var(--text-primary)]"
              />
            </label>
          {/if}

          {#if !preview}
            <button
              type="button"
              disabled={!selectedBytes}
              onclick={() => void runDryRun()}
              class="rounded-[6px] bg-[var(--accent-forge)] px-4 py-1.5 font-semibold text-[#0B0C0F] disabled:opacity-50"
            >
              Analyser avant import (Dry-Run)
            </button>
          {/if}

          {#if preview}
            <div class="space-y-2 rounded-[8px] border border-[var(--border-default)] bg-[var(--bg-surface)] p-3.5">
              <div class="font-semibold text-[var(--text-primary)]">Aperçu avant écriture</div>
              <div class="text-[var(--text-secondary)]">
                {preview.total_items} fiches, {preview.folder_count} dossiers, {preview.totp_count} codes TOTP, {preview.duplicates.length} doublon(s).
              </div>
              <label class="block space-y-1">
                <span class="text-[var(--text-secondary)]">Gestion des doublons</span>
                <select bind:value={policy} class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-elevated)] px-2.5 py-1.5 text-[var(--text-primary)]">
                  <option value="skip">Ignorer les doublons (Skip)</option>
                  <option value="merge">Fusionner et archiver ancien mot de passe (Merge)</option>
                  <option value="create_new">Créer comme nouvelles fiches (CreateNew)</option>
                </select>
              </label>
              <button
                type="button"
                onclick={() => void commitImport()}
                class="rounded-[6px] bg-[var(--status-secure)] px-4 py-1.5 font-semibold text-[#0B0C0F]"
              >
                Confirmer l'importation chiffrée
              </button>
            </div>
          {/if}

          {#if report}
            <div class="rounded-[8px] border border-[var(--status-secure)] bg-[rgba(47,179,121,0.1)] p-3 text-[var(--status-secure)]">
              Import terminé : {report.created} créées, {report.merged} fusionnées, {report.skipped} ignorées.
            </div>
          {/if}
        </div>
      {:else}
        <div class="mt-4 space-y-3 text-[12.5px]">
          <label class="block space-y-1 text-[var(--text-secondary)]">
            <span>Format d'export</span>
            <select bind:value={exportFormat} class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 text-[var(--text-primary)]">
              <option value="anvil">Archive chiffrée native (.anvil)</option>
              <option value="bitwarden_json">Bitwarden JSON (en clair)</option>
              <option value="csv">CSV standard (en clair)</option>
            </select>
          </label>

          {#if exportFormat !== "anvil"}
            <div class="rounded-[6px] border border-[var(--status-warning)] bg-[rgba(229,169,60,0.1)] px-3 py-2 text-[12px] text-[var(--status-warning)]">
              Attention : ce format écrit vos mots de passe et secrets TOTP en clair sur le disque.
            </div>
          {:else}
            <label class="block space-y-1 text-[var(--text-secondary)]">
              <span>Mot de passe de l'archive (optionnel, défaut : mot de passe maître)</span>
              <input type="password" bind:value={exportBackupPw} class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 text-[var(--text-primary)]" />
            </label>
          {/if}

          <label class="block space-y-1 text-[var(--text-secondary)]">
            <span>Confirmez votre mot de passe maître *</span>
            <input type="password" bind:value={exportMasterPw} required class="w-full rounded-[6px] border border-[var(--border-default)] bg-[var(--bg-surface)] px-3 py-2 text-[var(--text-primary)]" />
          </label>

          <button
            type="button"
            disabled={!exportMasterPw}
            onclick={() => void runExport()}
            class="rounded-[6px] bg-[var(--accent-forge)] px-4 py-1.5 font-semibold text-[#0B0C0F] disabled:opacity-50"
          >
            Télécharger l'export
          </button>
        </div>
      {/if}
    </div>
  </div>
{/if}
