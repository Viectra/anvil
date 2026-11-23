import type {
  AnvilClientBridge,
  ClipboardToastDto,
  ConflictItemDto,
  ConflictResolutionKind,
  DuplicatePolicy,
  FolderDto,
  ImportPreviewDto,
  ImportReportDto,
  ImportSourceKind,
  ItemDetailDto,
  ItemSummaryDto,
  PasswordGenOptionsDto,
  PasswordStrengthDto,
  SaveItemInputDto,
  SyncReportDto,
  TotpCodeDto,
  VaultStatusDto,
} from "@anvil/ui";

interface TauriInternals {
  invoke: <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
}

declare global {
  interface Window {
    __TAURI_INTERNALS__?: TauriInternals;
  }
}

export interface MobileStatusDto extends VaultStatusDto {
  biometric_kind: "android_keystore_strongbox" | "ios_secure_enclave" | "simulated_hardware";
  flag_secure_enabled: boolean;
  lock_on_background: boolean;
}

export type QrScanResultDto =
  | {
      kind: "onboarding";
      payload: {
        server_url: string;
        email: string | null;
        invite_token: string | null;
      };
    }
  | {
      kind: "totp";
      payload: {
        secret_base32: string;
        algorithm: "SHA1" | "SHA256" | "SHA512";
        digits: number;
        period_seconds: number;
        issuer: string | null;
        label: string | null;
      };
    };

async function invokeMobile<T>(cmd: string, payload: Record<string, unknown> = {}): Promise<T> {
  const internals = window.__TAURI_INTERNALS__;
  if (!internals || typeof internals.invoke !== "function") {
    throw new Error(`Tauri Mobile IPC indisponible pour '${cmd}'`);
  }
  return internals.invoke<T>(cmd, payload);
}

/** Mobile IPC adapter connecting touch Svelte 5 views to `anvil-mobile` and native device plugins. */
export class MobileAnvilBridge implements AnvilClientBridge {
  status(): Promise<MobileStatusDto> {
    return invokeMobile<MobileStatusDto>("cmd_status");
  }

  register(
    serverUrl: string,
    email: string,
    masterPassword: string,
    inviteToken: string | null,
  ): Promise<MobileStatusDto> {
    return invokeMobile<MobileStatusDto>("cmd_register", {
      serverUrl,
      email,
      masterPassword,
      inviteToken,
    });
  }

  login(serverUrl: string, email: string, masterPassword: string): Promise<MobileStatusDto> {
    return invokeMobile<MobileStatusDto>("cmd_login", {
      serverUrl,
      email,
      masterPassword,
    });
  }

  unlockWithPassword(masterPassword: string): Promise<MobileStatusDto> {
    return invokeMobile<MobileStatusDto>("cmd_unlock_password", { masterPassword });
  }

  async unlockWithBiometric(): Promise<MobileStatusDto> {
    try {
      await invokeMobile("plugin:biometric|authenticate", {
        reason: "Déverrouiller le coffre Anvil",
        allowDeviceCredential: false,
      });
    } catch {
      // Simulator or plugin unavailable: native backend decides hardware enclave availability.
    }
    return invokeMobile<MobileStatusDto>("cmd_unlock_biometric");
  }

  enableBiometric(masterPassword: string): Promise<MobileStatusDto> {
    return invokeMobile<MobileStatusDto>("cmd_enable_biometric", { masterPassword });
  }

  lock(): Promise<MobileStatusDto> {
    return invokeMobile<MobileStatusDto>("cmd_lock");
  }

  notifyAppBackgrounded(): Promise<MobileStatusDto> {
    return invokeMobile<MobileStatusDto>("cmd_on_app_backgrounded");
  }

  setPrivacySettings(
    flagSecureEnabled: boolean,
    lockOnBackground: boolean,
  ): Promise<MobileStatusDto> {
    return invokeMobile<MobileStatusDto>("cmd_set_privacy", {
      flagSecureEnabled,
      lockOnBackground,
    });
  }

  parseQrPayload(raw: string): Promise<QrScanResultDto> {
    return invokeMobile<QrScanResultDto>("cmd_parse_qr", { raw });
  }

  async scanQrWithCamera(): Promise<string> {
    const res = await invokeMobile<{ content?: string }>("plugin:barcode-scanner|scan", {
      windowed: false,
      formats: ["QR_CODE"],
    });
    if (!res?.content) {
      throw new Error("Aucun QR code détecté par la caméra");
    }
    return res.content;
  }

  attachTotpFromQr(itemId: string, rawQr: string): Promise<ItemDetailDto> {
    return invokeMobile<ItemDetailDto>("cmd_attach_totp_from_qr", { itemId, rawQr });
  }

  listFolders(): Promise<FolderDto[]> {
    return invokeMobile<FolderDto[]>("cmd_list_folders");
  }

  saveFolder(name: string, id: string | null = null): Promise<FolderDto> {
    return invokeMobile<FolderDto>("cmd_save_folder", { id, name });
  }

  deleteFolder(id: string): Promise<void> {
    return invokeMobile<void>("cmd_delete_folder", { id });
  }

  listItems(
    query: string,
    folderId: string | null,
    favoritesOnly: boolean,
    trashedOnly: boolean,
  ): Promise<ItemSummaryDto[]> {
    return invokeMobile<ItemSummaryDto[]>("cmd_list_items", {
      query,
      folderId,
      favoritesOnly,
      trashedOnly,
    });
  }

  getItem(id: string): Promise<ItemDetailDto> {
    return invokeMobile<ItemDetailDto>("cmd_get_item", { id });
  }

  saveItem(input: SaveItemInputDto): Promise<ItemDetailDto> {
    return invokeMobile<ItemDetailDto>("cmd_save_item", { input });
  }

  deleteItem(id: string): Promise<void> {
    return invokeMobile<void>("cmd_delete_item", { id });
  }

  uploadItemLogo(_itemId: string, _bytes: number[]): Promise<ItemDetailDto> {
    return Promise.reject(new Error("Upload logo non requis sur mobile"));
  }

  async copySecret(label: string, value: string): Promise<ClipboardToastDto> {
    await navigator.clipboard.writeText(value);
    const clearAfterSeconds = 30;
    const expiresAtMs = Date.now() + clearAfterSeconds * 1000;
    window.setTimeout(() => {
      void navigator.clipboard
        .readText()
        .then((cur) => {
          if (cur === value) return navigator.clipboard.writeText("");
          return undefined;
        })
        .catch(() => {});
    }, clearAfterSeconds * 1000);
    return {
      label,
      clear_after_seconds: clearAfterSeconds,
      expires_at_ms: expiresAtMs,
    };
  }

  generateTotp(secretOrUri: string, unixTimestampSeconds: number): Promise<TotpCodeDto> {
    return invokeMobile<TotpCodeDto>("cmd_generate_totp", {
      secretOrUri,
      unixTimestampSeconds,
    });
  }

  generatePassword(
    options: PasswordGenOptionsDto,
  ): Promise<{ value: string; strength: PasswordStrengthDto }> {
    return invokeMobile<{ value: string; strength: PasswordStrengthDto }>(
      "cmd_generate_password",
      { options },
    );
  }

  evaluatePassword(value: string): Promise<PasswordStrengthDto> {
    return invokeMobile<PasswordStrengthDto>("cmd_evaluate_password", { value });
  }

  previewImport(
    _format: ImportSourceKind,
    _bytes: number[],
    _backupPassword: string | null,
  ): Promise<ImportPreviewDto> {
    return Promise.reject(new Error("Utilisez Anvil Desktop pour l'import de masse"));
  }

  executeImport(_previewId: string, _policy: DuplicatePolicy): Promise<ImportReportDto> {
    return Promise.reject(new Error("Utilisez Anvil Desktop pour l'import de masse"));
  }

  exportVault(): Promise<number[]> {
    return Promise.reject(new Error("Utilisez Anvil Desktop pour l'export"));
  }

  syncNow(): Promise<SyncReportDto> {
    return invokeMobile<SyncReportDto>("cmd_sync");
  }

  listConflicts(): Promise<ConflictItemDto[]> {
    return invokeMobile<ConflictItemDto[]>("cmd_list_conflicts");
  }

  resolveConflict(
    conflictId: string,
    resolution: ConflictResolutionKind,
  ): Promise<SyncReportDto> {
    return invokeMobile<SyncReportDto>("cmd_resolve_conflict", {
      conflictId,
      resolution,
    });
  }
}
