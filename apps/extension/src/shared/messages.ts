import type {
  FolderDto,
  ItemDetailDto,
  ItemSummaryDto,
  PasswordGenOptionsDto,
  PasswordStrengthDto,
  SaveItemInputDto,
  SyncReportDto,
  TotpCodeDto,
  VaultStatusDto,
} from "@anvil/ui";

export type SecurityRiskLevel =
  | "safe"
  | "warn_http"
  | "blocked_invalid_url"
  | "blocked_cross_origin_iframe"
  | "blocked_idn_homograph"
  | "blocked_domain_mismatch";

export interface AutofillSecurityVerdictDto {
  allowed: boolean;
  silent_autofill_allowed: boolean;
  risk_level: SecurityRiskLevel;
  host: string | null;
  registrable_domain: string | null;
  origin: string | null;
  is_secure_context: boolean;
  is_idn_punycode: boolean;
  is_mixed_script: boolean;
  reasons: string[];
}

export interface UrlMatchResponseDto {
  security: AutofillSecurityVerdictDto;
  items: ItemSummaryDto[];
}

export interface AutofillCredentialDto {
  item_id: string;
  title: string;
  username: string;
  password: string;
  totp_code: string | null;
  security: AutofillSecurityVerdictDto;
}

export interface CapturedSubmissionDto {
  pageUrl: string;
  pageTitle: string;
  username: string;
  password: string;
  isPasswordChange: boolean;
}

export type ExtensionRequest =
  | { type: "anvil:status" }
  | {
      type: "anvil:register";
      serverUrl: string;
      email: string;
      masterPassword: string;
      inviteToken: string | null;
    }
  | { type: "anvil:login"; serverUrl: string; email: string; masterPassword: string }
  | { type: "anvil:unlock"; masterPassword: string }
  | { type: "anvil:lock" }
  | { type: "anvil:sync" }
  | { type: "anvil:list-folders" }
  | { type: "anvil:save-folder"; id: string | null; name: string }
  | { type: "anvil:delete-folder"; id: string }
  | {
      type: "anvil:list-items";
      query: string;
      folderId: string | null;
      favoritesOnly: boolean;
      trashedOnly: boolean;
    }
  | { type: "anvil:get-item"; id: string }
  | { type: "anvil:save-item"; input: SaveItemInputDto }
  | { type: "anvil:delete-item"; id: string }
  | { type: "anvil:generate-totp"; secretOrUri: string; unixTimestampSeconds: number }
  | { type: "anvil:generate-password"; options: PasswordGenOptionsDto }
  | { type: "anvil:evaluate-password"; value: string }
  | { type: "anvil:match-tab-url"; topFrameUrl: string; activeFrameUrl: string; isIframe: boolean }
  | {
      type: "anvil:get-autofill-credentials";
      itemId: string;
      topFrameUrl: string;
      activeFrameUrl: string;
      isIframe: boolean;
    }
  | { type: "anvil:approve-iframe-origin"; origin: string }
  | { type: "anvil:save-captured-credential"; submission: CapturedSubmissionDto }
  | { type: "anvil:fill-active-tab"; itemId: string };

export type ExtensionResponse<T = unknown> =
  | { ok: true; data: T }
  | { ok: false; error: string };

export interface TabBadgePayload {
  unlocked: boolean;
  matchCount: number;
  blocked: boolean;
}

export type PopupStatusSnapshot = {
  status: VaultStatusDto;
  folders: FolderDto[];
  items: ItemSummaryDto[];
  selectedItem: ItemDetailDto | null;
  totp?: TotpCodeDto;
  passwordStrength?: PasswordStrengthDto;
  syncReport?: SyncReportDto;
};
