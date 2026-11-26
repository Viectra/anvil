export type ItemKind = "login" | "secure_note";

export type UriMatchMode =
  | "base_domain"
  | "host"
  | "starts_with"
  | "exact"
  | "regex"
  | "never";

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export type DuplicatePolicy = "skip" | "merge" | "create_new";

export type ConflictResolutionKind = "keep_local" | "keep_server" | "duplicate_both";

export type ImportSourceKind =
  | "bitwarden_json"
  | "bitwarden_encrypted_json"
  | "bitwarden_csv"
  | "chrome_csv"
  | "edge_csv"
  | "brave_csv"
  | "firefox_csv"
  | "keepass_csv"
  | "keepass_xml"
  | "onepassword_csv"
  | "onepassword_1pux"
  | "proton_pass_csv"
  | "dashlane_csv";

export interface ItemUriDto {
  uri: string;
  match_mode: UriMatchMode;
}

export interface PasswordHistoryEntryDto {
  password: string;
  changed_at: string;
}

export interface CustomFieldDto {
  name: string;
  value: string;
  hidden: boolean;
}

export interface TotpConfigDto {
  secret_base32: string;
  algorithm: TotpAlgorithm;
  digits: number;
  period_seconds: number;
  issuer: string | null;
  label: string | null;
}

export interface ItemLogoDto {
  blob_id: string | null;
  fallback_color: string;
  data_url?: string | null;
}

export interface LoginDataDto {
  username: string;
  email: string;
  password: string;
  password_history: PasswordHistoryEntryDto[];
  uris: ItemUriDto[];
  totp: TotpConfigDto | null;
}

export interface ItemSummaryDto {
  id: string;
  kind: ItemKind;
  title: string;
  folder_id: string | null;
  favorite: boolean;
  trashed: boolean;
  subtitle: string;
  primary_url: string | null;
  has_totp: boolean;
  logo_blob_id: string | null;
  fallback_color: string;
  fallback_initials: string;
  updated_at: string;
}

export interface ItemDetailDto {
  id: string;
  schema_version: number;
  kind: ItemKind;
  title: string;
  folder_id: string | null;
  favorite: boolean;
  trashed_at: string | null;
  item_version: number;
  logo: ItemLogoDto;
  login: LoginDataDto | null;
  custom_fields: CustomFieldDto[];
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface SaveItemInputDto {
  id?: string | null;
  kind: ItemKind;
  title: string;
  folder_id: string | null;
  favorite: boolean;
  trashed_at: string | null;
  login: LoginDataDto | null;
  custom_fields: CustomFieldDto[];
  notes: string;
}

export interface FolderDto {
  id: string;
  name: string;
  created_at: string;
  updated_at: string;
}

export interface VaultStatusDto {
  configured: boolean;
  authenticated: boolean;
  unlocked: boolean;
  biometric_available: boolean;
  biometric_enabled: boolean;
  server_url: string | null;
  email: string | null;
  role?: string | null;
  avatar_data_url?: string | null;
  sync_revision: number;
  pending_conflicts: number;
}

export interface TotpCodeDto {
  code: string;
  remaining_seconds: number;
  period_seconds: number;
}

export interface PasswordGenOptionsDto {
  mode: "password" | "passphrase";
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  digits: boolean;
  symbols: boolean;
  exclude_ambiguous: boolean;
  word_count: number;
  separator: string;
  capitalize: boolean;
  include_number: boolean;
}

export interface PasswordStrengthDto {
  score: number;
  entropy_bits: number;
  crack_time_display: string;
  feedback_warning: string | null;
}

export interface DuplicateCandidateDto {
  imported_index: number;
  existing_item_id: string;
  title: string;
  identity: string;
  domain: string | null;
}

export interface ImportPreviewDto {
  preview_id: string;
  total_items: number;
  folder_count: number;
  totp_count: number;
  duplicates: DuplicateCandidateDto[];
  warnings: string[];
}

export interface ImportReportDto {
  created: number;
  merged: number;
  skipped: number;
  folders_created: number;
  warnings: string[];
}

export interface ConflictItemDto {
  conflict_id: string;
  entity_id: string;
  entity_kind: "item" | "folder";
  title: string;
  local_summary: string;
  server_summary: string;
  server_deleted: boolean;
  server_revision: number;
}

export interface SyncReportDto {
  current_revision: number;
  pushed_mutations: number;
  auto_merged_identical: number;
  pending_conflicts: number;
}

export interface ClipboardToastDto {
  label: string;
  clear_after_seconds: number;
  expires_at_ms: number;
}

export interface WindowChromeStateDto {
  platform: "windows" | "macos" | "linux";
  is_maximized: boolean;
  is_focused: boolean;
}
