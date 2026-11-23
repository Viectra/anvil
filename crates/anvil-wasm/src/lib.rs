//! WebAssembly cryptographic bridge, volatile session manager, and anti-phishing guard.

pub mod error;
pub mod security;
pub mod session;

#[cfg(target_arch = "wasm32")]
pub mod bindings {
    use anvil_core::crypto::KdfParams;
    use anvil_core::importers::{DuplicatePolicy, ImportFormat};
    use serde::{Deserialize, Serialize};
    use wasm_bindgen::prelude::*;

    use crate::error::WasmError;
    use crate::security::{evaluate_autofill_context, extract_registrable_domain};
    use crate::session::{
        EncryptedFolderEnvelopeDto, EncryptedItemEnvelopeDto, EphemeralSessionSealDto,
        PasswordGenOptionsDto, SaveItemInputDto, WasmAccountMeta, WasmVaultSession,
        derive_login_auth, evaluate_password_dto, generate_password_with_strength,
        prepare_registration,
    };

    fn err_js(err: impl ToString) -> JsValue {
        JsValue::from_str(&err.to_string())
    }

    fn parse_json<T: for<'de> Deserialize<'de>>(raw: &str) -> Result<T, JsValue> {
        serde_json::from_str(raw)
            .map_err(|e| WasmError::Serialization(e.to_string()))
            .map_err(err_js)
    }

    fn to_json<T: Serialize>(value: &T) -> Result<String, JsValue> {
        serde_json::to_string(value)
            .map_err(|e| WasmError::Serialization(e.to_string()))
            .map_err(err_js)
    }

    /// Evaluates frame anti-phishing safety without unlocking the vault.
    #[wasm_bindgen]
    pub fn assess_page_security(
        top_frame_url: &str,
        active_frame_url: &str,
        is_iframe: bool,
        approved_origins_json: &str,
    ) -> Result<String, JsValue> {
        let approved: Vec<String> = if approved_origins_json.trim().is_empty() {
            Vec::new()
        } else {
            parse_json(approved_origins_json)?
        };
        let verdict =
            evaluate_autofill_context(top_frame_url, active_frame_url, is_iframe, &approved);
        to_json(&verdict)
    }

    /// Extracts normalized eTLD+1 domain via the bundled Public Suffix List.
    #[wasm_bindgen]
    pub fn extract_base_domain_wasm(raw_url: &str) -> Option<String> {
        extract_registrable_domain(raw_url)
    }

    /// Derives Argon2id Zero-Knowledge registration keys in linear WASM memory.
    #[wasm_bindgen]
    pub fn prepare_registration_wasm(
        email: &str,
        master_password: &str,
        kdf_params_json: &str,
    ) -> Result<String, JsValue> {
        let params: KdfParams = parse_json(kdf_params_json)?;
        let res = prepare_registration(email, master_password, params).map_err(err_js)?;
        to_json(&res)
    }

    /// Derives `master_auth_hash_b64` from prelogin salt + KDF params.
    #[wasm_bindgen]
    pub fn derive_login_auth_wasm(
        master_password: &str,
        kdf_salt_b64: &str,
        kdf_params_json: &str,
    ) -> Result<String, JsValue> {
        let params: KdfParams = parse_json(kdf_params_json)?;
        let res = derive_login_auth(master_password, kdf_salt_b64, params).map_err(err_js)?;
        to_json(&res)
    }

    #[wasm_bindgen]
    pub fn generate_password_wasm(options_json: &str) -> Result<String, JsValue> {
        let opts: PasswordGenOptionsDto = parse_json(options_json)?;
        let res = generate_password_with_strength(opts).map_err(err_js)?;
        to_json(&res)
    }

    #[wasm_bindgen]
    pub fn evaluate_password_wasm(value: &str) -> Result<String, JsValue> {
        let res = evaluate_password_dto(value);
        to_json(&res)
    }

    /// Stateful WASM vault handle kept in Background Service Worker volatile RAM.
    #[wasm_bindgen]
    pub struct AnvilWasmClient {
        session: WasmVaultSession,
    }

    impl Default for AnvilWasmClient {
        fn default() -> Self {
            Self::new()
        }
    }

    #[wasm_bindgen]
    impl AnvilWasmClient {
        #[wasm_bindgen(constructor)]
        pub fn new() -> Self {
            Self {
                session: WasmVaultSession::new(),
            }
        }

        pub fn is_unlocked(&self) -> bool {
            self.session.is_unlocked()
        }

        pub fn lock(&mut self) {
            self.session.lock();
        }

        pub fn unlock_with_password(
            &mut self,
            account_json: &str,
            master_password: &str,
            folders_json: &str,
            items_json: &str,
        ) -> Result<(), JsValue> {
            let account: WasmAccountMeta = parse_json(account_json)?;
            let folders: Vec<EncryptedFolderEnvelopeDto> = parse_json(folders_json)?;
            let items: Vec<EncryptedItemEnvelopeDto> = parse_json(items_json)?;
            self.session
                .unlock_with_password(&account, master_password, &folders, &items)
                .map_err(err_js)
        }

        pub fn export_ephemeral_session(
            &self,
            ttl_seconds: u64,
            now_unix: u64,
        ) -> Result<String, JsValue> {
            let seal = self
                .session
                .export_ephemeral_session(ttl_seconds, now_unix)
                .map_err(err_js)?;
            to_json(&seal)
        }

        pub fn unlock_with_ephemeral_session(
            &mut self,
            account_json: &str,
            seal_json: &str,
            now_unix: u64,
            folders_json: &str,
            items_json: &str,
        ) -> Result<(), JsValue> {
            let account: WasmAccountMeta = parse_json(account_json)?;
            let seal: EphemeralSessionSealDto = parse_json(seal_json)?;
            let folders: Vec<EncryptedFolderEnvelopeDto> = parse_json(folders_json)?;
            let items: Vec<EncryptedItemEnvelopeDto> = parse_json(items_json)?;
            self.session
                .unlock_with_ephemeral_session(&account, &seal, now_unix, &folders, &items)
                .map_err(err_js)
        }

        pub fn apply_sync_delta(
            &mut self,
            folders_json: &str,
            items_json: &str,
        ) -> Result<(), JsValue> {
            let folders: Vec<EncryptedFolderEnvelopeDto> = parse_json(folders_json)?;
            let items: Vec<EncryptedItemEnvelopeDto> = parse_json(items_json)?;
            self.session
                .apply_sync_delta(&folders, &items)
                .map_err(err_js)
        }

        pub fn list_folders(&self) -> Result<String, JsValue> {
            let folders = self.session.list_folders().map_err(err_js)?;
            to_json(&folders)
        }

        pub fn encrypt_folder_upsert(
            &mut self,
            id: Option<String>,
            name: &str,
        ) -> Result<String, JsValue> {
            let (dto, envelope) = self
                .session
                .encrypt_folder_upsert(id.as_deref(), name)
                .map_err(err_js)?;
            to_json(&serde_json::json!({ "folder": dto, "envelope": envelope }))
        }

        pub fn encrypt_item_upsert(&mut self, input_json: &str) -> Result<String, JsValue> {
            let input: SaveItemInputDto = parse_json(input_json)?;
            let (detail, envelope) = self.session.encrypt_item_upsert(input).map_err(err_js)?;
            to_json(&serde_json::json!({ "item": detail, "envelope": envelope }))
        }

        pub fn remove_item_local(&mut self, item_id: &str) -> Result<String, JsValue> {
            let removed = self.session.remove_item_local(item_id).map_err(err_js)?;
            Ok(removed.to_string())
        }

        pub fn remove_folder_local(&mut self, folder_id: &str) -> Result<String, JsValue> {
            let removed = self
                .session
                .remove_folder_local(folder_id)
                .map_err(err_js)?;
            Ok(removed.to_string())
        }

        pub fn search_items(
            &self,
            query: &str,
            folder_id: Option<String>,
            favorites_only: bool,
            trashed_only: bool,
        ) -> Result<String, JsValue> {
            let rows = self
                .session
                .search_items(query, folder_id.as_deref(), favorites_only, trashed_only)
                .map_err(err_js)?;
            to_json(&rows)
        }

        pub fn match_items_for_url(
            &self,
            top_frame_url: &str,
            active_frame_url: &str,
            is_iframe: bool,
            approved_origins_json: &str,
        ) -> Result<String, JsValue> {
            let approved: Vec<String> = if approved_origins_json.trim().is_empty() {
                Vec::new()
            } else {
                parse_json(approved_origins_json)?
            };
            let matched = self
                .session
                .match_items_for_url(top_frame_url, active_frame_url, is_iframe, &approved)
                .map_err(err_js)?;
            to_json(&matched)
        }

        pub fn get_autofill_credentials(
            &self,
            item_id: &str,
            top_frame_url: &str,
            active_frame_url: &str,
            is_iframe: bool,
            approved_origins_json: &str,
            unix_timestamp_seconds: u64,
        ) -> Result<String, JsValue> {
            let approved: Vec<String> = if approved_origins_json.trim().is_empty() {
                Vec::new()
            } else {
                parse_json(approved_origins_json)?
            };
            let creds = self
                .session
                .get_autofill_credentials(
                    item_id,
                    top_frame_url,
                    active_frame_url,
                    is_iframe,
                    &approved,
                    unix_timestamp_seconds,
                )
                .map_err(err_js)?;
            to_json(&creds)
        }

        pub fn get_item_detail(&self, item_id: &str) -> Result<String, JsValue> {
            let detail = self.session.get_item_detail(item_id).map_err(err_js)?;
            to_json(&detail)
        }

        pub fn generate_totp(
            &self,
            secret_or_uri: &str,
            unix_timestamp_seconds: u64,
        ) -> Result<String, JsValue> {
            let code = self
                .session
                .generate_totp(secret_or_uri, unix_timestamp_seconds)
                .map_err(err_js)?;
            to_json(&code)
        }

        pub fn preview_import(
            &mut self,
            format_json: &str,
            bytes: &[u8],
            backup_password: Option<String>,
        ) -> Result<String, JsValue> {
            let format: ImportFormat = parse_json(format_json)?;
            let preview = self
                .session
                .preview_import(format, bytes, backup_password.as_deref())
                .map_err(err_js)?;
            to_json(&preview)
        }

        pub fn execute_import(
            &mut self,
            preview_id: &str,
            policy_json: &str,
        ) -> Result<String, JsValue> {
            let policy: DuplicatePolicy = parse_json(policy_json)?;
            let payload = self
                .session
                .execute_import(preview_id, policy)
                .map_err(err_js)?;
            to_json(&payload)
        }

        pub fn export_vault(
            &self,
            account_json: &str,
            format: &str,
            master_password: &str,
            backup_password: Option<String>,
        ) -> Result<Vec<u8>, JsValue> {
            let account: WasmAccountMeta = parse_json(account_json)?;
            self.session
                .export_vault(
                    &account,
                    format,
                    master_password,
                    backup_password.as_deref(),
                )
                .map_err(err_js)
        }
    }
}
