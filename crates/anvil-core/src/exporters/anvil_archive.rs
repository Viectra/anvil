//! Native encrypted `.anvil` backup archive preserving folders, entries, and custom logos.

use std::io::{Read, Write};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::kdf::{KDF_SALT_LEN, derive_master_key_raw};
use crate::crypto::{
    KEY_LEN, KdfAlgorithm, KdfParams, MasterPassword, decrypt_envelope, encrypt_envelope,
    generate_kdf_salt,
};
use crate::error::AnvilError;
use crate::models::{VaultBlob, VaultFolder, VaultItem, VaultSnapshot};

const ARCHIVE_MAGIC: &[u8; 4] = b"ANVL";
const ARCHIVE_VERSION_V1: u8 = 0x01;
const ARCHIVE_HEADER_LEN: usize = 4 + 1 + 12 + KDF_SALT_LEN;
const ARCHIVE_INFO: &[u8] = b"anvil:v1:archive-export";
const MAX_ARCHIVE_DECOMPRESSED_BYTES: usize = 128 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct ArchivePayload {
    archive_version: u32,
    exported_at: DateTime<Utc>,
    folders: Vec<VaultFolder>,
    items: Vec<VaultItem>,
    blobs: Vec<ArchiveBlob>,
}

#[derive(Serialize, Deserialize)]
struct ArchiveBlob {
    id: Uuid,
    item_id: Uuid,
    mime_type: String,
    data_b64: String,
    updated_at: DateTime<Utc>,
}

/// Exports the full vault snapshot (including custom logos) into a password-encrypted `.anvil` archive.
pub fn export_anvil_archive(
    snapshot: &VaultSnapshot,
    backup_password: &MasterPassword,
) -> Result<Vec<u8>, AnvilError> {
    export_anvil_archive_with_params(snapshot, backup_password, &KdfParams::default(), true)
}

pub(crate) fn export_anvil_archive_with_params(
    snapshot: &VaultSnapshot,
    backup_password: &MasterPassword,
    params: &KdfParams,
    enforce_bounds: bool,
) -> Result<Vec<u8>, AnvilError> {
    if enforce_bounds {
        params.validate()?;
    }
    let salt = generate_kdf_salt()?;
    let key = derive_archive_key(backup_password, &salt, params)?;

    let payload = ArchivePayload {
        archive_version: 1,
        exported_at: Utc::now(),
        folders: snapshot.folders.clone(),
        items: snapshot
            .items
            .iter()
            .filter(|i| i.trashed_at.is_none())
            .cloned()
            .collect(),
        blobs: snapshot
            .blobs
            .iter()
            .map(|b| ArchiveBlob {
                id: b.id,
                item_id: b.item_id,
                mime_type: b.mime_type.clone(),
                data_b64: BASE64_STANDARD.encode(&*b.data),
                updated_at: b.updated_at,
            })
            .collect(),
    };

    let json = Zeroizing::new(serde_json::to_vec(&payload)?);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&json)
        .map_err(|e| AnvilError::ExportError(format!("gzip compression failed: {e}")))?;
    let compressed = Zeroizing::new(
        encoder
            .finish()
            .map_err(|e| AnvilError::ExportError(format!("gzip finish failed: {e}")))?,
    );

    let mut header = Vec::with_capacity(ARCHIVE_HEADER_LEN);
    header.extend_from_slice(ARCHIVE_MAGIC);
    header.push(ARCHIVE_VERSION_V1);
    header.extend_from_slice(&params.memory_kib.to_be_bytes());
    header.extend_from_slice(&params.iterations.to_be_bytes());
    header.extend_from_slice(&params.parallelism.to_be_bytes());
    header.extend_from_slice(&salt);

    let envelope = encrypt_envelope(&key, &compressed, &header)?;

    let mut out = Vec::with_capacity(header.len() + envelope.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&envelope);
    Ok(out)
}

/// Decrypts and restores a `.anvil` backup archive after verifying its authenticated header and KDF bounds.
pub fn import_anvil_archive(
    archive_bytes: &[u8],
    backup_password: &MasterPassword,
) -> Result<VaultSnapshot, AnvilError> {
    import_anvil_archive_inner(archive_bytes, backup_password, true)
}

pub(crate) fn import_anvil_archive_inner(
    archive_bytes: &[u8],
    backup_password: &MasterPassword,
    enforce_bounds: bool,
) -> Result<VaultSnapshot, AnvilError> {
    if archive_bytes.len() <= ARCHIVE_HEADER_LEN {
        return Err(AnvilError::InvalidEnvelope);
    }
    if &archive_bytes[..4] != ARCHIVE_MAGIC {
        return Err(AnvilError::UnsupportedImportFormat);
    }
    let version = archive_bytes[4];
    if version != ARCHIVE_VERSION_V1 {
        return Err(AnvilError::UnsupportedEnvelopeVersion(version));
    }

    let memory_kib = u32::from_be_bytes([
        archive_bytes[5],
        archive_bytes[6],
        archive_bytes[7],
        archive_bytes[8],
    ]);
    let iterations = u32::from_be_bytes([
        archive_bytes[9],
        archive_bytes[10],
        archive_bytes[11],
        archive_bytes[12],
    ]);
    let parallelism = u32::from_be_bytes([
        archive_bytes[13],
        archive_bytes[14],
        archive_bytes[15],
        archive_bytes[16],
    ]);
    let params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib,
        iterations,
        parallelism,
    };
    if enforce_bounds {
        params.validate()?;
    }

    let mut salt = [0u8; KDF_SALT_LEN];
    salt.copy_from_slice(&archive_bytes[17..ARCHIVE_HEADER_LEN]);

    let key = derive_archive_key(backup_password, &salt, &params)?;
    let header = &archive_bytes[..ARCHIVE_HEADER_LEN];
    let envelope = &archive_bytes[ARCHIVE_HEADER_LEN..];

    let compressed = decrypt_envelope(&key, envelope, header).map_err(|err| match err {
        AnvilError::DecryptionFailed => AnvilError::WrongBackupPassword,
        other => other,
    })?;

    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut decompressed = Zeroizing::new(Vec::new());
    let limit = (MAX_ARCHIVE_DECOMPRESSED_BYTES as u64) + 1;
    (&mut decoder)
        .take(limit)
        .read_to_end(&mut decompressed)
        .map_err(|e| AnvilError::ImportError(format!("corrupted .anvil gzip stream: {e}")))?;

    if decompressed.len() > MAX_ARCHIVE_DECOMPRESSED_BYTES {
        return Err(AnvilError::ArchiveLimitExceeded(format!(
            "decompressed .anvil payload exceeds {MAX_ARCHIVE_DECOMPRESSED_BYTES} bytes"
        )));
    }

    let payload: ArchivePayload = serde_json::from_slice(&decompressed)?;
    let mut blobs = Vec::with_capacity(payload.blobs.len());
    for b in payload.blobs {
        let raw = BASE64_STANDARD.decode(&b.data_b64).map_err(|_| {
            AnvilError::ImportError("invalid base64 logo blob in .anvil".to_owned())
        })?;
        blobs.push(VaultBlob {
            id: b.id,
            item_id: b.item_id,
            mime_type: b.mime_type,
            data: Zeroizing::new(raw),
            updated_at: b.updated_at,
        });
    }

    Ok(VaultSnapshot {
        folders: payload.folders,
        items: payload.items,
        blobs,
    })
}

fn derive_archive_key(
    password: &MasterPassword,
    salt: &[u8; KDF_SALT_LEN],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, AnvilError> {
    let mk = derive_master_key_raw(password, salt, params)?;
    let hk = Hkdf::<Sha256>::new(Some(salt), mk.as_bytes());
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(ARCHIVE_INFO, &mut *key)
        .map_err(|_| AnvilError::HkdfFailed)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ItemUri, LoginData, UriMatchMode};
    use crate::totp::TotpConfig;

    #[test]
    fn anvil_archive_roundtrip_preserves_folders_items_and_logos() {
        let folder = VaultFolder::new("Infrastructure");
        let mut item = VaultItem::new_login(
            "Proxmox",
            LoginData {
                username: "root@pam".to_owned(),
                email: String::new(),
                password: "pve-secret-password".to_owned(),
                password_history: vec![],
                uris: vec![ItemUri {
                    uri: "https://pve.lan:8006".to_owned(),
                    match_mode: UriMatchMode::Host,
                }],
                totp: Some(TotpConfig::from_input("JBSWY3DPEHPK3PXP").expect("totp")),
            },
        );
        item.folder_id = Some(folder.id);
        let blob_id = Uuid::new_v4();
        item.logo.blob_id = Some(blob_id);

        let blob = VaultBlob {
            id: blob_id,
            item_id: item.id,
            mime_type: "image/png".to_owned(),
            data: Zeroizing::new(vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            updated_at: Utc::now(),
        };

        let snapshot = VaultSnapshot {
            folders: vec![folder],
            items: vec![item],
            blobs: vec![blob],
        };

        let pw = MasterPassword::new("archive-master-pass");
        let fast = KdfParams::fast_for_tests();
        let archive =
            export_anvil_archive_with_params(&snapshot, &pw, &fast, false).expect("export");

        let restored = import_anvil_archive_inner(&archive, &pw, false).expect("restore");
        assert_eq!(restored.folders.len(), 1);
        assert_eq!(restored.folders[0].name, "Infrastructure");
        assert_eq!(restored.items.len(), 1);
        assert_eq!(restored.items[0].title, "Proxmox");
        assert_eq!(restored.blobs.len(), 1);
        assert_eq!(
            &*restored.blobs[0].data,
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        );

        let wrong_pw = MasterPassword::new("wrong-password");
        assert!(matches!(
            import_anvil_archive_inner(&archive, &wrong_pw, false),
            Err(AnvilError::WrongBackupPassword)
        ));

        // Tamper KDF header field (bound in AAD).
        let mut tampered_header = archive.clone();
        tampered_header[8] ^= 0x01;
        assert!(import_anvil_archive_inner(&tampered_header, &pw, false).is_err());

        // Also validate full OWASP default public entrypoints.
        let owasp_archive = export_anvil_archive(&snapshot, &pw).expect("owasp export");
        let owasp_restored = import_anvil_archive(&owasp_archive, &pw).expect("owasp restore");
        assert_eq!(owasp_restored.items.len(), 1);
    }
}
