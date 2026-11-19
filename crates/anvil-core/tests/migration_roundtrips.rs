//! Integration tests for all multi-manager importers, dry-run deduplication, and exporters.

use std::error::Error;
use std::io::{Cursor, Write};

use aes::Aes256;
use anvil_core::crypto::{BitwardenKdfParams, BitwardenKdfType};
use anvil_core::exporters::{export_bitwarden_json, export_csv};
use anvil_core::importers::{
    ColumnMapping, DuplicatePolicy, ImportFormat, apply_import, preview_import,
};
use anvil_core::models::{ItemKind, ItemUri, LoginData, UriMatchMode, VaultItem, VaultSnapshot};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cbc::Encryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

type TestResult = Result<(), Box<dyn Error>>;

fn encrypt_bw_test_payload(
    plaintext: &str,
    password: &str,
    params: &BitwardenKdfParams,
) -> Result<String, Box<dyn Error>> {
    let mut master_key = [0u8; 32];
    match params.kdf_type {
        BitwardenKdfType::Pbkdf2Sha256 => {
            pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                params.salt.as_bytes(),
                params.iterations,
                &mut master_key,
            );
        }
        BitwardenKdfType::Argon2id => return Err("test uses PBKDF2".into()),
    }
    let hk = Hkdf::<Sha256>::from_prk(&master_key).map_err(|_| "hkdf prk")?;
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    hk.expand(b"enc", &mut enc_key).map_err(|_| "hkdf enc")?;
    hk.expand(b"mac", &mut mac_key).map_err(|_| "hkdf mac")?;

    let iv = [0x42u8; 16];
    let pt = plaintext.as_bytes();
    let mut buf = vec![0u8; pt.len() + 16];
    buf[..pt.len()].copy_from_slice(pt);
    let ct = Encryptor::<Aes256>::new_from_slices(&enc_key, &iv)
        .map_err(|_| "aes init")?
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt.len())
        .map_err(|_| "pkcs7 pad")?;

    let mut mac_calc = Hmac::<Sha256>::new_from_slice(&mac_key).map_err(|_| "hmac")?;
    mac_calc.update(&iv);
    mac_calc.update(ct);
    let mac = mac_calc.finalize().into_bytes();

    Ok(format!(
        "2.{}|{}|{}",
        BASE64_STANDARD.encode(iv),
        BASE64_STANDARD.encode(ct),
        BASE64_STANDARD.encode(mac),
    ))
}

#[test]
fn bitwarden_json_unencrypted_and_export_roundtrip() -> TestResult {
    let bw_json = r#"{
      "encrypted": false,
      "folders": [{"id": "f-1", "name": "Travail"}],
      "items": [
        {
          "type": 1,
          "name": "GitHub",
          "folderId": "f-1",
          "favorite": true,
          "notes": "Org Anvil",
          "fields": [{"name": "PIN", "value": "9482", "type": 1}],
          "login": {
            "username": "dev@corp.io",
            "password": "my-secret-password",
            "totp": "otpauth://totp/GitHub:dev@corp.io?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            "uris": [{"uri": "https://github.com/login", "match": 0}]
          },
          "passwordHistory": [{"password": "older-password", "lastUsedDate": "2025-05-01T00:00:00Z"}]
        },
        {
          "type": 2,
          "name": "SSH Recovery",
          "notes": "Printed in safe",
          "favorite": false
        }
      ]
    }"#;

    let mut vault = VaultSnapshot::default();
    let preview = preview_import(
        ImportFormat::BitwardenJson,
        bw_json.as_bytes(),
        None,
        &vault,
    )?;
    assert_eq!(preview.total_items, 2);
    assert_eq!(preview.totp_count, 1);

    let summary = apply_import(preview, DuplicatePolicy::Skip, &mut vault);
    assert_eq!(summary.created, 2);
    assert_eq!(summary.folders_created, 1);
    assert_eq!(vault.items.len(), 2);

    let exported = export_bitwarden_json(&vault)?;
    let mut reimported = VaultSnapshot::default();
    let re_preview = preview_import(
        ImportFormat::BitwardenJson,
        exported.as_bytes(),
        None,
        &reimported,
    )?;
    let re_sum = apply_import(re_preview, DuplicatePolicy::Skip, &mut reimported);
    assert_eq!(re_sum.created, 2);
    assert_eq!(reimported.folders[0].name, "Travail");
    assert!(reimported.items[0].favorite);
    Ok(())
}

#[test]
fn bitwarden_encrypted_json_and_csv_roundtrip() -> TestResult {
    let inner = r#"{
      "folders": [{"id": "1", "name": "Finance"}],
      "items": [{
        "type": 1,
        "name": "Bank",
        "folderId": "1",
        "login": {
          "username": "alice@example.com",
          "password": "bank-password-99",
          "totp": "JBSWY3DPEHPK3PXP",
          "uris": [{"uri": "https://bank.example.com", "match": 0}]
        }
      }]
    }"#;
    let params = BitwardenKdfParams {
        kdf_type: BitwardenKdfType::Pbkdf2Sha256,
        salt: "bw-test-salt".to_owned(),
        iterations: 5_000,
        memory_mb: None,
        parallelism: None,
    };
    let cipher = encrypt_bw_test_payload(inner, "export-pw", &params)?;
    let encrypted_json = serde_json::json!({
        "encrypted": true,
        "passwordProtected": true,
        "salt": "bw-test-salt",
        "kdfType": 0,
        "kdfIterations": 5000,
        "data": cipher
    })
    .to_string();

    let empty = VaultSnapshot::default();
    assert!(
        preview_import(
            ImportFormat::BitwardenEncryptedJson,
            encrypted_json.as_bytes(),
            Some("wrong"),
            &empty
        )
        .is_err()
    );

    let prev = preview_import(
        ImportFormat::BitwardenEncryptedJson,
        encrypted_json.as_bytes(),
        Some("export-pw"),
        &empty,
    )?;
    let mut vault = VaultSnapshot::default();
    let sum = apply_import(prev, DuplicatePolicy::CreateNew, &mut vault);
    assert_eq!(sum.created, 1);

    let csv_out = export_csv(&vault)?;
    let mut csv_vault = VaultSnapshot::default();
    let csv_prev = preview_import(
        ImportFormat::BitwardenCsv,
        csv_out.as_bytes(),
        None,
        &csv_vault,
    )?;
    let csv_sum = apply_import(csv_prev, DuplicatePolicy::CreateNew, &mut csv_vault);
    assert_eq!(csv_sum.created, 1);
    assert_eq!(csv_vault.items[0].title, "Bank");
    Ok(())
}

#[test]
fn browser_keepass_onepassword_and_generic_importers_work() -> TestResult {
    let empty = VaultSnapshot::default();

    // Chrome / Firefox CSV
    let chrome_csv = "\
name,url,username,password,note
GitLab,https://gitlab.com/users/sign_in,dev@corp.io,gl_secret,work account
Internal,chrome://settings,x,y,ignored
";
    let chrome_prev = preview_import(ImportFormat::ChromeCsv, chrome_csv.as_bytes(), None, &empty)?;
    assert_eq!(chrome_prev.total_items, 1);

    // KeePass CSV
    let kp_csv = "\
\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"
\"Servers\",\"SSH Root\",\"root\",\"kp-pass\",\"https://srv.example.net\",\"prod\",\"JBSWY3DPEHPK3PXP\"
\"Recycle Bin\",\"Old\",\"x\",\"y\",\"https://old.net\",\"\",\"\"
";
    let kp_csv_prev = preview_import(ImportFormat::KeePassCsv, kp_csv.as_bytes(), None, &empty)?;
    assert_eq!(kp_csv_prev.total_items, 1);
    assert_eq!(kp_csv_prev.totp_count, 1);

    // KeePass 2.x XML
    let kp_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Root>
    <Group>
      <Name>Database</Name>
      <Group>
        <Name>Cloud</Name>
        <Entry>
          <String><Key>Title</Key><Value>AWS</Value></String>
          <String><Key>UserName</Key><Value>ops@corp.io</Value></String>
          <String><Key>Password</Key><Value Protected="True">aws-new-pass</Value></String>
          <String><Key>URL</Key><Value>https://aws.amazon.com</Value></String>
          <String><Key>otp</Key><Value>otpauth://totp/AWS:ops?secret=JBSWY3DPEHPK3PXP</Value></String>
          <History>
            <Entry>
              <String><Key>Password</Key><Value Protected="True">aws-old-pass</Value></String>
            </Entry>
          </History>
        </Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>"#;
    let kp_xml_prev = preview_import(ImportFormat::KeePassXml, kp_xml.as_bytes(), None, &empty)?;
    assert_eq!(kp_xml_prev.total_items, 1);
    assert_eq!(kp_xml_prev.totp_count, 1);
    let xml_login = kp_xml_prev.parsed.items[0]
        .login
        .as_ref()
        .ok_or("missing login")?;
    assert_eq!(xml_login.password_history.len(), 1);

    // 1Password .1pux archive in memory
    let export_data = r#"{
      "accounts": [{
        "vaults": [{
          "attrs": {"name": "Personal"},
          "items": [{
            "favIndex": 1,
            "overview": {"title": "Cloudflare", "url": "https://dash.cloudflare.com"},
            "details": {
              "loginFields": [
                {"designation": "username", "value": "cf@domain.net"},
                {"designation": "password", "value": "cf-pass-123"}
              ],
              "notesPlain": "DNS root",
              "sections": [{"fields": [{"title": "2FA", "value": {"totp": "JBSWY3DPEHPK3PXP"}}]}],
              "passwordHistory": [{"value": "cf-old-pass", "time": 1700000000}]
            }
          }]
        }]
      }]
    }"#;
    let mut zip_buf = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut zip_buf);
        zw.start_file("export.data", SimpleFileOptions::default())?;
        zw.write_all(export_data.as_bytes())?;
        zw.finish()?;
    }
    let op_prev = preview_import(
        ImportFormat::OnePassword1pux,
        zip_buf.get_ref(),
        None,
        &empty,
    )?;
    assert_eq!(op_prev.total_items, 1);
    assert!(op_prev.parsed.items[0].favorite);
    assert_eq!(op_prev.totp_count, 1);

    // Proton Pass CSV (auto) and Generic CSV (manual column mapping)
    let proton_csv = "\
name,url,email,username,password,note,totp,vault
Proton,https://proton.me,me@proton.me,me,proton-pass,recovery,JBSWY3DPEHPK3PXP,Mail
";
    let proton_prev = preview_import(
        ImportFormat::ProtonPassCsv,
        proton_csv.as_bytes(),
        None,
        &empty,
    )?;
    assert_eq!(proton_prev.total_items, 1);

    let custom_csv = "\
service_col,secret_col,login_col,site_col
CustomApp,s3cr3t,bob,https://custom.example.org
";
    let mapping = ColumnMapping {
        title: Some(0),
        password: Some(1),
        username: Some(2),
        url: Some(3),
        ..Default::default()
    };
    let custom_prev = preview_import(
        ImportFormat::GenericCsv(mapping),
        custom_csv.as_bytes(),
        None,
        &empty,
    )?;
    assert_eq!(custom_prev.total_items, 1);
    assert_eq!(custom_prev.parsed.items[0].title, "CustomApp");
    Ok(())
}

#[test]
fn dry_run_duplicate_policies_skip_merge_and_create_new() -> TestResult {
    let existing_item = VaultItem::new_login(
        "GitHub Existing",
        LoginData {
            username: "dev@corp.io".to_owned(),
            email: "dev@corp.io".to_owned(),
            password: "old-github-password".to_owned(),
            password_history: vec![],
            uris: vec![ItemUri {
                uri: "https://github.com".to_owned(),
                match_mode: UriMatchMode::BaseDomain,
            }],
            totp: None,
        },
    );
    let base_vault = VaultSnapshot {
        folders: vec![],
        items: vec![existing_item],
        blobs: vec![],
    };

    let incoming_csv = "\
name,url,username,password,note,totp
GitHub,https://gist.github.com/login,dev@corp.io,new-github-password,merged note,JBSWY3DPEHPK3PXP
Fresh Site,https://fresh.example.org,alice,fresh-pass,,
";

    // Policy: Skip
    let mut skip_vault = base_vault.clone();
    let prev_skip = preview_import(
        ImportFormat::BitwardenCsv,
        "\
folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,0,login,GitHub,merged note,,0,https://gist.github.com/login,dev@corp.io,new-github-password,JBSWY3DPEHPK3PXP
,0,login,Fresh Site,,,0,https://fresh.example.org,alice,fresh-pass,
"
        .as_bytes(),
        None,
        &skip_vault,
    )?;
    assert_eq!(prev_skip.duplicates.len(), 1);
    let sum_skip = apply_import(prev_skip, DuplicatePolicy::Skip, &mut skip_vault);
    assert_eq!(sum_skip.skipped, 1);
    assert_eq!(sum_skip.created, 1);
    assert_eq!(skip_vault.items.len(), 2);

    // Policy: Merge (archives old password & adds TOTP)
    let mut merge_vault = base_vault.clone();
    let prev_merge = preview_import(
        ImportFormat::ProtonPassCsv,
        incoming_csv.as_bytes(),
        None,
        &merge_vault,
    )?;
    assert_eq!(prev_merge.duplicates.len(), 1);
    let sum_merge = apply_import(prev_merge, DuplicatePolicy::Merge, &mut merge_vault);
    assert_eq!(sum_merge.merged, 1);
    assert_eq!(sum_merge.created, 1);
    assert_eq!(merge_vault.items.len(), 2);

    let merged = merge_vault
        .items
        .iter()
        .find(|i| i.kind == ItemKind::Login && i.title == "GitHub Existing")
        .ok_or("merged item missing")?;
    let login = merged.login.as_ref().ok_or("missing login")?;
    assert_eq!(login.password, "new-github-password");
    assert_eq!(login.password_history.len(), 1);
    assert_eq!(login.password_history[0].password, "old-github-password");
    assert!(login.totp.is_some());
    assert!(merged.notes.contains("merged note"));

    // Policy: CreateNew
    let mut new_vault = base_vault;
    let prev_new = preview_import(
        ImportFormat::ProtonPassCsv,
        incoming_csv.as_bytes(),
        None,
        &new_vault,
    )?;
    let sum_new = apply_import(prev_new, DuplicatePolicy::CreateNew, &mut new_vault);
    assert_eq!(sum_new.created, 2);
    assert_eq!(new_vault.items.len(), 3);
    Ok(())
}
