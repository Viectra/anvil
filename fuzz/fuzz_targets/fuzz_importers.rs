#![no_main]

use anvil_core::crypto::MasterPassword;
use anvil_core::exporters::import_anvil_archive;
use anvil_core::importers::{ImportFormat, preview_import};
use anvil_core::models::VaultSnapshot;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let empty = VaultSnapshot::default();
    let formats = [
        ImportFormat::BitwardenJson,
        ImportFormat::BitwardenEncryptedJson,
        ImportFormat::BitwardenCsv,
        ImportFormat::ChromeCsv,
        ImportFormat::KeePassCsv,
        ImportFormat::KeePassXml,
        ImportFormat::OnePasswordCsv,
        ImportFormat::OnePassword1pux,
        ImportFormat::ProtonPassCsv,
    ];
    for fmt in formats {
        let _ = preview_import(fmt, data, Some("fuzz-pw"), &empty);
    }
    let _ = import_anvil_archive(data, &MasterPassword::new("fuzz-pw"));
});
