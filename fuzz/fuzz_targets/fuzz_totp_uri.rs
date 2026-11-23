#![no_main]

use anvil_core::totp::TotpConfig;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(cfg) = TotpConfig::from_input(text)
    {
        let _ = cfg.generate_at(1_700_000_000);
        let rebuilt = cfg.to_otpauth_uri("FuzzIssuer");
        let _ = TotpConfig::from_input(&rebuilt);
    }
});
