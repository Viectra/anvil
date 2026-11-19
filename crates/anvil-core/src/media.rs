//! Client-side account logo processing (EXIF stripping, resizing) and fallback avatars.

#[cfg(feature = "media")]
use std::io::Cursor;

#[cfg(feature = "media")]
use image::ImageFormat;
#[cfg(feature = "media")]
use image::imageops::FilterType;

#[cfg(feature = "media")]
use crate::error::AnvilError;

/// Maximum raw image input size accepted for client-side logo processing (5 MiB).
pub const MAX_INPUT_LOGO_BYTES: usize = 5 * 1024 * 1024;
/// Maximum encrypted/encoded logo output size matching server `vault_blobs` limit (256 KiB).
pub const MAX_OUTPUT_LOGO_BYTES: usize = 256 * 1024;
/// Maximum logo width or height in pixels.
pub const MAX_LOGO_DIMENSION: u32 = 128;

const ACCENT_PALETTE: [&str; 5] = ["#E07A2F", "#5B8DEF", "#2FB379", "#E5A93C", "#E63946"];

/// Normalized, metadata-stripped PNG logo ready for client-side encryption.
#[cfg(feature = "media")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessedLogo {
    pub mime_type: String,
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

/// Decodes an uploaded image, scales it down to <= 128x128, and re-encodes as PNG to strip all EXIF metadata.
#[cfg(feature = "media")]
pub fn process_custom_logo(raw_bytes: &[u8]) -> Result<ProcessedLogo, AnvilError> {
    if raw_bytes.is_empty() {
        return Err(AnvilError::MediaError("logo image is empty".to_owned()));
    }
    if raw_bytes.len() > MAX_INPUT_LOGO_BYTES {
        return Err(AnvilError::MediaError(format!(
            "logo exceeds maximum input size of {MAX_INPUT_LOGO_BYTES} bytes"
        )));
    }

    let decoded = image::load_from_memory(raw_bytes)
        .map_err(|e| AnvilError::MediaError(format!("unsupported or invalid image: {e}")))?;

    let mut current =
        if decoded.width() > MAX_LOGO_DIMENSION || decoded.height() > MAX_LOGO_DIMENSION {
            decoded.resize(MAX_LOGO_DIMENSION, MAX_LOGO_DIMENSION, FilterType::Lanczos3)
        } else {
            decoded
        };

    for target_dim in [MAX_LOGO_DIMENSION, 96, 64] {
        if current.width() > target_dim || current.height() > target_dim {
            current = current.resize(target_dim, target_dim, FilterType::Lanczos3);
        }
        let mut out = Cursor::new(Vec::new());
        current
            .write_to(&mut out, ImageFormat::Png)
            .map_err(|e| AnvilError::MediaError(format!("PNG encoding failed: {e}")))?;
        let png_bytes = out.into_inner();
        if png_bytes.len() <= MAX_OUTPUT_LOGO_BYTES {
            return Ok(ProcessedLogo {
                mime_type: "image/png".to_owned(),
                bytes: png_bytes,
                width: current.width(),
                height: current.height(),
            });
        }
    }

    Err(AnvilError::MediaError(format!(
        "processed PNG exceeds maximum blob limit of {MAX_OUTPUT_LOGO_BYTES} bytes"
    )))
}

/// Computes stylized 1-2 character initials from a vault entry title.
pub fn fallback_initials(title: &str) -> String {
    let words: Vec<&str> = title
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();

    match words.as_slice() {
        [] => "AN".to_owned(),
        [single] => single
            .chars()
            .take(2)
            .map(|c| c.to_ascii_uppercase())
            .collect(),
        [first, second, ..] => {
            let mut out = String::with_capacity(2);
            if let Some(c) = first.chars().next() {
                out.push(c.to_ascii_uppercase());
            }
            if let Some(c) = second.chars().next() {
                out.push(c.to_ascii_uppercase());
            }
            out
        }
    }
}

/// Picks a deterministic Forge/Steel palette hex color for an entry title.
pub fn fallback_accent_color(title: &str) -> &'static str {
    let mut hash: u32 = 2_166_136_261;
    for byte in title.as_bytes() {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    ACCENT_PALETTE[(hash as usize) % ACCENT_PALETTE.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_initials_and_color_are_clean_and_deterministic() {
        assert_eq!(fallback_initials("GitHub — Travail"), "GT");
        assert_eq!(fallback_initials("Cloudflare"), "CL");
        assert_eq!(fallback_initials(""), "AN");
        assert_eq!(
            fallback_accent_color("GitHub"),
            fallback_accent_color("GitHub")
        );
    }

    #[cfg(feature = "media")]
    #[test]
    fn process_custom_logo_resizes_and_strips_metadata() {
        let img = image::RgbaImage::from_fn(256, 128, |x, y| {
            image::Rgba([(x % 255) as u8, (y % 255) as u8, 120, 255])
        });
        let mut raw_buf = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut raw_buf, ImageFormat::Png)
            .expect("encode test png");

        let bytes_with_fake_chunk = raw_buf.into_inner();
        assert!(!bytes_with_fake_chunk.is_empty());
        // Verify oversized raw payload rejection before decode.
        let oversized = vec![0u8; MAX_INPUT_LOGO_BYTES + 1];
        assert!(process_custom_logo(&oversized).is_err());

        let processed = process_custom_logo(&bytes_with_fake_chunk).expect("logo processed");
        assert_eq!(processed.mime_type, "image/png");
        assert!(processed.width <= MAX_LOGO_DIMENSION);
        assert!(processed.height <= MAX_LOGO_DIMENSION);
        assert!(processed.bytes.len() <= MAX_OUTPUT_LOGO_BYTES);
    }
}
