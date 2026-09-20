use anyhow::Context;

/// Magic prefix tag for zstd-compressed values: "PSZ1" (4 bytes).
/// Values written by this module always start with this tag followed by a zstd frame.
/// Values without this tag are treated as legacy raw serialized bytes (pre-compression).
const COMPRESSED_MAGIC: &[u8] = b"PSZ1";

pub fn compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(COMPRESSED_MAGIC.len() + data.len() / 4);
    out.extend_from_slice(COMPRESSED_MAGIC);
    let compressed = zstd::encode_all(data, 3).context("zstd compress failed")?;
    out.extend_from_slice(&compressed);
    Ok(out)
}

pub fn decompress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    // Check for compression magic prefix
    if data.len() >= COMPRESSED_MAGIC.len() && &data[..COMPRESSED_MAGIC.len()] == COMPRESSED_MAGIC {
        // New format: magic prefix + zstd frame
        zstd::decode_all(&data[COMPRESSED_MAGIC.len()..])
            .context("zstd decompress failed")
    } else {
        // Legacy format: raw serialized bytes (no compression)
        Ok(data.to_vec())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn compress_round_trips_and_prefixes_magic() {
        let original = (0u8..=255).cycle().take(2048).collect::<Vec<_>>();
        let encoded = compress(&original).unwrap();
        assert!(encoded.starts_with(COMPRESSED_MAGIC));
        assert_ne!(encoded, original);
        assert_eq!(decompress(&encoded).unwrap(), original);
    }

    #[test]
    fn compress_empty_round_trips() {
        let encoded = compress(&[]).unwrap();
        assert!(encoded.starts_with(COMPRESSED_MAGIC));
        assert_eq!(decompress(&encoded).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decompress_legacy_bytes_without_magic() {
        let raw = b"pre-compression-payload";
        assert_eq!(decompress(raw).unwrap(), raw);
        assert_eq!(decompress(&[]).unwrap(), Vec::<u8>::new());
        assert_eq!(decompress(b"PSZ").unwrap(), b"PSZ");
    }

    #[test]
    fn decompress_rejects_truncated_zstd_after_magic() {
        assert!(decompress(b"PSZ1not-a-zstd-frame").is_err());
        assert!(decompress(COMPRESSED_MAGIC).is_err());
    }
}