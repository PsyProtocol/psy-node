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