// Included by both build.rs and lib.rs; use only core/std and no module declarations.

/// Stage magic values from psy_core/src/constants/protocol.rs:
/// MAINNET = 0x1337CF514544C069, TESTNET = 0x1337CF514544C169, REGTEST = 0x1337CF514544CF69.
///
/// The deployed testnet uses REGTEST magic. Switching to TESTNET magic requires
/// a fresh deployment because magic changes UPS circuit fingerprints and proving setup.
pub const STAGE_MAGICS: [(&str, u64); 3] = [
    ("localhost", 0x1337CF514544CF69),
    ("testnet", 0x1337CF514544CF69),
    ("mainnet", 0x1337CF514544C069),
];

/// Returns the stage's magic, or None for an unknown stage.
pub fn magic_for_stage(stage: &str) -> Option<u64> {
    let mut i = 0;
    while i < STAGE_MAGICS.len() {
        if STAGE_MAGICS[i].0 == stage {
            return Some(STAGE_MAGICS[i].1);
        }
        i += 1;
    }
    None
}

/// Parses configuration magic with an optional 0x prefix.
pub fn parse_magic_hex(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    let body = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if body.is_empty() {
        return Err("magic must not be empty".to_string());
    }
    u64::from_str_radix(body, 16).map_err(|e| format!("invalid magic {raw}: {e}"))
}

/// Human-readable stage names for diagnostics.
pub fn known_stages() -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < STAGE_MAGICS.len() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(STAGE_MAGICS[i].0);
        i += 1;
    }
    out
}
