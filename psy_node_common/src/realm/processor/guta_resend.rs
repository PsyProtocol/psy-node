//! Resend policy for a Realm GUTA submission that the Coordinator accepted but did not include.

/// Environment variable that overrides [`REALM_GUTA_RESEND_AFTER_CHECKPOINTS_DEFAULT`].
pub const REALM_GUTA_RESEND_AFTER_CHECKPOINTS_ENV: &str = "REALM_GUTA_RESEND_AFTER_CHECKPOINTS";

/// Coordinator checkpoints a submission may stay unincluded before the Realm resends it.
pub const REALM_GUTA_RESEND_AFTER_CHECKPOINTS_DEFAULT: u64 = 10;

/// A submission can sit in a live Coordinator batch for two checkpoints after it was sent: one
/// batch may be proving and one gathering. A resend before that can put a second copy into the
/// next batch, which fails the planner's leaf check and parks the Coordinator Processor.
pub const REALM_GUTA_RESEND_MIN_CHECKPOINTS: u64 = 2;

const _: () = assert!(REALM_GUTA_RESEND_AFTER_CHECKPOINTS_DEFAULT >= REALM_GUTA_RESEND_MIN_CHECKPOINTS);

pub fn parse_realm_guta_resend_after_checkpoints(raw: Option<&str>) -> anyhow::Result<u64> {
    let Some(raw) = raw else {
        return Ok(REALM_GUTA_RESEND_AFTER_CHECKPOINTS_DEFAULT);
    };
    let value = raw.trim().parse::<u64>().map_err(|err| {
        anyhow::anyhow!(
            "invalid {} value {:?}; expected a number of checkpoints, at least {}: {}",
            REALM_GUTA_RESEND_AFTER_CHECKPOINTS_ENV,
            raw,
            REALM_GUTA_RESEND_MIN_CHECKPOINTS,
            err
        )
    })?;
    anyhow::ensure!(
        value >= REALM_GUTA_RESEND_MIN_CHECKPOINTS,
        "invalid {} value {}; must be at least {} checkpoints",
        REALM_GUTA_RESEND_AFTER_CHECKPOINTS_ENV,
        value,
        REALM_GUTA_RESEND_MIN_CHECKPOINTS
    );
    Ok(value)
}

pub fn realm_guta_resend_after_checkpoints_from_env() -> anyhow::Result<u64> {
    match std::env::var(REALM_GUTA_RESEND_AFTER_CHECKPOINTS_ENV) {
        Ok(raw) => parse_realm_guta_resend_after_checkpoints(Some(&raw)),
        Err(std::env::VarError::NotPresent) => parse_realm_guta_resend_after_checkpoints(None),
        Err(err) => Err(anyhow::anyhow!("failed to read {}: {}", REALM_GUTA_RESEND_AFTER_CHECKPOINTS_ENV, err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_uses_the_default() {
        assert_eq!(parse_realm_guta_resend_after_checkpoints(None).unwrap(), 10);
        assert_eq!(REALM_GUTA_RESEND_AFTER_CHECKPOINTS_DEFAULT, 10);
    }

    #[test]
    fn valid_values_are_used() {
        assert_eq!(parse_realm_guta_resend_after_checkpoints(Some("2")).unwrap(), 2);
        assert_eq!(parse_realm_guta_resend_after_checkpoints(Some("25")).unwrap(), 25);
        assert_eq!(parse_realm_guta_resend_after_checkpoints(Some("18446744073709551615")).unwrap(), u64::MAX);
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        assert_eq!(parse_realm_guta_resend_after_checkpoints(Some(" 12\n")).unwrap(), 12);
    }

    #[test]
    fn values_below_the_minimum_are_refused() {
        for raw in ["0", "1"] {
            let err = parse_realm_guta_resend_after_checkpoints(Some(raw)).unwrap_err().to_string();
            assert!(err.contains(REALM_GUTA_RESEND_AFTER_CHECKPOINTS_ENV), "unexpected error for {raw:?}: {err}");
            assert!(err.contains("at least 2"), "unexpected error for {raw:?}: {err}");
        }
    }

    #[test]
    fn values_that_are_not_unsigned_integers_are_refused() {
        for raw in ["", "  ", "-3", "abc", "1.5"] {
            let err = parse_realm_guta_resend_after_checkpoints(Some(raw)).unwrap_err().to_string();
            assert!(err.contains(REALM_GUTA_RESEND_AFTER_CHECKPOINTS_ENV), "unexpected error for {raw:?}: {err}");
        }
    }
}
