//! Configuration of the psy-bridge-reader binary: flags and environment.

use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use psy_bridge_reader_core::admission::{Budgets, LaneBudget};

const MAX_TOKEN_BYTES: u64 = 4096;

#[derive(Debug, Clone, Parser)]
#[command(name = "psy-bridge-reader")]
pub struct Config {
    #[arg(long, env = "PSY_BRIDGE_READER_LISTEN", default_value = "127.0.0.1:8740")]
    pub listen: SocketAddr,
    #[arg(long, env = "PSY_BRIDGE_READER_TOKEN_FILE")]
    pub token_file: PathBuf,
    #[arg(long, env = "PSY_BRIDGE_READER_DATABASE_URL")]
    pub database_url: String,
    /// No default: a wrong default would silently read another schema.
    #[arg(long, env = "PSY_BRIDGE_READER_DB_SCHEMA")]
    pub db_schema: String,
    #[arg(long, env = "PSY_BRIDGE_READER_TICK_MS", default_value_t = 500)]
    pub tick_ms: u64,
    #[arg(long, env = "PSY_BRIDGE_READER_MAX_ROWS_PER_TICK", default_value_t = 50000)]
    pub max_rows_per_tick: u64,
    #[arg(long, env = "PSY_BRIDGE_READER_MEMORY_BUDGET_BYTES", default_value_t = 10_737_418_240)]
    pub memory_budget_bytes: u64,
    #[arg(long, env = "PSY_BRIDGE_READER_STATEMENT_TIMEOUT_MS", default_value_t = 5000)]
    pub statement_timeout_ms: u64,
    #[arg(long, env = "PSY_BRIDGE_READER_BRIDGE_PROGRESS_CONCURRENCY")]
    pub bridge_progress_concurrency: Option<usize>,
    #[arg(long, env = "PSY_BRIDGE_READER_BRIDGE_PROGRESS_MAX_QUEUE")]
    pub bridge_progress_max_queue: Option<usize>,
    #[arg(long, env = "PSY_BRIDGE_READER_BRIDGE_PROGRESS_QUEUE_WAIT_MS")]
    pub bridge_progress_queue_wait_ms: Option<u64>,
    #[arg(long, env = "PSY_BRIDGE_READER_BRIDGE_PROGRESS_DEADLINE_MS")]
    pub bridge_progress_deadline_ms: Option<u64>,
    #[arg(long, env = "PSY_BRIDGE_READER_CLAIM_PROOF_CONCURRENCY")]
    pub claim_proof_concurrency: Option<usize>,
    #[arg(long, env = "PSY_BRIDGE_READER_CLAIM_PROOF_MAX_QUEUE")]
    pub claim_proof_max_queue: Option<usize>,
    #[arg(long, env = "PSY_BRIDGE_READER_CLAIM_PROOF_QUEUE_WAIT_MS")]
    pub claim_proof_queue_wait_ms: Option<u64>,
    #[arg(long, env = "PSY_BRIDGE_READER_CLAIM_PROOF_DEADLINE_MS")]
    pub claim_proof_deadline_ms: Option<u64>,
    #[arg(long, env = "PSY_BRIDGE_READER_INTERACTIVE_CONCURRENCY")]
    pub interactive_concurrency: Option<usize>,
    #[arg(long, env = "PSY_BRIDGE_READER_INTERACTIVE_MAX_QUEUE")]
    pub interactive_max_queue: Option<usize>,
    #[arg(long, env = "PSY_BRIDGE_READER_INTERACTIVE_QUEUE_WAIT_MS")]
    pub interactive_queue_wait_ms: Option<u64>,
    #[arg(long, env = "PSY_BRIDGE_READER_INTERACTIVE_DEADLINE_MS")]
    pub interactive_deadline_ms: Option<u64>,
    #[arg(long, env = "PSY_BRIDGE_READER_BACKGROUND_CONCURRENCY")]
    pub background_concurrency: Option<usize>,
    #[arg(long, env = "PSY_BRIDGE_READER_BACKGROUND_MAX_QUEUE")]
    pub background_max_queue: Option<usize>,
    #[arg(long, env = "PSY_BRIDGE_READER_BACKGROUND_QUEUE_WAIT_MS")]
    pub background_queue_wait_ms: Option<u64>,
    #[arg(long, env = "PSY_BRIDGE_READER_BACKGROUND_DEADLINE_MS")]
    pub background_deadline_ms: Option<u64>,
}

fn apply(
    lane: &mut LaneBudget,
    concurrency: Option<usize>,
    max_queue: Option<usize>,
    queue_wait_ms: Option<u64>,
    deadline_ms: Option<u64>,
) {
    if let Some(v) = concurrency {
        lane.concurrency = v;
    }
    if let Some(v) = max_queue {
        lane.max_queue = v;
    }
    if let Some(v) = queue_wait_ms {
        lane.queue_wait = Duration::from_millis(v);
    }
    if let Some(v) = deadline_ms {
        lane.deadline = Duration::from_millis(v);
    }
}

fn is_private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

impl Config {
    /// Defaults with the lane overrides applied, validated.
    pub fn budgets(&self) -> Result<Budgets, String> {
        let mut b = Budgets::default();
        apply(
            &mut b.bridge_progress,
            self.bridge_progress_concurrency,
            self.bridge_progress_max_queue,
            self.bridge_progress_queue_wait_ms,
            self.bridge_progress_deadline_ms,
        );
        apply(
            &mut b.claim_proof,
            self.claim_proof_concurrency,
            self.claim_proof_max_queue,
            self.claim_proof_queue_wait_ms,
            self.claim_proof_deadline_ms,
        );
        apply(
            &mut b.interactive,
            self.interactive_concurrency,
            self.interactive_max_queue,
            self.interactive_queue_wait_ms,
            self.interactive_deadline_ms,
        );
        apply(
            &mut b.background,
            self.background_concurrency,
            self.background_max_queue,
            self.background_queue_wait_ms,
            self.background_deadline_ms,
        );
        b.validate()?;
        Ok(b)
    }

    pub fn validate(&self) -> Result<(), String> {
        if !is_private_or_loopback(self.listen.ip()) {
            return Err(format!(
                "listen address {} is neither loopback nor private",
                self.listen
            ));
        }
        if !(1..=1000).contains(&self.tick_ms) {
            return Err(format!("tick_ms {} must be within 1..=1000", self.tick_ms));
        }
        if !(1..=50000).contains(&self.max_rows_per_tick) {
            return Err(format!(
                "max_rows_per_tick {} must be within 1..=50000",
                self.max_rows_per_tick
            ));
        }
        self.budgets()?;
        Ok(())
    }

    /// Reads the bearer token: non-empty, at most 4 KiB, mode 0600 or stricter.
    pub fn read_token(&self) -> Result<String, String> {
        let path = &self.token_file;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("token file {}: {e}", path.display()))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "token file {} must not be accessible by group or others",
                path.display()
            ));
        }
        if meta.len() > MAX_TOKEN_BYTES {
            return Err(format!("token file {} exceeds 4 KiB", path.display()));
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("token file {}: {e}", path.display()))?;
        let token = raw.strip_suffix('\n').unwrap_or(&raw);
        if token.is_empty() {
            return Err(format!("token file {} is empty", path.display()));
        }
        Ok(token.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(extra: &[&str]) -> Config {
        let mut args = vec![
            "psy-bridge-reader",
            "--token-file",
            "/nonexistent",
            "--database-url",
            "postgres://x",
            "--db-schema",
            "s",
        ];
        args.extend_from_slice(extra);
        Config::try_parse_from(args).unwrap()
    }

    #[test]
    fn public_listen_address_is_refused() {
        assert!(parse(&[]).validate().is_ok());
        assert!(parse(&["--listen", "10.1.2.3:8740"]).validate().is_ok());
        assert!(parse(&["--listen", "[::1]:8740"]).validate().is_ok());
        assert!(parse(&["--listen", "8.8.8.8:8740"]).validate().is_err());
        assert!(parse(&["--listen", "0.0.0.0:8740"]).validate().is_err());
        assert!(parse(&["--listen", "[2001:db8::1]:8740"]).validate().is_err());
    }

    #[test]
    fn tick_over_1000_ms_is_refused() {
        assert!(parse(&["--tick-ms", "1000"]).validate().is_ok());
        assert!(parse(&["--tick-ms", "1001"]).validate().is_err());
        assert!(parse(&["--tick-ms", "0"]).validate().is_err());
    }

    #[test]
    fn lane_override_with_deadline_below_queue_wait_is_refused() {
        let c = parse(&[
            "--claim-proof-queue-wait-ms",
            "1500",
            "--claim-proof-deadline-ms",
            "1000",
        ]);
        assert!(c.budgets().is_err());
        assert!(c.validate().is_err());
        let ok = parse(&["--claim-proof-concurrency", "2"]);
        assert_eq!(ok.budgets().unwrap().claim_proof.concurrency, 2);
    }

    #[test]
    fn token_file_with_group_or_world_access_is_refused() {
        let path = std::env::temp_dir().join(format!(
            "psy-bridge-reader-token-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, "secret\n").unwrap();
        let p = path.to_str().unwrap();
        let cfg = || {
            Config::try_parse_from([
                "psy-bridge-reader", "--token-file", p, "--database-url", "x", "--db-schema", "s",
            ])
            .unwrap()
        };
        for mode in [0o640, 0o604, 0o666] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(cfg().read_token().is_err(), "mode {mode:o}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(cfg().read_token().unwrap(), "secret");
        std::fs::write(&path, "").unwrap();
        assert!(cfg().read_token().is_err());
        std::fs::remove_file(&path).unwrap();
    }
}
