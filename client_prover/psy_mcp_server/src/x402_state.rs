use std::{
    collections::HashSet,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

use fs2::FileExt;

pub struct ConsumedPayments {
    path: PathBuf,
    hashes: Mutex<HashSet<String>>,
    load_error: Option<String>,
}

impl ConsumedPayments {
    pub fn load(dir: &Path) -> Self {
        let path = dir.join("consumed_payments.json");
        let (hashes, load_error) = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str(&text) {
                Ok(hashes) => (hashes, None),
                Err(e) => (HashSet::new(), Some(format!("{} is invalid: {e}", path.display()))),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (HashSet::new(), None),
            Err(e) => (HashSet::new(), Some(format!("could not read {}: {e}", path.display()))),
        };
        Self {
            path,
            hashes: Mutex::new(hashes),
            load_error,
        }
    }

    pub fn consume(&self, hash: String) -> anyhow::Result<bool> {
        if let Some(error) = &self.load_error {
            anyhow::bail!("consumed-payment state is unavailable: {error}");
        }
        let mut hashes = self.hashes.lock().unwrap();
        if contains_key(&hashes, &hash) {
            return Ok(false);
        }
        if !persist_new(&self.path, &hash)? {
            hashes.insert(hash);
            return Ok(false);
        }
        hashes.insert(hash);
        Ok(true)
    }
}

fn contains_key(hashes: &HashSet<String>, key: &str) -> bool {
    hashes.contains(key) || key.split_once(':').is_some_and(|(_, legacy_hash)| hashes.contains(legacy_hash))
}

fn persist_new(path: &Path, hash: &str) -> anyhow::Result<bool> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let lock_path = path.with_extension("json.lock");
    let lock = std::fs::OpenOptions::new().read(true).write(true).create(true).open(&lock_path)?;
    lock.lock_exclusive()?;
    let mut hashes = match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str::<HashSet<String>>(&text)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashSet::new(),
        Err(e) => return Err(e.into()),
    };
    if contains_key(&hashes, hash) {
        let _ = FileExt::unlock(&lock);
        return Ok(false);
    }
    hashes.insert(hash.to_string());
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    {
        let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(serde_json::to_string(&hashes)?.as_bytes())?;
        file.sync_all()?;
    }
    std::fs::rename(tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    let _ = FileExt::unlock(&lock);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consumption_is_durable_and_one_use() {
        let dir = tempfile::tempdir().unwrap();
        let first = ConsumedPayments::load(dir.path());
        assert!(first.consume("sepolia:abc".into()).unwrap());
        assert!(!first.consume("sepolia:abc".into()).unwrap());

        let reloaded = ConsumedPayments::load(dir.path());
        assert!(!reloaded.consume("sepolia:abc".into()).unwrap());
        assert!(reloaded.consume("ethereum:abc".into()).unwrap());
    }

    #[test]
    fn legacy_bare_hashes_remain_consumed_after_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("consumed_payments.json"), r#"["abc"]"#).unwrap();
        let state = ConsumedPayments::load(dir.path());
        assert!(!state.consume("sepolia:abc".into()).unwrap());
    }

    #[test]
    fn corrupt_state_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("consumed_payments.json"), "not json").unwrap();
        let state = ConsumedPayments::load(dir.path());
        assert!(state.consume("sepolia:abc".into()).is_err());
    }
}
