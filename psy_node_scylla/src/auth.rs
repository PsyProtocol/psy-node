//! Optional file-based credentials and externally provisioned schema.
//! The unset defaults preserve existing unauthenticated deployments.
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

// Deliberately no Debug implementation: credentials must not enter diagnostics.
pub(crate) struct Credentials {
    pub(crate) username: String,
    pub(crate) password: String,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn secret(path: &Path) -> io::Result<String> {
    let file = File::open(path).map_err(|_| invalid("Scylla credential file is unreadable"))?;
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)
        .map_err(|_| invalid("Scylla credential file cannot be read"))?;
    if bytes.len() > 4096 {
        return Err(invalid("Scylla credential exceeds the size limit"));
    }
    let raw = String::from_utf8(bytes).map_err(|_| invalid("Scylla credential is not UTF-8"))?;
    // Secret files may end with one newline. Preserve meaningful spaces.
    let value = raw.strip_suffix("\r\n").or_else(|| raw.strip_suffix('\n')).unwrap_or(&raw);
    if value.trim().is_empty() || value.contains(['\r', '\n', '\0']) {
        return Err(invalid("Scylla credential is empty or contains a line separator"));
    }
    Ok(value.to_owned())
}

pub(crate) fn from_paths(username: Option<&Path>, password: Option<&Path>) -> io::Result<Option<Credentials>> {
    match (username, password) {
        (None, None) => Ok(None),
        (Some(user), Some(pass)) => Ok(Some(Credentials { username: secret(user)?, password: secret(pass)? })),
        _ => Err(invalid("Set both SCYLLA_USERNAME_FILE and SCYLLA_PASSWORD_FILE")),
    }
}

pub(crate) fn from_env() -> io::Result<Option<Credentials>> {
    let username = std::env::var_os("SCYLLA_USERNAME_FILE").map(PathBuf::from);
    let password = std::env::var_os("SCYLLA_PASSWORD_FILE").map(PathBuf::from);
    from_paths(username.as_deref(), password.as_deref())
}

pub(crate) fn schema_mode(value: Option<&str>) -> io::Result<bool> {
    match value {
        None | Some("0") | Some("false") => Ok(false),
        Some("1") | Some("true") => Ok(true),
        _ => Err(invalid("PSY_SCYLLA_SCHEMA_PRECREATED must be 0, 1, false or true")),
    }
}

pub(crate) fn schema_precreated() -> io::Result<bool> {
    match std::env::var("PSY_SCYLLA_SCHEMA_PRECREATED") {
        Ok(value) => schema_mode(Some(&value)),
        Err(std::env::VarError::NotPresent) => schema_mode(None),
        Err(_) => Err(invalid("PSY_SCYLLA_SCHEMA_PRECREATED must be UTF-8")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Files(PathBuf);
    impl Files {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("psy-scylla-auth-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn put(&self, name: &str, content: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)] {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(&p).unwrap().write_all(content).unwrap();
            p
        }
    }
    impl Drop for Files {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
    }

    #[test]
    fn unset_preserves_legacy_and_partial_configuration_fails_closed() {
        assert!(from_paths(None, None).unwrap().is_none());
        let missing = Path::new("/does-not-exist");
        assert!(from_paths(Some(missing), None).is_err());
        assert!(from_paths(None, Some(missing)).is_err());
        assert!(from_paths(Some(missing), Some(missing)).is_err());
    }

    #[test]
    fn files_accept_one_newline_and_preserve_spaces_without_debugging_values() {
        let files = Files::new();
        let user = files.put("username", b"psy_chain\n");
        let pass = files.put("password", b" a secret with spaces \r\n");
        let value = from_paths(Some(&user), Some(&pass)).unwrap().unwrap();
        assert!(value.username == "psy_chain");
        assert!(value.password == " a secret with spaces ");
    }

    #[test]
    fn malformed_secret_files_fail_without_content_in_errors() {
        let files = Files::new();
        for (index, bytes) in [b"".as_slice(), b"  \n", b"never-log-this\nsecond-line", b"secret\0suffix", b"\xff"].into_iter().enumerate() {
            let p = files.put(&format!("invalid-{index}"), bytes);
            let message = secret(&p).err().unwrap().to_string();
            assert!(!message.contains("never-log-this"));
            assert!(!message.contains("second-line"));
        }
        let large = files.put("large", &vec![b'x'; 4097]);
        assert!(secret(&large).is_err());
    }

    #[test]
    fn schema_mode_has_legacy_default_and_rejects_typos() {
        assert!(!schema_mode(None).unwrap());
        for value in ["0", "false"] { assert!(!schema_mode(Some(value)).unwrap()); }
        for value in ["1", "true"] { assert!(schema_mode(Some(value)).unwrap()); }
        for value in ["", "TRUE", "yes", "tru"] { assert!(schema_mode(Some(value)).is_err()); }
    }
}
