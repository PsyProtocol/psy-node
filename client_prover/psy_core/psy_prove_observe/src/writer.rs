use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        mpsc::Receiver,
        Arc,
    },
};

use serde_json::Value;

use crate::Config;

struct RotatingWriter {
    directory: PathBuf,
    limit: u64,
    files: usize,
    bytes: u64,
    file: File,
}
impl RotatingWriter {
    fn new(c: &Config) -> io::Result<Self> {
        fs::create_dir_all(&c.directory)?;
        let file = Self::open(&c.directory.join("events.0.jsonl"))?;
        let bytes = file.metadata()?.len();
        Ok(Self {
            directory: c.directory.clone(),
            limit: c.file_bytes,
            files: c.files,
            bytes,
            file,
        })
    }
    fn open(p: &std::path::Path) -> io::Result<File> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(p)
    }
    fn path(&self, n: usize) -> PathBuf {
        self.directory.join(format!("events.{n}.jsonl"))
    }
    fn write(&mut self, value: Value) -> io::Result<()> {
        let mut line = serde_json::to_vec(&value)?;
        line.push(b'\n');
        if line.len() as u64 > self.limit {
            return Err(io::Error::other("diagnostic record exceeds file cap"));
        }
        if self.bytes + line.len() as u64 > self.limit {
            match fs::remove_file(self.path(self.files - 1)) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => (),
            }
            for n in (1..self.files).rev() {
                match fs::rename(self.path(n - 1), self.path(n)) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                    _ => (),
                }
            }
            self.file = Self::open(&self.path(0))?;
            self.bytes = 0;
        }
        self.file.write_all(&line)?;
        self.bytes += line.len() as u64;
        Ok(())
    }
}

pub(crate) fn start(config: &Config, rx: Receiver<Value>, errors: Arc<AtomicU64>) -> io::Result<()> {
    let mut writer = RotatingWriter::new(config)?;
    std::thread::Builder::new().name("prove-observe-log".into()).spawn(move || {
        while let Ok(value) = rx.recv() {
            if writer.write(value).is_err() {
                errors.fetch_add(1, Relaxed);
            }
        }
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_is_bounded_and_records_remain_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            directory: dir.path().into(),
            capacity: 2,
            event_capacity: 2,
            file_bytes: 1024,
            files: 3,
            slow_ms: 10,
        };
        let mut w = RotatingWriter::new(&config).unwrap();
        for n in 0..1000 {
            w.write(serde_json::json!({"n":n,"event":"test"})).unwrap();
        }
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 3);
        for entry in entries {
            let path = entry.unwrap().path();
            assert!(fs::metadata(&path).unwrap().len() <= 1024);
            for line in fs::read_to_string(path).unwrap().lines() {
                serde_json::from_str::<Value>(line).unwrap();
            }
        }
    }
}
