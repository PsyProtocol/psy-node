use async_trait::async_trait;
use dashmap::DashMap;
use psy_io::tokio::TokioLikeFileSystem;

pub struct SimpleMockMemoryFileSystem {
    pub files: DashMap<String, Vec<u8>>,
}

impl SimpleMockMemoryFileSystem {
    pub fn new() -> Self {
        Self {
            files: DashMap::new(),
        }
    }
}
#[async_trait]
impl TokioLikeFileSystem for SimpleMockMemoryFileSystem {
    type File = std::io::Cursor<Vec<u8>>;

    async fn file_like_fs_create(&self, path: &str) -> tokio::io::Result<Self::File> {
        if self.files.contains_key(path) {
            Ok(std::io::Cursor::new(self.files.get(path).unwrap().clone()))
        } else {
            Ok(std::io::Cursor::new(Vec::new()))
        }
    }

    async fn file_like_fs_open(&self, path: &str) -> tokio::io::Result<Self::File> {
        if let Some(data) = self.files.get(path) {
            Ok(std::io::Cursor::new(data.clone()))
        } else {
            Err(tokio::io::Error::new(
                tokio::io::ErrorKind::NotFound,
                "File not found",
            ))
        }
    }
    async fn file_like_fs_flush_file_with_path(&self, path: &str, file: &mut Self::File) -> tokio::io::Result<()> {
        let data = file.get_ref().clone();
        self.files.insert(path.to_string(), data);
        Ok(())
    }
        async fn file_like_fs_create_dir_all(&self, _path: &str) -> tokio::io::Result<()> {
            // No-op for in-memory filesystem
            Ok(())
        }
}

