use async_trait::async_trait;
use dashmap::DashMap;
use psy_io::tokio::{FileLikeMetadata, TokioLikeFileSystem};
#[derive(Clone)]
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
    async fn file_like_fs_sync_file_with_path(&self, path: &str, file: &mut Self::File) -> tokio::io::Result<()> {
        // sync for memory fs is the same as flush
        let data = file.get_ref().clone();
        self.files.insert(path.to_string(), data);
        Ok(())
    }
        async fn file_like_fs_create_dir_all(&self, _path: &str) -> tokio::io::Result<()> {
            // No-op for in-memory filesystem
            Ok(())
        }

    async fn file_like_exists(&self, path: &str) -> tokio::io::Result<bool>{
        Ok(self.files.contains_key(path))
    }
    async fn file_like_remove_file(&self, path: &str) -> tokio::io::Result<()> {
        if self.files.remove(path).is_some() {
            Ok(())
        } else {
            Err(tokio::io::Error::new(
                tokio::io::ErrorKind::NotFound,
                "File not found",
            ))
        }
    }
    async fn file_like_rename(&self, old_path: &str, new_path: &str) -> tokio::io::Result<()> {
        if let Some(data) = self.files.remove(old_path) {
            self.files.insert(new_path.to_string(), data.1);
            Ok(())
        } else {
            Err(tokio::io::Error::new(
                tokio::io::ErrorKind::NotFound,
                "File not found",
            ))
        }
    }
    async fn file_like_fs_sync_parent_dir(&self, _path: &str) -> tokio::io::Result<()> {
        Ok(())
    }
    async fn file_like_metadata(&self, path: &str) -> tokio::io::Result<FileLikeMetadata> {
        if let Some(data) = self.files.get(path) {
            Ok(FileLikeMetadata::new(data.len() as u64, true, false, false))
        } else {
            Err(tokio::io::Error::new(
                tokio::io::ErrorKind::NotFound,
                "File not found",
            ))
        }
    }
}

