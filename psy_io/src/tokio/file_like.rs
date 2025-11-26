use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FileLikeMetadata {
    length: u64,
    is_file: bool,
    is_symlink: bool,
    is_dir: bool,
}
impl FileLikeMetadata {
    pub fn len(&self) -> u64 {
        self.length
    }
    pub fn is_file(&self) -> bool {
        self.is_file
    }
    pub fn is_symlink(&self) -> bool {
        self.is_symlink
    }
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }
}
#[async_trait]
pub trait TokioLikeFileSystem: Send + Sync {
    type File: TokioFileLike;
    async fn file_like_fs_create(&self, path: &str) -> tokio::io::Result<Self::File>;
    async fn file_like_fs_open(&self, path: &str) -> tokio::io::Result<Self::File>;
    async fn file_like_fs_flush_file_with_path(&self, _path: &str, file: &mut Self::File) -> tokio::io::Result<()> {
        file.flush().await
    }

}
#[derive(Debug, Clone, Copy)]
pub struct TokioStdFileSystem;

#[async_trait]
impl TokioLikeFileSystem for TokioStdFileSystem {
    type File = tokio::fs::File;
    async fn file_like_fs_create(&self, path: &str) -> tokio::io::Result<Self::File> {
        tokio::fs::File::create(path).await
    }
    async fn file_like_fs_open(&self, path: &str) -> tokio::io::Result<Self::File> {
        tokio::fs::File::open(path).await
    }
}


#[async_trait]
pub trait TokioFileLike: AsyncWriteExt + AsyncReadExt + AsyncSeekExt + Unpin + Send {
    async fn file_like_metadata(&mut self) -> tokio::io::Result<FileLikeMetadata>;
    async fn file_like_create(path: &str) -> tokio::io::Result<Self>
    where
        Self: Sized;
    async fn file_like_open(path: &str) -> tokio::io::Result<Self>
    where
        Self: Sized;
}

#[async_trait]
impl TokioFileLike for tokio::fs::File {
    async fn file_like_metadata(&mut self) -> tokio::io::Result<FileLikeMetadata> {
        let metadata = self.metadata().await?;
        Ok(FileLikeMetadata {
            length: metadata.len(),
            is_file: metadata.is_file(),
            is_symlink: metadata.is_symlink(),
            is_dir: metadata.is_dir(),
        })
    }
    async fn file_like_create(path: &str) -> tokio::io::Result<Self>
    where
        Self: Sized,
    {
        tokio::fs::File::create(path).await
    }
    async fn file_like_open(path: &str) -> tokio::io::Result<Self>
    where
        Self: Sized,
    {
        tokio::fs::File::open(path).await
    }
}

#[async_trait]
impl TokioFileLike for std::io::Cursor<Vec<u8>> {
    async fn file_like_metadata(&mut self) -> tokio::io::Result<FileLikeMetadata> {
        let length = self.get_ref().len() as u64;
        Ok(FileLikeMetadata {
            length,
            is_file: true,
            is_symlink: false,
            is_dir: false,
        })
    }
    async fn file_like_create(_path: &str) -> tokio::io::Result<Self>
    where
        Self: Sized,
    {
        Ok(std::io::Cursor::new(Vec::new()))
    }
    async fn file_like_open(_path: &str) -> tokio::io::Result<Self>
    where
        Self: Sized,
    {
        Ok(std::io::Cursor::new(Vec::new()))
    }
}
