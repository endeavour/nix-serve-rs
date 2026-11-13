//! NAR serializer matching `nix nar pack` / `nix store dump-path`.
//!
//! Directory entries are emitted in byte-wise sorted order and symlinks are
//! not followed, so the bytes hash to the same narHash Nix recorded.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use std::future::Future;

use tokio::fs;
use tokio::io::{self, AsyncReadExt};

pub trait NarWrite {
    fn write_all(&mut self, buf: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}

impl NarWrite for Vec<u8> {
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.extend_from_slice(buf);
        Ok(())
    }
}

pub async fn write_nar(path: &Path, writer: &mut impl NarWrite) -> io::Result<u64> {
    let mut counted = CountWriter { inner: writer, written: 0 };
    write_string(&mut counted, "nix-archive-1").await?;
    write_node(&mut counted, path).await?;
    Ok(counted.written)
}

async fn write_node<W>(writer: &mut CountWriter<'_, W>, path: &Path) -> io::Result<()>
where
    W: NarWrite,
{
    let metadata = fs::symlink_metadata(path).await?;
    let file_type = metadata.file_type();
    write_string(writer, "(").await?;
    write_string(writer, "type").await?;
    if file_type.is_symlink() {
        write_string(writer, "symlink").await?;
        write_string(writer, "target").await?;
        let target = fs::read_link(path).await?;
        write_bytes(writer, target.as_os_str().as_bytes()).await?;
    } else if file_type.is_file() {
        write_string(writer, "regular").await?;
        if metadata.permissions().mode() & 0o111 != 0 {
            write_string(writer, "executable").await?;
            write_bytes(writer, b"").await?;
        }
        write_string(writer, "contents").await?;
        write_file(writer, path, metadata.len()).await?;
    } else if file_type.is_dir() {
        write_string(writer, "directory").await?;
        let mut names = Vec::new();
        let mut entries = fs::read_dir(path).await?;
        while let Some(entry) = entries.next_entry().await? {
            names.push(entry.file_name());
        }
        names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        for name in names {
            write_string(writer, "entry").await?;
            write_string(writer, "(").await?;
            write_string(writer, "name").await?;
            write_bytes(writer, name.as_bytes()).await?;
            write_string(writer, "node").await?;
            Box::pin(write_node(writer, &path.join(&name))).await?;
            write_string(writer, ")").await?;
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported file type in NAR: {}", path.display()),
        ));
    }
    write_string(writer, ")").await?;
    Ok(())
}

async fn write_file<W>(writer: &mut CountWriter<'_, W>, path: &Path, len: u64) -> io::Result<()>
where
    W: NarWrite,
{
    writer.write_all(&len.to_le_bytes()).await?;
    let mut file = fs::File::open(path).await?;
    let mut remaining = len;
    let mut buf = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let read = file.read(&mut buf[..want]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("store file shrank while dumping {}", path.display()),
            ));
        }
        writer.write_all(&buf[..read]).await?;
        remaining -= read as u64;
    }
    let padding = (8 - (len % 8)) % 8;
    if padding != 0 {
        writer.write_all(&[0u8; 8][..padding as usize]).await?;
    }
    Ok(())
}

async fn write_string<W>(writer: &mut CountWriter<'_, W>, value: &str) -> io::Result<()>
where
    W: NarWrite,
{
    write_bytes(writer, value.as_bytes()).await
}

async fn write_bytes<W>(writer: &mut CountWriter<'_, W>, value: &[u8]) -> io::Result<()>
where
    W: NarWrite,
{
    let len = value.len() as u64;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(value).await?;
    let padding = (8 - (value.len() % 8)) % 8;
    if padding != 0 {
        writer.write_all(&[0u8; 8][..padding]).await?;
    }
    Ok(())
}

struct CountWriter<'a, W> {
    inner: &'a mut W,
    written: u64,
}

impl<W> CountWriter<'_, W>
where
    W: NarWrite,
{
    async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.inner.write_all(buf).await?;
        self.written += buf.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn matches_nix_nar_pack() {
        let nix = Command::new("nix").arg("--version").output();
        if nix.is_err() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("nix-serve-rs-nar-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir).await;
        fs::create_dir(&dir).await.unwrap();
        fs::write(dir.join("b.txt"), b"hello").await.unwrap();
        fs::write(dir.join("a.txt"), b"").await.unwrap();
        let mut exe = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o755)
            .open(dir.join("run"))
            .await
            .unwrap();
        exe.write_all(b"#!/bin/sh\n").await.unwrap();
        drop(exe);
        fs::symlink("b.txt", dir.join("link")).await.unwrap();
        fs::create_dir(dir.join("sub")).await.unwrap();
        fs::write(dir.join("sub").join("c"), b"xyz").await.unwrap();

        let mut ours = Vec::new();
        write_nar(&dir, &mut ours).await.unwrap();
        let theirs = Command::new("nix")
            .args(["nar", "pack", "--"])
            .arg(&dir)
            .output()
            .unwrap();
        assert!(
            theirs.status.success(),
            "nix nar pack failed: {}",
            String::from_utf8_lossy(&theirs.stderr)
        );
        assert_eq!(ours, theirs.stdout, "NAR bytes diverged from nix nar pack");
        let _ = fs::remove_dir_all(&dir).await;
    }
}
