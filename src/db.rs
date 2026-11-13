//! Read-only lookups against the Nix SQLite database.
//!
//! Connections are opened per request and dropped before a NAR is streamed,
//! so a slow client cannot hold the store database lock.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use crate::nix32;

#[derive(Debug, Clone)]
pub struct PathInfo {
    pub path: String,
    pub hash_part: String,
    pub nar_hash_nix32: String,
    pub nar_size: u64,
    pub deriver: Option<String>,
    pub references: Vec<String>,
    pub sigs: Vec<String>,
}

pub struct StoreDb {
    path: PathBuf,
    store_dir: String,
}

impl StoreDb {
    pub fn new(path: PathBuf, store_dir: PathBuf) -> Self {
        let store_dir = store_dir.to_string_lossy().trim_end_matches('/').to_string();
        Self { path, store_dir }
    }

    pub fn store_dir(&self) -> &str {
        &self.store_dir
    }

    pub fn lookup_hash_part(&self, hash_part: &str) -> Result<Option<PathInfo>, String> {
        if !nix32::is_hash_part(hash_part) {
            return Ok(None);
        }
        let conn = self.connect()?;
        let start = format!("{}/{hash_part}-", self.store_dir);
        let end = format!("{}/{hash_part}.", self.store_dir);
        let mut statement = conn
            .prepare(
                "SELECT id, path, hash, narSize, deriver, sigs
                 FROM ValidPaths
                 WHERE path >= ?1 AND path < ?2
                 LIMIT 2",
            )
            .map_err(|err| err.to_string())?;
        let mut rows = statement
            .query(rusqlite::params![start, end])
            .map_err(|err| err.to_string())?;
        let Some(row) = rows.next().map_err(|err| err.to_string())? else {
            return Ok(None);
        };
        let id: i64 = row.get(0).map_err(|err| err.to_string())?;
        let path: String = row.get(1).map_err(|err| err.to_string())?;
        let hash: String = row.get(2).map_err(|err| err.to_string())?;
        let nar_size: Option<i64> = row.get(3).map_err(|err| err.to_string())?;
        let deriver: Option<String> = row.get(4).map_err(|err| err.to_string())?;
        let sigs: Option<String> = row.get(5).map_err(|err| err.to_string())?;
        if rows.next().map_err(|err| err.to_string())?.is_some() {
            return Err(format!("multiple store paths share hash part {hash_part}"));
        }
        drop(rows);
        drop(statement);
        let Some(nar_size) = nar_size.filter(|size| *size >= 0) else {
            return Err(format!("{path} has no narSize in the Nix database"));
        };
        let nar_hash_nix32 = nix32_from_db_hash(&hash)?;
        let mut references = Vec::new();
        let mut ref_statement = conn
            .prepare(
                "SELECT p.path
                 FROM Refs r
                 JOIN ValidPaths p ON p.id = r.reference
                 WHERE r.referrer = ?1
                 ORDER BY p.path",
            )
            .map_err(|err| err.to_string())?;
        let mut ref_rows = ref_statement
            .query([id])
            .map_err(|err| err.to_string())?;
        while let Some(ref_row) = ref_rows.next().map_err(|err| err.to_string())? {
            references.push(ref_row.get(0).map_err(|err| err.to_string())?);
        }
        Ok(Some(PathInfo {
            hash_part: hash_part.to_string(),
            path,
            nar_hash_nix32,
            nar_size: nar_size as u64,
            deriver,
            references,
            sigs: sigs
                .unwrap_or_default()
                .split_whitespace()
                .map(str::to_string)
                .collect(),
        }))
    }

    fn connect(&self) -> Result<Connection, String> {
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|err| format!("opening {}: {err}", self.path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(|err| err.to_string())?;
        conn.pragma_update(None, "query_only", "ON")
            .map_err(|err| err.to_string())?;
        Ok(conn)
    }
}

fn nix32_from_db_hash(hash: &str) -> Result<String, String> {
    let rest = hash.strip_prefix("sha256:").unwrap_or(hash);
    if rest.len() == 52 && nix32::is_nar_hash(rest) {
        return Ok(rest.to_string());
    }
    if rest.len() == 64 && rest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let mut digest = [0u8; 32];
        for (index, chunk) in rest.as_bytes().chunks(2).enumerate() {
            let text = std::str::from_utf8(chunk).unwrap();
            digest[index] = u8::from_str_radix(text, 16)
                .map_err(|err| format!("bad nar hash {hash}: {err}"))?;
        }
        return Ok(nix32::encode(&digest));
    }
    Err(format!("unsupported nar hash format: {hash}"))
}

pub fn basename(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_db_hex_hash() {
        let encoded = nix32_from_db_hash(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        .unwrap();
        assert_eq!(
            encoded,
            "0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73"
        );
    }
}
