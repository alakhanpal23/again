//! Local SQLite index and content-addressed output store.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::fingerprint::{FileDigestCache, FileIdentity};

const SCHEMA_VERSION: i64 = 2;
const MAX_FILE_DIGEST_ROWS: i64 = 50_000;
const FILE_DIGEST_PRUNE_INTERVAL: u16 = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCall {
    pub id: String,
    pub session_id: String,
    pub turn_id: Option<String>,
    pub cwd: PathBuf,
    pub raw_command: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredResult {
    pub id: String,
    pub request_key: String,
    pub stdout_digest: String,
    pub stderr_digest: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub policy_version: String,
    pub proof_json: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventDisposition {
    Executed,
    ReplayedFull,
    ReplayedCompact,
    PassedThrough,
    BypassedNoStore,
    Quarantined,
}

impl EventDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Executed => "executed",
            Self::ReplayedFull => "replayed_full",
            Self::ReplayedCompact => "replayed_compact",
            Self::PassedThrough => "passed_through",
            Self::BypassedNoStore => "bypassed_no_store",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StoreStats {
    pub executions: u64,
    pub full_replays: u64,
    pub compact_replays: u64,
    pub bypasses: u64,
    pub quarantines: u64,
    pub duplicate_bytes_omitted: u64,
    pub estimated_execution_ms_saved: u64,
}

pub struct Store {
    root: PathBuf,
    blobs: PathBuf,
    conn: Connection,
    file_digest_writes_since_prune: u16,
}

impl Store {
    /// Resolve state for a repository-scoped execution.
    ///
    /// Codex normally grants tool calls write access to the active workspace,
    /// not to arbitrary locations under the user's home directory. Keeping the
    /// default store in `<workspace>/.again` therefore makes the hook usable
    /// without broadening Codex's sandbox. Tests and advanced users can still
    /// provide `AGAIN_HOME` to select an isolated location explicitly.
    pub fn root_for_workspace(workspace: &Path) -> Result<PathBuf> {
        if let Some(path) = std::env::var_os("AGAIN_HOME") {
            return Ok(PathBuf::from(path));
        }
        let workspace = fs::canonicalize(workspace)
            .with_context(|| format!("resolve Again workspace {}", workspace.display()))?;
        if !workspace.is_dir() {
            bail!(
                "Again workspace is not a directory: {}",
                workspace.display()
            );
        }
        Ok(workspace.join(".again"))
    }

    pub fn open_for_workspace(workspace: &Path) -> Result<Self> {
        Self::open(Self::root_for_workspace(workspace)?)
    }

    pub fn default_root() -> Result<PathBuf> {
        if let Some(path) = std::env::var_os("AGAIN_HOME") {
            return Ok(PathBuf::from(path));
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HOME is unavailable; set AGAIN_HOME to a private directory"))?;
        Ok(home.join(".again"))
    }

    pub fn open_default() -> Result<Self> {
        Self::open(Self::default_root()?)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let blobs = root.join("blobs");
        fs::create_dir_all(&blobs)
            .with_context(|| format!("create Again state directory {}", blobs.display()))?;
        set_private_dir(&root)?;
        set_private_dir(&blobs)?;
        create_self_ignoring_gitignore(&root)?;

        let database = root.join("again.sqlite");
        let conn = Connection::open(&database)
            .with_context(|| format!("open Again database {}", database.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "FULL")?;

        let store = Self {
            root,
            blobs,
            conn,
            file_digest_writes_since_prune: FILE_DIGEST_PRUNE_INTERVAL - 1,
        };
        store.migrate()?;
        set_private_file(&database)?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            bail!(
                "Again database schema {version} is newer than supported schema {SCHEMA_VERSION}"
            );
        }
        if version == 0 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE pending_calls (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    turn_id TEXT,
                    cwd TEXT NOT NULL,
                    raw_command TEXT NOT NULL,
                    argv_json TEXT NOT NULL,
                    created_ms INTEGER NOT NULL
                );
                CREATE TABLE results (
                    id TEXT PRIMARY KEY,
                    request_key TEXT NOT NULL UNIQUE,
                    stdout_digest TEXT NOT NULL,
                    stderr_digest TEXT NOT NULL,
                    stdout_bytes INTEGER NOT NULL,
                    stderr_bytes INTEGER NOT NULL,
                    exit_code INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    policy_version TEXT NOT NULL,
                    proof_json TEXT NOT NULL,
                    quarantined INTEGER NOT NULL DEFAULT 0,
                    quarantine_reason TEXT,
                    created_ms INTEGER NOT NULL,
                    last_used_ms INTEGER NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE deliveries (
                    session_id TEXT NOT NULL,
                    result_id TEXT NOT NULL,
                    delivered_ms INTEGER NOT NULL,
                    PRIMARY KEY (session_id, result_id),
                    FOREIGN KEY (result_id) REFERENCES results(id) ON DELETE CASCADE
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    call_id TEXT,
                    result_id TEXT,
                    disposition TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    elapsed_ms INTEGER NOT NULL DEFAULT 0,
                    bytes_omitted INTEGER NOT NULL DEFAULT 0,
                    created_ms INTEGER NOT NULL
                );
                CREATE INDEX events_created_idx ON events(created_ms);
                PRAGMA user_version = 1;
                COMMIT;
                "#,
            )?;
        }
        if version < 2 {
            self.conn.execute_batch(
                r#"
                BEGIN IMMEDIATE;
                CREATE TABLE file_digests (
                    device BLOB NOT NULL CHECK(typeof(device) = 'blob' AND length(device) = 8),
                    inode BLOB NOT NULL CHECK(typeof(inode) = 'blob' AND length(inode) = 8),
                    mode INTEGER NOT NULL CHECK(mode >= 0),
                    uid INTEGER NOT NULL CHECK(uid >= 0),
                    gid INTEGER NOT NULL CHECK(gid >= 0),
                    size BLOB NOT NULL CHECK(typeof(size) = 'blob' AND length(size) = 8),
                    mtime_sec INTEGER NOT NULL,
                    mtime_nsec INTEGER NOT NULL CHECK(mtime_nsec >= 0 AND mtime_nsec < 1000000000),
                    ctime_sec INTEGER NOT NULL,
                    ctime_nsec INTEGER NOT NULL CHECK(ctime_nsec >= 0 AND ctime_nsec < 1000000000),
                    digest BLOB NOT NULL CHECK(typeof(digest) = 'blob' AND length(digest) = 32),
                    row_checksum BLOB NOT NULL CHECK(typeof(row_checksum) = 'blob' AND length(row_checksum) = 32),
                    last_used_ms INTEGER NOT NULL,
                    PRIMARY KEY (device, inode)
                ) WITHOUT ROWID;
                CREATE INDEX file_digests_lru_idx ON file_digests(last_used_ms);
                PRAGMA user_version = 2;
                COMMIT;
                "#,
            )?;
        }
        Ok(())
    }

    pub fn create_call(
        &self,
        session_id: &str,
        turn_id: Option<&str>,
        cwd: &Path,
        raw_command: &str,
        argv: &[String],
    ) -> Result<PendingCall> {
        let id = Uuid::new_v4().simple().to_string();
        let call = PendingCall {
            id,
            session_id: session_id.to_owned(),
            turn_id: turn_id.map(ToOwned::to_owned),
            cwd: cwd.to_path_buf(),
            raw_command: raw_command.to_owned(),
            argv: argv.to_vec(),
        };
        self.conn.execute(
            "INSERT INTO pending_calls (id, session_id, turn_id, cwd, raw_command, argv_json, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                call.id,
                call.session_id,
                call.turn_id,
                call.cwd.to_string_lossy(),
                call.raw_command,
                serde_json::to_string(&call.argv)?,
                now_ms(),
            ],
        )?;
        Ok(call)
    }

    pub fn get_call(&self, id: &str) -> Result<Option<PendingCall>> {
        self.conn
            .query_row(
                "SELECT id, session_id, turn_id, cwd, raw_command, argv_json FROM pending_calls WHERE id = ?1",
                [id],
                |row| {
                    let argv_json: String = row.get(5)?;
                    let argv = serde_json::from_str(&argv_json).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;
                    Ok(PendingCall {
                        id: row.get(0)?,
                        session_id: row.get(1)?,
                        turn_id: row.get(2)?,
                        cwd: PathBuf::from(row.get::<_, String>(3)?),
                        raw_command: row.get(4)?,
                        argv,
                    })
                },
            )
            .optional()
            .context("read pending call")
    }

    pub fn delete_call(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM pending_calls WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn put_blob(&self, bytes: &[u8]) -> Result<String> {
        let digest = blake3::hash(bytes).to_hex().to_string();
        let target = self.blob_path(&digest)?;
        if target.exists() {
            self.verify_blob(&digest, bytes)?;
            return Ok(digest);
        }

        let parent = target.parent().context("blob target has no parent")?;
        fs::create_dir_all(parent)?;
        set_private_dir(parent)?;
        let staged = parent.join(format!(".{}.{}.tmp", digest, Uuid::new_v4().simple()));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staged)?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        set_private_file(&staged)?;
        match fs::rename(&staged, &target) {
            Ok(()) => {}
            Err(error) if target.exists() => {
                let _ = fs::remove_file(&staged);
                self.verify_blob(&digest, bytes).context(error)?;
            }
            Err(error) => {
                let _ = fs::remove_file(&staged);
                return Err(error).context("commit CAS blob");
            }
        }
        Ok(digest)
    }

    pub fn get_blob(&self, digest: &str) -> Result<Vec<u8>> {
        let path = self.blob_path(digest)?;
        let bytes = fs::read(&path).with_context(|| format!("read blob {digest}"))?;
        let actual = blake3::hash(&bytes).to_hex().to_string();
        if actual != digest {
            bail!("CAS corruption: blob {digest} hashes to {actual}");
        }
        Ok(bytes)
    }

    fn blob_path(&self, digest: &str) -> Result<PathBuf> {
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("invalid BLAKE3 digest");
        }
        Ok(self.blobs.join(&digest[..2]).join(&digest[2..]))
    }

    fn verify_blob(&self, digest: &str, expected: &[u8]) -> Result<()> {
        let existing = self.get_blob(digest)?;
        if existing != expected {
            bail!("CAS collision or corruption for blob {digest}");
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_result(
        &mut self,
        request_key: &str,
        stdout: &[u8],
        stderr: &[u8],
        exit_code: i32,
        duration_ms: u64,
        policy_version: &str,
        proof_json: &str,
    ) -> Result<StoredResult> {
        let stdout_digest = self.put_blob(stdout)?;
        let stderr_digest = self.put_blob(stderr)?;
        let existing = self.get_result(request_key)?;
        if let Some(existing) = existing {
            if existing.stdout_digest != stdout_digest
                || existing.stderr_digest != stderr_digest
                || existing.exit_code != exit_code
            {
                self.quarantine(&existing.id, "same_key_different_result")?;
                bail!("differential mismatch for request key {request_key}; entry quarantined");
            }
            return Ok(existing);
        }

        let result = StoredResult {
            id: format!("r_{}", Uuid::new_v4().simple()),
            request_key: request_key.to_owned(),
            stdout_digest,
            stderr_digest,
            stdout_bytes: stdout.len() as u64,
            stderr_bytes: stderr.len() as u64,
            exit_code,
            duration_ms,
            policy_version: policy_version.to_owned(),
            proof_json: proof_json.to_owned(),
        };
        let now = now_ms();
        let transaction = self.conn.transaction()?;
        transaction.execute(
            "INSERT INTO results (id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json, created_ms, last_used_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?11)",
            params![
                result.id,
                result.request_key,
                result.stdout_digest,
                result.stderr_digest,
                result.stdout_bytes,
                result.stderr_bytes,
                result.exit_code,
                result.duration_ms,
                result.policy_version,
                result.proof_json,
                now,
            ],
        )?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn get_result(&self, request_key: &str) -> Result<Option<StoredResult>> {
        self.conn
            .query_row(
                "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json FROM results WHERE request_key = ?1 AND quarantined = 0",
                [request_key],
                row_to_result,
            )
            .optional()
            .context("lookup cached result")
    }

    pub fn get_result_by_id(&self, id: &str) -> Result<Option<StoredResult>> {
        self.conn
            .query_row(
                "SELECT id, request_key, stdout_digest, stderr_digest, stdout_bytes, stderr_bytes, exit_code, duration_ms, policy_version, proof_json FROM results WHERE id = ?1 AND quarantined = 0",
                [id],
                row_to_result,
            )
            .optional()
            .context("lookup result by id")
    }

    pub fn note_hit(&self, result_id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE results SET hit_count = hit_count + 1, last_used_ms = ?2 WHERE id = ?1",
            params![result_id, now_ms()],
        )?;
        Ok(())
    }

    /// Returns true only when the exact result was already delivered in full to this session.
    pub fn was_delivered(&self, session_id: &str, result_id: &str) -> Result<bool> {
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM deliveries WHERE session_id = ?1 AND result_id = ?2)",
            params![session_id, result_id],
            |row| row.get(0),
        )?;
        Ok(exists)
    }

    pub fn mark_delivered(&self, session_id: &str, result_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO deliveries (session_id, result_id, delivered_ms) VALUES (?1, ?2, ?3)",
            params![session_id, result_id, now_ms()],
        )?;
        Ok(())
    }

    pub fn quarantine(&self, result_id: &str, reason: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE results SET quarantined = 1, quarantine_reason = ?2 WHERE id = ?1",
            params![result_id, reason],
        )?;
        self.record_event(
            None,
            Some(result_id),
            EventDisposition::Quarantined,
            reason,
            0,
            0,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_event(
        &self,
        call_id: Option<&str>,
        result_id: Option<&str>,
        disposition: EventDisposition,
        reason_code: &str,
        elapsed_ms: u64,
        bytes_omitted: u64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO events (call_id, result_id, disposition, reason_code, elapsed_ms, bytes_omitted, created_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                call_id,
                result_id,
                disposition.as_str(),
                reason_code,
                elapsed_ms,
                bytes_omitted,
                now_ms(),
            ],
        )?;
        Ok(())
    }

    pub fn last_event(&self) -> Result<Option<(String, String, Option<String>)>> {
        self.conn
            .query_row(
                "SELECT disposition, reason_code, result_id FROM events ORDER BY id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context("read last event")
    }

    pub fn stats(&self) -> Result<StoreStats> {
        let mut stats = StoreStats::default();
        let mut statement = self.conn.prepare(
            "SELECT disposition, COUNT(*), COALESCE(SUM(bytes_omitted), 0), COALESCE(SUM(elapsed_ms), 0) FROM events GROUP BY disposition",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?;
        for row in rows {
            let (disposition, count, omitted, elapsed) = row?;
            match disposition.as_str() {
                "executed" => stats.executions += count,
                "replayed_full" => {
                    stats.full_replays += count;
                    stats.estimated_execution_ms_saved += elapsed;
                }
                "replayed_compact" => {
                    stats.compact_replays += count;
                    stats.duplicate_bytes_omitted += omitted;
                    stats.estimated_execution_ms_saved += elapsed;
                }
                "passed_through" | "bypassed_no_store" => stats.bypasses += count,
                "quarantined" => stats.quarantines += count,
                _ => {}
            }
        }
        Ok(stats)
    }
}

impl FileDigestCache for Store {
    fn lookup(&mut self, identity: &FileIdentity) -> Option<[u8; 32]> {
        if !identity.is_valid() {
            return None;
        }
        let device = u64_blob(identity.device);
        let inode = u64_blob(identity.inode);
        let row = self
            .conn
            .query_row(
                r#"
                SELECT digest, row_checksum
                FROM file_digests
                WHERE device = ?1 AND inode = ?2 AND mode = ?3 AND uid = ?4
                  AND gid = ?5 AND size = ?6 AND mtime_sec = ?7 AND mtime_nsec = ?8
                  AND ctime_sec = ?9 AND ctime_nsec = ?10
                "#,
                params![
                    device,
                    inode,
                    i64::from(identity.mode),
                    i64::from(identity.uid),
                    i64::from(identity.gid),
                    u64_blob(identity.size),
                    identity.mtime_sec,
                    identity.mtime_nsec,
                    identity.ctime_sec,
                    identity.ctime_nsec,
                ],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional();

        let (digest_bytes, checksum_bytes) = match row {
            Ok(Some(row)) => row,
            Ok(None) => return None,
            Err(_) => return None,
        };
        let Ok(digest) = <[u8; 32]>::try_from(digest_bytes.as_slice()) else {
            self.delete_file_digest(identity);
            return None;
        };
        let Ok(checksum) = <[u8; 32]>::try_from(checksum_bytes.as_slice()) else {
            self.delete_file_digest(identity);
            return None;
        };
        if checksum != file_digest_row_checksum(identity, &digest) {
            self.delete_file_digest(identity);
            return None;
        }
        // Keep warm fingerprinting read-only. Updating LRU state for every file in
        // a recursive tree turns a cache hit into thousands of SQLite writes.
        // `last_used_ms` therefore means last validated/recorded time in v0; an
        // evicted hot digest is merely recomputed, never a correctness failure.
        Some(digest)
    }

    fn record(&mut self, identity: &FileIdentity, digest: [u8; 32]) {
        if !identity.is_valid() {
            return;
        }
        let checksum = file_digest_row_checksum(identity, &digest);
        let insert_result = self.conn.execute(
            r#"
                INSERT INTO file_digests (
                    device, inode, mode, uid, gid, size, mtime_sec, mtime_nsec,
                    ctime_sec, ctime_nsec, digest, row_checksum, last_used_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                ON CONFLICT(device, inode) DO UPDATE SET
                    mode = excluded.mode, uid = excluded.uid, gid = excluded.gid,
                    size = excluded.size, mtime_sec = excluded.mtime_sec,
                    mtime_nsec = excluded.mtime_nsec, ctime_sec = excluded.ctime_sec,
                    ctime_nsec = excluded.ctime_nsec, digest = excluded.digest,
                    row_checksum = excluded.row_checksum, last_used_ms = excluded.last_used_ms
                "#,
            params![
                u64_blob(identity.device),
                u64_blob(identity.inode),
                i64::from(identity.mode),
                i64::from(identity.uid),
                i64::from(identity.gid),
                u64_blob(identity.size),
                identity.mtime_sec,
                identity.mtime_nsec,
                identity.ctime_sec,
                identity.ctime_nsec,
                digest.as_slice(),
                checksum.as_slice(),
                now_ms(),
            ],
        );
        if insert_result.is_err() {
            return;
        }

        self.file_digest_writes_since_prune = self.file_digest_writes_since_prune.saturating_add(1);
        if self.file_digest_writes_since_prune >= FILE_DIGEST_PRUNE_INTERVAL {
            self.prune_file_digests();
            self.file_digest_writes_since_prune = 0;
        }
    }
}

impl Store {
    fn delete_file_digest(&self, identity: &FileIdentity) {
        let _ = self.conn.execute(
            "DELETE FROM file_digests WHERE device = ?1 AND inode = ?2",
            params![u64_blob(identity.device), u64_blob(identity.inode)],
        );
    }

    fn prune_file_digests(&self) {
        let Ok(count) = self
            .conn
            .query_row("SELECT COUNT(*) FROM file_digests", [], |row| {
                row.get::<_, i64>(0)
            })
        else {
            return;
        };
        let excess = (count - MAX_FILE_DIGEST_ROWS).max(0);
        if excess == 0 {
            return;
        }
        let _ = self.conn.execute(
            r#"
            DELETE FROM file_digests
            WHERE (device, inode) IN (
                SELECT device, inode FROM file_digests
                ORDER BY last_used_ms ASC, device ASC, inode ASC LIMIT ?1
            )
            "#,
            [excess],
        );
    }
}

fn u64_blob(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn file_digest_row_checksum(identity: &FileIdentity, digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("again.file-digest-row.v1");
    hasher.update(&identity.device.to_be_bytes());
    hasher.update(&identity.inode.to_be_bytes());
    hasher.update(&identity.mode.to_be_bytes());
    hasher.update(&identity.uid.to_be_bytes());
    hasher.update(&identity.gid.to_be_bytes());
    hasher.update(&identity.size.to_be_bytes());
    hasher.update(&identity.mtime_sec.to_be_bytes());
    hasher.update(&identity.mtime_nsec.to_be_bytes());
    hasher.update(&identity.ctime_sec.to_be_bytes());
    hasher.update(&identity.ctime_nsec.to_be_bytes());
    hasher.update(digest);
    *hasher.finalize().as_bytes()
}

fn create_self_ignoring_gitignore(root: &Path) -> Result<()> {
    if root.file_name().and_then(|name| name.to_str()) != Some(".again") {
        return Ok(());
    }
    let path = root.join(".gitignore");
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut file) => {
            file.write_all(b"*\n")?;
            file.sync_all()?;
            set_private_file(&path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error).with_context(|| format!("create {}", path.display())),
    }
}

fn row_to_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredResult> {
    Ok(StoredResult {
        id: row.get(0)?,
        request_key: row.get(1)?,
        stdout_digest: row.get(2)?,
        stderr_digest: row.get(3)?,
        stdout_bytes: row.get(4)?,
        stderr_bytes: row.get(5)?,
        exit_code: row.get(6)?,
        duration_ms: row.get(7)?,
        policy_version: row.get(8)?,
        proof_json: row.get(9)?,
    })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(unix)]
fn set_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_file_identity() -> FileIdentity {
        FileIdentity {
            device: 17,
            inode: 29,
            mode: 0o100644,
            uid: 501,
            gid: 20,
            size: 4096,
            mtime_sec: 1_700_000_000,
            mtime_nsec: 123,
            ctime_sec: 1_700_000_001,
            ctime_nsec: 456,
        }
    }

    #[test]
    fn blobs_round_trip_and_detect_invalid_digest() {
        let temp = TempDir::new().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let digest = store.put_blob(b"hello").unwrap();
        assert_eq!(store.get_blob(&digest).unwrap(), b"hello");
        assert!(store.get_blob("../escape").is_err());
    }

    #[test]
    fn file_digest_memo_survives_reopen_without_persisting_paths() {
        let temp = TempDir::new().unwrap();
        let identity = test_file_identity();
        let digest = [0x5a; 32];
        {
            let mut store = Store::open(temp.path()).unwrap();
            store.record(&identity, digest);
            assert_eq!(store.lookup(&identity), Some(digest));
        }

        let mut reopened = Store::open(temp.path()).unwrap();
        assert_eq!(reopened.lookup(&identity), Some(digest));
        let columns: Vec<String> = reopened
            .conn
            .prepare("PRAGMA table_info(file_digests)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(!columns.iter().any(|column| column.contains("path")));
    }

    #[test]
    fn corrupted_file_digest_row_is_a_miss_and_can_be_recomputed() {
        let temp = TempDir::new().unwrap();
        let identity = test_file_identity();
        let digest = [0x71; 32];
        let mut store = Store::open(temp.path()).unwrap();
        store.record(&identity, digest);
        store
            .conn
            .execute("UPDATE file_digests SET digest = zeroblob(32)", [])
            .unwrap();

        assert_eq!(store.lookup(&identity), None, "checksum failure is a miss");
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM file_digests", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0, "corrupt row is discarded");

        store.record(&identity, digest);
        assert_eq!(store.lookup(&identity), Some(digest));
    }

    #[test]
    fn version_one_database_migrates_file_digest_table() {
        let temp = TempDir::new().unwrap();
        fs::create_dir_all(temp.path().join("blobs")).unwrap();
        let database = temp.path().join("again.sqlite");
        Connection::open(&database)
            .unwrap()
            .execute_batch("PRAGMA user_version = 1;")
            .unwrap();

        let store = Store::open(temp.path()).unwrap();
        let version: i64 = store
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let exists: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = 'file_digests'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exists, 1);
    }

    #[test]
    fn repository_scoped_store_is_self_ignored_without_overwriting_user_file() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join(".again");
        let store = Store::open(&root).unwrap();
        assert_eq!(fs::read_to_string(root.join(".gitignore")).unwrap(), "*\n");
        drop(store);

        fs::write(root.join(".gitignore"), "user-owned\n").unwrap();
        drop(Store::open(&root).unwrap());
        assert_eq!(
            fs::read_to_string(root.join(".gitignore")).unwrap(),
            "user-owned\n"
        );
    }

    #[test]
    fn pending_calls_round_trip_without_shell_interpolation() {
        let temp = TempDir::new().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let call = store
            .create_call(
                "session",
                Some("turn"),
                temp.path(),
                "rg needle src",
                &["rg".into(), "needle".into(), "src".into()],
            )
            .unwrap();
        assert_eq!(store.get_call(&call.id).unwrap(), Some(call.clone()));
        store.delete_call(&call.id).unwrap();
        assert_eq!(store.get_call(&call.id).unwrap(), None);
    }

    #[test]
    fn results_and_delivery_state_round_trip() {
        let temp = TempDir::new().unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        let result = store
            .insert_result("key", b"out", b"", 0, 50, "v0", "{}")
            .unwrap();
        assert_eq!(store.get_result("key").unwrap(), Some(result.clone()));
        assert!(!store.was_delivered("s", &result.id).unwrap());
        store.mark_delivered("s", &result.id).unwrap();
        assert!(store.was_delivered("s", &result.id).unwrap());
    }

    #[test]
    fn same_key_with_different_output_is_quarantined() {
        let temp = TempDir::new().unwrap();
        let mut store = Store::open(temp.path()).unwrap();
        store
            .insert_result("key", b"first", b"", 0, 1, "v0", "{}")
            .unwrap();
        assert!(
            store
                .insert_result("key", b"second", b"", 0, 1, "v0", "{}")
                .is_err()
        );
        assert!(store.get_result("key").unwrap().is_none());
    }
}
