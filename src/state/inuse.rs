//! Process-wide accounting of which state databases this process has open.
//!
//! Restore is an offline, exclusive operation: it must never write into a
//! database that a live [`StateStore`](super::store::StateStore) still owns.
//! Within one process that is provable, because every store registers its path
//! on open and unregisters it on drop.
//!
//! This is deliberately a *per-process* guarantee, not a host-wide one. Two
//! independent wg-basic processes are outside its reach, which is exactly why
//! restore also refuses to run unless the operator has stopped the management
//! service.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

fn open_databases() -> &'static Mutex<HashSet<PathBuf>> {
    static OPEN: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    OPEN.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Records that this process holds `path` open.
pub(crate) fn register(path: &Path) {
    if let Ok(mut open) = open_databases().lock() {
        open.insert(path.to_path_buf());
    }
}

/// Records that this process no longer holds `path` open.
pub(crate) fn unregister(path: &Path) {
    if let Ok(mut open) = open_databases().lock() {
        open.remove(path);
    }
}

/// Whether this process currently holds `path` open.
///
/// Normalizes the path first, so `/a/b` and `/a/./b` are recognized as the same
/// database rather than looking like two unrelated files.
pub(crate) fn is_open_in_this_process(path: &Path) -> bool {
    let normalized = normalize(path);
    open_databases()
        .lock()
        .map(|open| open.iter().any(|entry| normalize(entry) == normalized))
        .unwrap_or(true)
}

/// Best-effort lexical normalization.
///
/// This deliberately does not resolve symlinks or touch the filesystem: it only
/// removes `.` segments and collapses repeated separators so two spellings of
/// one path compare equal.
fn normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_is_exclusive_per_path() {
        let path = Path::new("/tmp/wgb-registry-a.db");
        assert!(!is_open_in_this_process(path));
        register(path);
        assert!(is_open_in_this_process(path));
        // A different spelling of the same file is still the same database.
        assert!(is_open_in_this_process(Path::new(
            "/tmp/./wgb-registry-a.db"
        )));
        unregister(path);
        assert!(!is_open_in_this_process(path));
    }

    #[test]
    fn normalization_collapses_cur_dir_and_repeated_separators() {
        assert_eq!(
            normalize(Path::new("/tmp//./state.db")),
            normalize(Path::new("/tmp/state.db"))
        );
    }
}
