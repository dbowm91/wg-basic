//! Cross-process advisory ownership of one state path.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("the state service lease is already held")]
    Busy,
    #[error("the state service lease path is unsafe")]
    Unsafe,
    #[error("the state service lease could not be inspected or acquired")]
    Io,
}

/// Owns an advisory lock until its file descriptor is closed, including on
/// process death. File contents are informational and never prove ownership.
pub struct ServiceLease {
    _file: nix::fcntl::Flock<File>,
    path: PathBuf,
}

/// Coordinates purge/restore with online backups without stopping serve.
/// Backups take a shared lease; replacement and purge take an exclusive one.
pub struct MaintenanceLease {
    _file: nix::fcntl::Flock<File>,
}

impl MaintenanceLease {
    pub fn path_for_state(state: &Path) -> Result<PathBuf, LeaseError> {
        let absolute = std::path::absolute(state).map_err(|_| LeaseError::Io)?;
        let name = absolute.file_name().ok_or(LeaseError::Unsafe)?;
        let mut lock_name = name.to_os_string();
        lock_name.push(".maintenance.lock");
        Ok(absolute.with_file_name(lock_name))
    }

    pub fn shared(state: &Path) -> Result<Self, LeaseError> {
        Self::lock(state, nix::fcntl::FlockArg::LockSharedNonblock)
    }

    pub fn exclusive(state: &Path) -> Result<Self, LeaseError> {
        Self::lock(state, nix::fcntl::FlockArg::LockExclusiveNonblock)
    }

    fn lock(state: &Path, mode: nix::fcntl::FlockArg) -> Result<Self, LeaseError> {
        let path = Self::path_for_state(state)?;
        let parent = path.parent().ok_or(LeaseError::Unsafe)?;
        let parent_meta = fs::symlink_metadata(parent).map_err(|_| LeaseError::Unsafe)?;
        if !parent_meta.is_dir()
            || parent_meta.uid() != nix::unistd::geteuid().as_raw()
            || parent_meta.mode() & 0o022 != 0
        {
            return Err(LeaseError::Unsafe);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| LeaseError::Unsafe)?;
        verify_file(&file)?;
        let file = nix::fcntl::Flock::lock(file, mode).map_err(|(_, error)| {
            if error == nix::errno::Errno::EWOULDBLOCK {
                LeaseError::Busy
            } else {
                LeaseError::Io
            }
        })?;
        verify_file(&file)?;
        Ok(Self { _file: file })
    }
}

impl ServiceLease {
    pub fn path_for_state(state: &Path) -> Result<PathBuf, LeaseError> {
        let absolute = std::path::absolute(state).map_err(|_| LeaseError::Io)?;
        let name = absolute.file_name().ok_or(LeaseError::Unsafe)?;
        let mut lease_name = name.to_os_string();
        lease_name.push(".serve.lock");
        Ok(absolute.with_file_name(lease_name))
    }

    pub fn acquire(state: &Path) -> Result<Self, LeaseError> {
        let path = Self::path_for_state(state)?;
        let parent = path.parent().ok_or(LeaseError::Unsafe)?;
        let parent_meta = fs::symlink_metadata(parent).map_err(|_| LeaseError::Unsafe)?;
        if !parent_meta.is_dir()
            || parent_meta.uid() != nix::unistd::geteuid().as_raw()
            || parent_meta.mode() & 0o022 != 0
        {
            return Err(LeaseError::Unsafe);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| LeaseError::Unsafe)?;
        verify_file(&file)?;
        let file = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|(_, error)| {
                if error == nix::errno::Errno::EWOULDBLOCK {
                    LeaseError::Busy
                } else {
                    LeaseError::Io
                }
            })?;
        verify_file(&file)?;
        file.set_len(0).map_err(|_| LeaseError::Io)?;
        let mut writer = &*file;
        writeln!(
            writer,
            "pid={} started={}",
            std::process::id(),
            crate::state::now_seconds()
        )
        .map_err(|_| LeaseError::Io)?;
        writer.flush().map_err(|_| LeaseError::Io)?;
        Ok(Self { _file: file, path })
    }

    /// Returns whether a live process holds the lock. Missing and stale lock
    /// files are free; their contents are not consulted.
    pub fn is_held(state: &Path) -> Result<bool, LeaseError> {
        let path = Self::path_for_state(state)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(LeaseError::Io),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err(LeaseError::Unsafe);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| LeaseError::Unsafe)?;
        verify_file(&file)?;
        match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(_lock) => Ok(false),
            Err((_, error)) if error == nix::errno::Errno::EWOULDBLOCK => Ok(true),
            Err(_) => Err(LeaseError::Io),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn verify_file(file: &File) -> Result<(), LeaseError> {
    let metadata = file.metadata().map_err(|_| LeaseError::Io)?;
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(LeaseError::Unsafe);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lock_excludes_another_open_file_and_releases_on_drop() {
        let root = std::env::temp_dir().join(format!("wg-basic-lease-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join("state.db");
        let first = ServiceLease::acquire(&state).unwrap();
        assert!(ServiceLease::is_held(&state).unwrap());
        assert!(matches!(
            ServiceLease::acquire(&state),
            Err(LeaseError::Busy)
        ));
        drop(first);
        assert!(!ServiceLease::is_held(&state).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_backups_exclude_exclusive_maintenance_but_not_each_other() {
        let root =
            std::env::temp_dir().join(format!("wg-basic-maint-lease-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let state = root.join("state.db");
        let first = MaintenanceLease::shared(&state).unwrap();
        let second = MaintenanceLease::shared(&state).unwrap();
        assert!(matches!(
            MaintenanceLease::exclusive(&state),
            Err(LeaseError::Busy)
        ));
        drop(first);
        drop(second);
        let exclusive = MaintenanceLease::exclusive(&state).unwrap();
        assert!(matches!(
            MaintenanceLease::shared(&state),
            Err(LeaseError::Busy)
        ));
        drop(exclusive);
        fs::remove_dir_all(root).unwrap();
    }
}
