//! Windows service lease. `LockFileEx` is released when the handle closes,
//! including when the process dies. The DACL, not a mode bit, is the privacy check.

use super::super::privacy::{self, secret_file_owned_by_us};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use wg_basic_win32_sys::{FileLock, LockError as WinLockError};

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("the state service lease is already held")]
    Busy,
    #[error("the state service lease path is unsafe")]
    Unsafe,
    #[error("the state service lease could not be inspected or acquired")]
    Io,
}

pub struct ServiceLease {
    _file: FileLock,
    path: PathBuf,
}

pub struct MaintenanceLease {
    _file: FileLock,
}

impl MaintenanceLease {
    pub fn path_for_state(state: &Path) -> Result<PathBuf, LeaseError> {
        lock_path(state, ".maintenance.lock")
    }

    pub fn shared(state: &Path) -> Result<Self, LeaseError> {
        Ok(Self {
            _file: lock_file(&Self::path_for_state(state)?, false, false)?,
        })
    }

    pub fn exclusive(state: &Path) -> Result<Self, LeaseError> {
        Ok(Self {
            _file: lock_file(&Self::path_for_state(state)?, true, false)?,
        })
    }
}

impl ServiceLease {
    pub fn path_for_state(state: &Path) -> Result<PathBuf, LeaseError> {
        lock_path(state, ".serve.lock")
    }

    pub fn acquire(state: &Path) -> Result<Self, LeaseError> {
        let path = Self::path_for_state(state)?;
        let file = lock_file(&path, true, true)?;
        Ok(Self { _file: file, path })
    }

    pub fn is_held(state: &Path) -> Result<bool, LeaseError> {
        Self::is_held_by_uid(state, privacy::current_uid())
    }

    pub(crate) fn is_held_by_uid(state: &Path, _owner_uid: u32) -> Result<bool, LeaseError> {
        let path = Self::path_for_state(state)?;
        if !path.exists() {
            return Ok(false);
        }
        if !secret_file_owned_by_us(&path) {
            return Err(LeaseError::Unsafe);
        }
        match try_lock(&path, true, false) {
            Ok(lock) => {
                drop(lock);
                Ok(false)
            }
            Err(LeaseError::Busy) => Ok(true),
            Err(error) => Err(error),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn lock_path(state: &Path, suffix: &str) -> Result<PathBuf, LeaseError> {
    let absolute = std::path::absolute(state).map_err(|_| LeaseError::Io)?;
    let name = absolute.file_name().ok_or(LeaseError::Unsafe)?;
    let mut lock_name = name.to_os_string();
    lock_name.push(suffix);
    Ok(absolute.with_file_name(lock_name))
}

fn lock_file(path: &Path, exclusive: bool, annotate: bool) -> Result<FileLock, LeaseError> {
    let parent = path.parent().ok_or(LeaseError::Unsafe)?;
    let parent_state =
        privacy::inspect(parent, privacy::current_uid()).map_err(|_| LeaseError::Unsafe)?;
    if !parent_state.is_dir || parent_state.mode & 0o022 != 0 {
        return Err(LeaseError::Unsafe);
    }
    try_lock(path, exclusive, annotate)
}

fn try_lock(path: &Path, exclusive: bool, annotate: bool) -> Result<FileLock, LeaseError> {
    let mut file = if path.exists() {
        if !secret_file_owned_by_us(path) {
            return Err(LeaseError::Unsafe);
        }
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| LeaseError::Unsafe)?
    } else {
        privacy::create_secret_file(path).map_err(|_| LeaseError::Unsafe)?
    };
    if annotate {
        file.set_len(0).map_err(|_| LeaseError::Io)?;
        writeln!(
            file,
            "pid={} started={}",
            std::process::id(),
            crate::state::now_seconds()
        )
        .map_err(|_| LeaseError::Io)?;
        file.flush().map_err(|_| LeaseError::Io)?;
    }
    let locked = if exclusive {
        FileLock::try_exclusive(file)
    } else {
        FileLock::try_shared(file)
    };
    match locked {
        Ok(lock) => Ok(lock),
        Err(WinLockError::Busy) => Err(LeaseError::Busy),
        Err(WinLockError::Io) => Err(LeaseError::Io),
    }
}
