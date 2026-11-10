//! Secret-file privacy.
//!
//! Unix checks the owner uid and the mode bits. Windows checks a protected
//! DACL with one allow ACE for the current user. A missing mode bit is not
//! treated as success.

use std::fs::{self, File};
use std::io;
use std::path::Path;

pub(crate) fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

pub(crate) struct Inspection {
    pub is_symlink: bool,
    pub is_dir: bool,
    pub is_file: bool,
    pub owner: u32,
    pub expected: u32,
    /// Unix mode. On Windows a private object is `0o600` and anything else is
    /// `0o777`, so the existing mode masks fail closed.
    pub mode: u32,
}

pub(crate) fn inspect(path: &Path, expected_uid: u32) -> io::Result<Inspection> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Inspection {
            is_symlink: metadata.file_type().is_symlink(),
            is_dir: metadata.is_dir(),
            is_file: metadata.is_file(),
            owner: metadata.uid(),
            expected: expected_uid,
            mode: metadata.mode(),
        })
    }
    #[cfg(windows)]
    {
        let private = wg_basic_win32_sys::is_private(path).unwrap_or(false);
        Ok(Inspection {
            is_symlink: metadata.file_type().is_symlink(),
            is_dir: metadata.is_dir() && !metadata.file_type().is_symlink(),
            is_file: metadata.is_file() && !metadata.file_type().is_symlink(),
            owner: expected_uid,
            expected: expected_uid,
            mode: if private { 0o600 } else { 0o777 },
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = expected_uid;
        Ok(Inspection {
            is_symlink: metadata.file_type().is_symlink(),
            is_dir: metadata.is_dir(),
            is_file: metadata.is_file(),
            owner: 1,
            expected: 0,
            mode: 0o777,
        })
    }
}

pub(crate) fn create_secret_file(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(windows)]
    {
        wg_basic_win32_sys::create_private_file(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secret files are not supported on this platform",
        ))
    }
}

pub(crate) fn restrict_secret(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    {
        wg_basic_win32_sys::restrict_to_current_user(path)
            .map_err(|error| io::Error::other(error.to_string()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secret files are not supported on this platform",
        ))
    }
}

#[cfg(test)]
pub(crate) fn restrict_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
    }
    #[cfg(windows)]
    {
        wg_basic_win32_sys::restrict_to_current_user(path)
            .map_err(|error| io::Error::other(error.to_string()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private directories are not supported on this platform",
        ))
    }
}

/// True when a purge is allowed to delete this regular secret file.
pub(crate) fn secret_file_owned_by_us(path: &Path) -> bool {
    match inspect(path, current_uid()) {
        Ok(inspection) => {
            !inspection.is_symlink
                && inspection.is_file
                && inspection.owner == inspection.expected
                && inspection.mode & 0o077 == 0
        }
        Err(_) => false,
    }
}
