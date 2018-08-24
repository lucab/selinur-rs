//! Support for `selinuxfs`, main OS interface for global SELinux state.

use super::errors;
use openat;
use std::{fs, path};

use std::io::Read;
use std::os::unix::io::{FromRawFd, IntoRawFd};

/// Default SELinux FS mountpoint.
pub const DEFAULT_PATH: &str = "/sys/fs/selinux/";

/// Main OS interface for SELinux (via selinuxfs).
pub struct SELinuxFs {
    dirfd: openat::Dir,
}

impl SELinuxFs {
    /// Open a `SELinuxFs` instance at path.
    pub fn open_path<P: AsRef<path::Path>>(fspath: P) -> errors::Result<Self> {
        let fp = fs::File::open(fspath.as_ref())?;
        Self::from_file(fp)
    }

    /// Create a `SELinuxFs` instance from a `File`.
    ///
    /// Open file must point to a directory which is a mountpoint
    /// for a `selinux` filesystem.
    pub fn from_file(fp: fs::File) -> errors::Result<Self> {
        if !fp.metadata()?.is_dir() {
            bail!("selinuxfs path is not a directory");
        }
        // UNSAFE(lucab): checked above that this is a dirfd, ownership transferred here.
        let dirfd = unsafe { openat::Dir::from_raw_fd(fp.into_raw_fd()) };
        let fs = Self { dirfd };
        Ok(fs)
    }

    /// Whether the kernel is in SELinux enforcing mode.
    pub fn is_enforcing(&self) -> errors::Result<bool> {
        let mut fp = self.dirfd.open_file("enforce")?;
        let mut buf = vec![b'0'];
        fp.read_exact(&mut buf)?;
        match buf.get(0) {
            Some(b'0') => Ok(false),
            Some(b'1') => Ok(true),
            _ => bail!("unable to detect enforcing mode"),
        }
    }
}
