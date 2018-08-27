//! Support for `selinuxfs`, main OS interface for global SELinux state.

use super::errors::{self, ResultExt};
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

    /// Whether the kernel denies unknown object classes or permissions.
    pub fn deny_unknown(&self) -> errors::Result<bool> {
        let mut fp = self.dirfd.open_file("deny_unknown")?;
        let mut buf = vec![b'0'];
        fp.read_exact(&mut buf)?;
        match buf.get(0) {
            Some(b'0') => Ok(false),
            Some(b'1') => Ok(true),
            _ => bail!("unable to detect deny_unknown mode"),
        }
    }

    /// Whether the kernel rejects unknown object classes or permissions.
    pub fn reject_unknown(&self) -> errors::Result<bool> {
        let mut fp = self.dirfd.open_file("reject_unknown")?;
        let mut buf = vec![b'0'];
        fp.read_exact(&mut buf)?;
        match buf.get(0) {
            Some(b'0') => Ok(false),
            Some(b'1') => Ok(true),
            _ => bail!("unable to detect reject_unknown mode"),
        }
    }

    /// Whether Multi-Level Security (MLS) support is enabled.
    pub fn mls_enabled(&self) -> errors::Result<bool> {
        let mut fp = self.dirfd.open_file("mls")?;
        let mut buf = vec![b'0'];
        fp.read_exact(&mut buf)?;
        match buf.get(0) {
            Some(b'0') => Ok(false),
            Some(b'1') => Ok(true),
            _ => bail!("unable to detect mls mode"),
        }
    }

    /// Whether the kernel is only checking application-requested
    /// protection on mmap/mprotect.
    pub fn check_requested_protection(&self) -> errors::Result<bool> {
        let mut fp = self.dirfd.open_file("checkreqprot")?;
        let mut buf = vec![b'0'];
        fp.read_exact(&mut buf)?;
        match buf.get(0) {
            Some(b'0') => Ok(false),
            Some(b'1') => Ok(true),
            _ => bail!("unable to detect checkreqprot mode"),
        }
    }

    /// Policy format version supported by the current kernel.
    pub fn policy_version(&self) -> errors::Result<u32> {
        let mut fp = self.dirfd.open_file("policyvers")?;
        let mut val = String::with_capacity(4);
        fp.read_to_string(&mut val)?;
        val.parse()
            .chain_err(|| "failed to parse policy version integer")
    }
}
