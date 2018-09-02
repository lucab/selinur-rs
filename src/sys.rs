//! Support for `selinuxfs`, main OS interface for global SELinux state.

use super::errors::{self, ResultExt};
use openat;
use std::{collections, fs, io, path};

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

    /// Return the value of the named SELinux booleans, if it exists.
    ///
    /// First value is the current state, while the second is the
    /// value pending a commit.
    pub fn sebool<T: AsRef<str>>(&self, name: T) -> errors::Result<Option<(bool, bool)>> {
        let booldir = self.dirfd.sub_dir("booleans")?;
        let target_bool = booldir.open_file(name.as_ref());

        // Check that the sebool exists.
        if let Err(ref e) = target_bool {
            if e.kind() == io::ErrorKind::NotFound {
                return Ok(None);
            }
        }

        // Check that the sebool is a file.
        let mut boolfile = target_bool?;
        if !boolfile.metadata()?.is_file() {
            return Ok(None);
        }

        // Read current and pending values (whitespace separated).
        let mut buf = vec![0; 3];
        boolfile.read_exact(&mut buf)?;
        let cur = match buf.get(0) {
            Some(b'0') => false,
            Some(b'1') => true,
            _ => bail!("unable to detect sebool current value"),
        };
        let next = match buf.get(2) {
            Some(b'0') => false,
            Some(b'1') => true,
            _ => bail!("unable to detect sebool pending value"),
        };

        Ok(Some((cur, next)))
    }

    /// Return a map of all available SELinux booleans.
    ///
    /// First value is the current state, while the second is the
    /// value pending a commit.
    pub fn dump_sebools(&self) -> errors::Result<collections::BTreeMap<String, (bool, bool)>> {
        let mut boolmap = collections::BTreeMap::new();
        let sebools = self.list_sebools()?;
        for name in sebools {
            let vals = self.sebool(&name)?;
            match vals {
                Some(bb) => boolmap.insert(name, bb),
                None => bail!("failed to get value for sebool {}", name),
            };
        }
        Ok(boolmap)
    }

    /// Return a list of all available SELinux booleans names.
    pub fn list_sebools(&self) -> errors::Result<collections::BTreeSet<String>> {
        let mut boolset = collections::BTreeSet::new();
        let booldir = self.dirfd.list_dir("booleans")?;
        for entry in booldir {
            // Ignore unavailable entries.
            let bfile = match entry {
                Ok(f) => f,
                _ => continue,
            };
            // Ignore non-file entries.
            let ftype = bfile.simple_type().unwrap_or(openat::SimpleType::Other);
            if ftype != openat::SimpleType::File {
                continue;
            }
            boolset.insert(bfile.file_name().to_string_lossy().into_owned());
        }
        Ok(boolset)
    }
}
