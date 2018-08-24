use super::errors;
use errno;
use libc;
use openat;
use std::{ffi, fs, io};

use std::io::BufRead;
use std::os::unix::io::{FromRawFd, IntoRawFd};

/// Check whether current kernel supports SELinux (via selinuxfs).
///
/// This detects whether the OS was booted with SELinux support. It
/// checks for "selinuxfs" via:
///  1. `/proc/filesystems`
///  2. `sysfs()`
pub fn has_selinuxfs(procfs_mountpoint: Option<fs::File>) -> errors::Result<bool> {
    let dir = match procfs_mountpoint {
        Some(d) => d,
        None => fs::File::open("/proc")?,
    };

    if !dir.metadata()?.is_dir() {
        bail!("not a directory");
    }
    // UNSAFE(lucab): checked above that this is a dirfd, ownership transferred here.
    let dirfd = unsafe { openat::Dir::from_raw_fd(dir.into_raw_fd()) };

    // Check /proc/filesystems for "selinuxfs".
    let fp = dirfd.open_file("filesystems")?;
    if let Ok(r) = check_procfs(fp) {
        return Ok(r);
    }

    // Check sysfs(1, "selinuxfs");
    if let Ok(r) = check_sysfs() {
        return Ok(r);
    }

    bail!("unable to detect selinuxfs");
}

pub(crate) fn check_procfs(fp: fs::File) -> errors::Result<bool> {
    let bufrd = io::BufReader::new(fp);
    for l in bufrd.lines() {
        if let Ok(s) = l {
            if s.contains("selinuxfs") {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(crate) fn check_sysfs() -> errors::Result<bool> {
    let fsname = ffi::CString::new("selinuxfs")?;
    let name_ptr = fsname.as_ptr();

    // UNSAFE(lucab): name_ptr points to memory owned by cname.
    let r = unsafe { libc::syscall(libc::SYS_sysfs, 1, name_ptr) };

    // Found!
    if r >= 0 {
        return Ok(true);
    }

    let eno = errno::errno();
    let e: i32 = eno.into();
    // Not found!
    if e == libc::EINVAL {
        return Ok(false);
    }

    // Uhm, no clear result :(
    // Disabled `CONFIG_SYSFS_SYSCALL` or seccomp filter could result in this.
    Err(errors::Error::from_kind(errors::ErrorKind::Sys(eno)).chain_err(|| "sysfs error"))
}
