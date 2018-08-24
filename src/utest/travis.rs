use super::kernel::{self, has_selinuxfs};
use std::io::Write;
use std::{env, fs, io};

#[test]
fn test_travis_has_selinuxfs() {
    if !is_travis() {
        return;
    };

    let r0 = has_selinuxfs(None).unwrap();
    assert_eq!(r0, false);
    let procfs = fs::File::open("/proc").unwrap();
    let r1 = has_selinuxfs(Some(procfs)).unwrap();
    assert_eq!(r0, r1);
}

#[test]
fn test_travis_procfs() {
    if !is_travis() {
        return;
    };

    let fs_file = fs::File::open("/proc/filesystems").unwrap();
    let r0 = kernel::check_procfs(fs_file).unwrap();
    assert_eq!(r0, false);
}

#[test]
fn test_travis_sysfs() {
    if !is_travis() {
        return;
    };

    // This returns ENOPERM on Travis (likely seccomp).
    kernel::check_sysfs().unwrap_err();
}

fn is_travis() -> bool {
    if let Err(_) = env::var("TRAVIS_RUST_VERSION") {
        let out = io::stdout();
        writeln!(out.lock(), "Not on TravisCI, skipping.").ok();
        false
    } else {
        true
    }
}
