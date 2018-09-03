extern crate selinur;

use selinur::sys;
use std::{io};

use std::io::Write;

#[test]
fn test_sys_sebools_list() {
    let sefs = match auto_selinuxfs() {
        Some(fs) => fs,
        None => return,
    };

    let bools = sefs.list_sebools().unwrap();
    // NOTE(lucab): this is a strong assumption, but not guaranteed.
    assert!(bools.len() > 0);
}

fn auto_selinuxfs() -> Option<sys::SELinuxFs> {
    let ok = selinur::has_selinuxfs(None).unwrap_or(false);
    if !ok {
        let out = io::stdout();
        writeln!(out.lock(), "selinuxfs not available, skipping.").ok();
        return None;
    }
    if let Ok(fs) = sys::SELinuxFs::open_path(sys::DEFAULT_PATH) {
        return Some(fs);
    }
    if let Ok(fs) = sys::SELinuxFs::mount_fs(sys::DEFAULT_PATH) {
        return Some(fs);
    }

    let out = io::stdout();
    writeln!(out.lock(), "unable to open or mount selinuxfs, skipping.").ok();
    None
}
