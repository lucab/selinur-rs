extern crate selinur;

use selinur::sys;
use std::{io};

use std::io::Write;

#[test]
fn test_sys_sebools_list() {
    if !has_selinuxfs() {
        return;
    }

    let sefs = sys::SELinuxFs::open_path(sys::DEFAULT_PATH).unwrap();
    let bools = sefs.list_sebools().unwrap();
    // NOTE(lucab): this is a strong assumption, but not guaranteed.
    assert!(bools.len() > 0);
}

fn has_selinuxfs() -> bool {
    let ok = selinur::has_selinuxfs(None).unwrap_or(false);
    if !ok {
        let out = io::stdout();
        writeln!(out.lock(), "selinuxfs not available, skipping.").ok();
    }
    ok
}
