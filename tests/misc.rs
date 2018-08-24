extern crate selinur;

use std::fs;

#[test]
fn test_misc_has_selinuxfs() {
    let r0 = selinur::has_selinuxfs(None).unwrap();

    if let Ok(procfs) = fs::File::open("/proc") {
        let r1 = selinur::has_selinuxfs(Some(procfs)).unwrap();
        assert_eq!(r0, r1);
    }
}
