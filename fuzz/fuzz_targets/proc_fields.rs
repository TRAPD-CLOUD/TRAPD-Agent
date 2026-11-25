#![no_main]

use libfuzzer_sys::fuzz_target;
use trapd_schema as schema;

#[allow(dead_code)]
#[path = "../../agent/src/forensics/session.rs"]
mod session;

fuzz_target!(|fields: [u8; 8]| {
    let inode = u64::from_le_bytes(fields);
    let uid = u32::from_le_bytes([fields[0], fields[1], fields[2], fields[3]]);
    let minor = fields[4];
    let tty = (136 << 8) + i32::from(minor);
    let stat = format!("100 (worker )( {uid}) S 7 100 7 {tty} 100");
    let tty_nr = session::parse_tty_nr_from_stat(&stat).unwrap();
    assert_eq!(session::tty_from_nr(tty_nr), Some(format!("pts/{minor}")));
    assert_eq!(
        session::parse_ns_inode(&format!("net:[{inode}]")),
        Some(inode)
    );
    assert_eq!(
        session::parse_id_field(&uid.to_string()),
        (uid != u32::MAX).then_some(uid)
    );

    let id = format!("{inode:064x}");
    let scope = format!("/system.slice/docker-{id}.scope");
    let cgroup = session::most_specific_cgroup(&format!("1:name=systemd:/\n0::{scope}\n")).unwrap();
    assert_eq!(
        session::container_from_cgroup(&cgroup),
        Some(("docker", id))
    );
});
