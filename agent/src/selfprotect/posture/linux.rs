//! Linux platform posture, read from procfs/sysfs under a configurable root so
//! tests run against fixture trees.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use super::snapshot::Setting;

const SECURE_BOOT_VAR: &str =
    "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
/// `kernel.tainted` bits that mean the module/kernel integrity chain was
/// bypassed: forced module load (bit 1), forced module unload (bit 3), unsigned module
/// (bit 13). Proprietary (0), out-of-specification SMP (2) and out-of-tree (12) are
/// common and benign. See Documentation/admin-guide/tainted-kernels.rst.
pub const TAINT_INTEGRITY_MASK: u64 = (1 << 1) | (1 << 3) | (1 << 13);

fn read_small(root: &Path, rel: &str) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::open(root.join(rel))
        .ok()?
        .take(4096)
        .read_to_end(&mut buf)
        .ok()?;
    Some(buf)
}

fn read_text(root: &Path, rel: &str) -> Option<String> {
    read_small(root, rel).map(|b| String::from_utf8_lossy(&b).trim().to_string())
}

/// efivar layout: 4 attribute bytes, then the payload (one byte for SecureBoot).
pub fn parse_secure_boot_var(bytes: &[u8]) -> Option<bool> {
    match bytes {
        [_, _, _, _, v] => Some(*v == 1),
        _ => None,
    }
}

/// `none [integrity] confidentiality`: the bracketed word is active.
pub fn parse_lockdown(text: &str) -> Option<&str> {
    let start = text.find('[')? + 1;
    let end = text[start..].find(']')? + start;
    Some(&text[start..end])
}

pub fn collect(root: &Path) -> BTreeMap<String, Setting> {
    let mut m = BTreeMap::new();

    let secure_boot = if let Some(b) = read_small(root, SECURE_BOOT_VAR) {
        match parse_secure_boot_var(&b) {
            Some(on) => Setting::flag(on),
            None => Setting::unknown("unparseable"),
        }
    } else if root.join("sys/firmware/efi").is_dir() {
        Setting::unknown("unreadable")
    } else {
        Setting::unknown("not_uefi")
    };
    m.insert("secure_boot".into(), secure_boot);

    m.insert(
        "kernel_lockdown".into(),
        match read_text(root, "sys/kernel/security/lockdown")
            .as_deref()
            .and_then(parse_lockdown)
        {
            Some("none") => Setting::new("none", Some(false)),
            Some(mode) => Setting::new(mode, Some(true)),
            None => Setting::unknown("unavailable"),
        },
    );

    m.insert(
        "module_sig_enforce".into(),
        match read_text(root, "sys/module/module/parameters/sig_enforce").as_deref() {
            Some("Y") | Some("1") => Setting::flag(true),
            Some("N") | Some("0") => Setting::flag(false),
            _ => Setting::unknown("unavailable"),
        },
    );

    m.insert(
        "kernel_tainted".into(),
        match read_text(root, "proc/sys/kernel/tainted").and_then(|t| t.parse::<u64>().ok()) {
            Some(v) => Setting::new(v.to_string(), Some(v & TAINT_INTEGRITY_MASK == 0)),
            None => Setting::unknown("unavailable"),
        },
    );

    m.insert(
        "kexec_load_disabled".into(),
        match read_text(root, "proc/sys/kernel/kexec_load_disabled").as_deref() {
            Some("1") => Setting::flag(true),
            Some("0") => Setting::flag(false),
            _ => Setting::unknown("unavailable"),
        },
    );

    m.insert(
        "yama_ptrace_scope".into(),
        match read_text(root, "proc/sys/kernel/yama/ptrace_scope")
            .and_then(|t| t.parse::<u8>().ok())
        {
            Some(v) => Setting::new(v.to_string(), Some(v >= 1)),
            None => Setting::unknown("unavailable"),
        },
    );
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(root: &Path, rel: &str, data: &[u8]) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    fn tree() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("trapd_posture_linux_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn parsers() {
        assert_eq!(parse_secure_boot_var(&[6, 0, 0, 0, 1]), Some(true));
        assert_eq!(parse_secure_boot_var(&[6, 0, 0, 0, 0]), Some(false));
        assert_eq!(parse_secure_boot_var(&[6, 0, 0]), None);
        assert_eq!(
            parse_lockdown("none [integrity] confidentiality"),
            Some("integrity")
        );
        assert_eq!(
            parse_lockdown("[none] integrity confidentiality"),
            Some("none")
        );
        assert_eq!(parse_lockdown("garbage"), None);
    }

    #[test]
    fn hardened_host() {
        let r = tree();
        put(&r, SECURE_BOOT_VAR, &[6, 0, 0, 0, 1]);
        put(
            &r,
            "sys/kernel/security/lockdown",
            b"none [integrity] confidentiality\n",
        );
        put(&r, "sys/module/module/parameters/sig_enforce", b"Y\n");
        put(&r, "proc/sys/kernel/tainted", b"4097\n"); // proprietary + out-of-tree only
        put(&r, "proc/sys/kernel/kexec_load_disabled", b"1\n");
        put(&r, "proc/sys/kernel/yama/ptrace_scope", b"2\n");
        let m = collect(&r);
        for (k, s) in &m {
            assert_eq!(s.secure, Some(true), "{k}: {s:?}");
        }
        assert_eq!(m["kernel_lockdown"].value, "integrity");
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn weakened_host() {
        let r = tree();
        put(&r, SECURE_BOOT_VAR, &[6, 0, 0, 0, 0]);
        put(
            &r,
            "sys/kernel/security/lockdown",
            b"[none] integrity confidentiality\n",
        );
        put(&r, "sys/module/module/parameters/sig_enforce", b"N\n");
        put(
            &r,
            "proc/sys/kernel/tainted",
            format!("{}\n", 1u64 << 13).as_bytes(),
        );
        put(&r, "proc/sys/kernel/kexec_load_disabled", b"0\n");
        put(&r, "proc/sys/kernel/yama/ptrace_scope", b"0\n");
        let m = collect(&r);
        for (k, s) in &m {
            assert_eq!(s.secure, Some(false), "{k}: {s:?}");
        }
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn each_integrity_taint_bit_is_insecure_on_its_own_and_benign_bits_are_not() {
        // forced load (1), forced unload (3), unsigned module (13)
        for bit in [1u32, 3, 13] {
            let r = tree();
            put(
                &r,
                "proc/sys/kernel/tainted",
                format!("{}\n", 1u64 << bit).as_bytes(),
            );
            assert_eq!(
                collect(&r)["kernel_tainted"].secure,
                Some(false),
                "bit {bit}"
            );
            let _ = std::fs::remove_dir_all(&r);
        }
        // proprietary (0), out-of-specification SMP (2), out-of-tree (12)
        for bit in [0u32, 2, 12] {
            let r = tree();
            put(
                &r,
                "proc/sys/kernel/tainted",
                format!("{}\n", 1u64 << bit).as_bytes(),
            );
            assert_eq!(
                collect(&r)["kernel_tainted"].secure,
                Some(true),
                "bit {bit}"
            );
            let _ = std::fs::remove_dir_all(&r);
        }
    }

    #[test]
    fn missing_files_are_unknown_not_insecure() {
        let r = tree();
        let m = collect(&r);
        assert!(m.values().all(|s| s.secure.is_none()));
        assert_eq!(m["secure_boot"].value, "not_uefi");
        // efi dir present but var unreadable
        std::fs::create_dir_all(r.join("sys/firmware/efi")).unwrap();
        assert_eq!(collect(&r)["secure_boot"].value, "unreadable");
        let _ = std::fs::remove_dir_all(&r);
    }
}
