//! Resolve the small inode walk from the running kernel's BTF, never guessed offsets.
//! Aya 0.13 does not expose struct members; this bounded reader handles BTF v1 records.
use std::collections::HashMap;

const MAX_BTF: usize = 16 * 1024 * 1024;
const FIELDS: [(&str, &str, usize); 6] = [
    ("path", "dentry", 8),
    ("dentry", "d_inode", 8),
    ("inode", "i_ino", 8),
    ("inode", "i_sb", 8),
    ("super_block", "s_dev", 4),
    ("file", "f_flags", 4),
];

pub fn running_offsets() -> Option<[u32; 6]> {
    use std::io::Read;
    let file = std::fs::File::open("/sys/kernel/btf/vmlinux").ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_BTF as u64 + 1).read_to_end(&mut bytes).ok()?;
    resolve(&bytes).ok()
}

pub fn inode_key(device: u64, inode: u64) -> [u64; 2] {
    // Linux kernel dev_t (12:20) differs from the userspace stat encoding.
    [
        ((libc::major(device) as u64) << 20) | libc::minor(device) as u64,
        inode,
    ]
}

fn word(bytes: &[u8], at: usize) -> Result<u32, &'static str> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at.checked_add(4).ok_or("offset overflow")?)
            .ok_or("truncated BTF")?
            .try_into()
            .map_err(|_| "word size")?,
    ))
}

pub fn resolve(bytes: &[u8]) -> Result<[u32; 6], &'static str> {
    if bytes.len() > MAX_BTF || bytes.get(..4) != Some(&[0x9f, 0xeb, 1, 0]) {
        return Err("unsupported BTF header");
    }
    let header = word(bytes, 4)? as usize;
    if header < 24 || header > bytes.len() {
        return Err("invalid header size");
    }
    let type_start = header
        .checked_add(word(bytes, 8)? as usize)
        .ok_or("type offset")?;
    let type_end = type_start
        .checked_add(word(bytes, 12)? as usize)
        .ok_or("type length")?;
    let string_start = header
        .checked_add(word(bytes, 16)? as usize)
        .ok_or("string offset")?;
    let string_end = string_start
        .checked_add(word(bytes, 20)? as usize)
        .ok_or("string length")?;
    let types = bytes.get(type_start..type_end).ok_or("type section")?;
    let strings = bytes
        .get(string_start..string_end)
        .ok_or("string section")?;
    if type_end > string_start {
        return Err("overlapping sections");
    }
    let name = |offset: u32| -> Result<&str, &'static str> {
        let tail = strings.get(offset as usize..).ok_or("string index")?;
        let end = tail
            .iter()
            .take(257)
            .position(|b| *b == 0)
            .ok_or("unterminated name")?;
        std::str::from_utf8(&tail[..end]).map_err(|_| "invalid name")
    };
    let mut records = Vec::new();
    let mut found: HashMap<usize, (u32, u32)> = HashMap::new();
    let mut at = 0;
    while at < types.len() {
        if records.len() >= 1_000_000 {
            return Err("too many types");
        }
        let named = word(types, at)?;
        let info = word(types, at + 4)?;
        let target = word(types, at + 8)?;
        let kind = (info >> 24) & 31;
        let count = (info & 65535) as usize;
        let extra = match kind {
            1 | 14 | 17 => 4,
            3 => 12,
            4 | 5 | 15 | 19 => count.checked_mul(12).ok_or("member length")?,
            6 | 13 => count.checked_mul(8).ok_or("member length")?,
            2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
            _ => return Err("unknown BTF kind"),
        };
        let end = at
            .checked_add(12)
            .and_then(|n| n.checked_add(extra))
            .ok_or("record length")?;
        if end > types.len() {
            return Err("truncated record");
        }
        records.push((kind, target));
        if kind == 4 {
            let structure = name(named)?;
            for (index, (_, field, width)) in FIELDS
                .iter()
                .enumerate()
                .filter(|(_, (expected, _, _))| *expected == structure)
            {
                for member in 0..count {
                    let start = at + 12 + member * 12;
                    if name(word(types, start)?)? != *field {
                        continue;
                    }
                    let bits = word(types, start + 8)?;
                    if (info >> 31 != 0 && bits >> 24 != 0) || !bits.is_multiple_of(8) {
                        return Err("bitfield layout");
                    }
                    let offset = bits / 8;
                    if offset > 4096
                        || offset as usize + width > target as usize
                        || !(offset as usize).is_multiple_of(*width)
                    {
                        return Err("invalid field bounds");
                    }
                    if found
                        .insert(index, (offset, word(types, start + 4)?))
                        .is_some()
                    {
                        return Err("ambiguous structure");
                    }
                }
            }
        }
        at = end;
    }
    let mut offsets = [0; 6];
    for (index, (_, _, width)) in FIELDS.iter().enumerate() {
        let (offset, mut id) = *found.get(&index).ok_or("missing layout field")?;
        let mut validated = false;
        for _ in 0..16 {
            let (kind, size) = *records
                .get(id.checked_sub(1).ok_or("void field")? as usize)
                .ok_or("type reference")?;
            match kind {
                8 | 9 | 10 | 11 | 18 => id = size,
                2 if *width == 8 && index < 4 && index != 2 => {
                    validated = true;
                    break;
                }
                1 if size == *width as u32 && (index == 2 || index >= 4) => {
                    validated = true;
                    break;
                }
                _ => break,
            }
        }
        if !validated {
            return Err("unexpected field type");
        }
        offsets[index] = offset;
    }
    Ok(offsets)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(ino: u32) -> Vec<u8> {
        let mut strings = vec![0];
        let mut types = Vec::new();
        let mut add = |name: &str, kind: u32, size: u32, members: Vec<(&str, u32, u32)>| {
            let named = strings.len() as u32;
            strings.extend(name.bytes());
            strings.push(0);
            for value in [named, (kind << 24) | members.len() as u32, size] {
                types.extend(value.to_le_bytes());
            }
            if kind == 1 {
                types.extend(0u32.to_le_bytes());
            }
            for (field, id, offset) in members {
                let n = strings.len() as u32;
                strings.extend(field.bytes());
                strings.push(0);
                for value in [n, id, offset * 8] {
                    types.extend(value.to_le_bytes());
                }
            }
        };
        add("u64", 1, 8, vec![]);
        add("u32", 1, 4, vec![]);
        add("", 2, 0, vec![]);
        add("path", 4, 16, vec![("dentry", 3, 8)]);
        add("dentry", 4, 192, vec![("d_inode", 3, 48)]);
        add("inode", 4, 640, vec![("i_ino", 1, ino), ("i_sb", 3, 56)]);
        add("super_block", 4, 1600, vec![("s_dev", 2, 16)]);
        add("file", 4, 256, vec![("f_flags", 2, 64)]);
        let mut b = vec![0x9f, 0xeb, 1, 0];
        for value in [
            24u32,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            b.extend(value.to_le_bytes());
        }
        b.extend(types);
        b.extend(strings);
        b
    }
    #[test]
    fn kernel_inode_layout_is_resolved_instead_of_assumed() {
        assert_eq!(resolve(&fixture(80)).unwrap(), [8, 48, 80, 56, 16, 64]);
        assert_eq!(resolve(&fixture(64)).unwrap()[2], 64);
    }
    #[test]
    fn corrupt_unaligned_or_missing_btf_never_claims_coverage() {
        assert!(resolve(&fixture(81)).is_err());
        assert!(resolve(&[]).is_err());
        let mut b = fixture(80);
        b.truncate(b.len() - 3);
        assert!(resolve(&b).is_err());
    }
    #[test]
    fn different_filesystems_cannot_share_an_inode_key() {
        assert_ne!(
            inode_key(libc::makedev(8, 1), 10),
            inode_key(libc::makedev(8, 2), 10)
        );
        assert_eq!(inode_key(libc::makedev(8, 1), 10), [(8 << 20) | 1, 10]);
    }
    #[test]
    fn current_kernel_btf_resolves_when_present() {
        if std::path::Path::new("/sys/kernel/btf/vmlinux").exists() {
            assert!(running_offsets().is_some());
        }
    }
}
