//! Minimal PE reader and the code-comparison maths behind the Windows
//! self-check (portable so it is unit-tested on Linux against synthetic PEs).
//!
//! # Method: in-memory `.text` versus the on-disk file
//!
//! The loader maps a DLL at `base` and, when `base != ImageBase`, adds
//! `delta = base - ImageBase` to every base-relocation target. So the bytes
//! the process *should* hold are the file's `.text` bytes with the relocations
//! applied: [`expected_text`] does exactly that (`DIR64` adds the 64-bit delta,
//! `HIGHLOW` the low 32 bits). Anything else is compared bit for bit, so a
//! patched prologue or an overwritten function is visible, and an attacker
//! cannot hide changes in "relocation-like" bytes (they must equal the
//! relocated value). Relocation types this reader does not understand are
//! excluded from the comparison ([`TextImage::ignore`]) rather than guessed.
//!
//! The expected text is reduced to one SHA-256 per 4 KiB page ([`page_digests`])
//! so the long-lived cache is ~1 % of the code size and the 30 s comparison
//! hashes memory chunk-wise without a second copy of the code.
//!
//! Known limit: Windows can legitimately rewrite `.text` of `ntdll`/`kernelbase`
//! at load time (import-optimisation dynamic relocations, hot patches). The
//! caller therefore treats page differences as a *change since the first scan*,
//! while the first bytes of critical functions are always compared to the file.

use sha2::{Digest, Sha256};

pub const PAGE: usize = 4096;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_CNT_CODE: u32 = 0x0000_0020;

#[derive(Debug, PartialEq, Eq)]
pub enum PeError {
    Truncated,
    BadMagic,
    Unsupported(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeInfo {
    pub image_base: u64,
    pub size_of_image: u32,
    pub sections: Vec<Section>,
    /// (rva, size) of the export and base-relocation data directories.
    pub export_dir: (u32, u32),
    pub reloc_dir: (u32, u32),
}

fn u16_at(b: &[u8], o: usize) -> Result<u16, PeError> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(PeError::Truncated)
}
fn u32_at(b: &[u8], o: usize) -> Result<u32, PeError> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(PeError::Truncated)
}
fn u64_at(b: &[u8], o: usize) -> Result<u64, PeError> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes(s.try_into().expect("8 bytes")))
        .ok_or(PeError::Truncated)
}

/// Parse the headers of a 64-bit PE (PE32+) image.
pub fn parse(b: &[u8]) -> Result<PeInfo, PeError> {
    if b.get(0..2) != Some(b"MZ") {
        return Err(PeError::BadMagic);
    }
    let pe = u32_at(b, 0x3c)? as usize;
    if b.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err(PeError::BadMagic);
    }
    let coff = pe + 4;
    let n_sections = u16_at(b, coff + 2)? as usize;
    let opt_size = u16_at(b, coff + 16)? as usize;
    let opt = coff + 20;
    if u16_at(b, opt)? != 0x20b {
        return Err(PeError::Unsupported("not PE32+"));
    }
    if n_sections > 96 {
        return Err(PeError::Unsupported("too many sections"));
    }
    let image_base = u64_at(b, opt + 24)?;
    let size_of_image = u32_at(b, opt + 56)?;
    let dirs = opt + 112;
    let export_dir = (u32_at(b, dirs)?, u32_at(b, dirs + 4)?);
    let reloc_dir = (u32_at(b, dirs + 5 * 8)?, u32_at(b, dirs + 5 * 8 + 4)?);
    let mut sections = Vec::with_capacity(n_sections);
    let table = opt + opt_size;
    for i in 0..n_sections {
        let s = table + i * 40;
        let raw = b.get(s..s + 8).ok_or(PeError::Truncated)?;
        let end = raw.iter().position(|&c| c == 0).unwrap_or(8);
        sections.push(Section {
            name: String::from_utf8_lossy(&raw[..end]).into_owned(),
            virtual_size: u32_at(b, s + 8)?,
            virtual_address: u32_at(b, s + 12)?,
            raw_size: u32_at(b, s + 16)?,
            raw_ptr: u32_at(b, s + 20)?,
            characteristics: u32_at(b, s + 36)?,
        });
    }
    Ok(PeInfo {
        image_base,
        size_of_image,
        sections,
        export_dir,
        reloc_dir,
    })
}

impl PeInfo {
    /// The main code section: `.text`, else the first executable one.
    pub fn text(&self) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| s.name == ".text")
            .or_else(|| {
                self.sections
                    .iter()
                    .find(|s| s.characteristics & (SCN_MEM_EXECUTE | SCN_CNT_CODE) != 0)
            })
    }

    /// File offset of an RVA inside a section's raw data.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        self.sections.iter().find_map(|s| {
            let size = s.virtual_size.max(s.raw_size);
            (rva >= s.virtual_address && rva - s.virtual_address < size.min(s.raw_size))
                .then(|| (s.raw_ptr + (rva - s.virtual_address)) as usize)
        })
    }
}

/// RVA of a named, non-forwarded export.
pub fn export_rva(b: &[u8], info: &PeInfo, name: &str) -> Option<u32> {
    let (dir_rva, dir_size) = info.export_dir;
    if dir_rva == 0 {
        return None;
    }
    let dir = info.rva_to_offset(dir_rva)?;
    let n_names = u32_at(b, dir + 24).ok()? as usize;
    let funcs = info.rva_to_offset(u32_at(b, dir + 28).ok()?)?;
    let names = info.rva_to_offset(u32_at(b, dir + 32).ok()?)?;
    let ords = info.rva_to_offset(u32_at(b, dir + 36).ok()?)?;
    for i in 0..n_names.min(65_536) {
        let name_off = info.rva_to_offset(u32_at(b, names + i * 4).ok()?)?;
        let tail = b.get(name_off..)?;
        if tail.starts_with(name.as_bytes()) && tail.get(name.len()) == Some(&0) {
            let ord = u16_at(b, ords + i * 2).ok()? as usize;
            let rva = u32_at(b, funcs + ord * 4).ok()?;
            // A function RVA inside the export directory is a forwarder string.
            if rva >= dir_rva && rva < dir_rva.saturating_add(dir_size) {
                return None;
            }
            return Some(rva);
        }
    }
    None
}

/// One base-relocation target inside the code section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reloc {
    /// Offset from the start of the code section.
    pub offset: usize,
    pub kind: u8,
}

/// Base relocations whose target starts inside `[text_rva, text_rva + len)`.
pub fn relocations_in(b: &[u8], info: &PeInfo, text_rva: u32, len: usize) -> Vec<Reloc> {
    let mut out = Vec::new();
    let (rva, size) = info.reloc_dir;
    let Some(start) = (rva != 0).then(|| info.rva_to_offset(rva)).flatten() else {
        return out;
    };
    let end = (start + size as usize).min(b.len());
    let mut p = start;
    while p + 8 <= end {
        let (Ok(page), Ok(block)) = (u32_at(b, p), u32_at(b, p + 4)) else {
            break;
        };
        let block = block as usize;
        if block < 8 || p + block > end {
            break;
        }
        for e in (p + 8..p + block).step_by(2) {
            let Ok(entry) = u16_at(b, e) else { break };
            let kind = (entry >> 12) as u8;
            if kind == 0 {
                continue;
            }
            let target = page as usize + (entry & 0x0fff) as usize;
            if target >= text_rva as usize && target < text_rva as usize + len {
                out.push(Reloc {
                    offset: target - text_rva as usize,
                    kind,
                });
            }
        }
        p += block;
    }
    out
}

/// The code section as the loader should have left it in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextImage {
    pub bytes: Vec<u8>,
    /// Ranges (offset, len) not comparable (unknown relocation types).
    pub ignore: Vec<(usize, usize)>,
}

// Budget the expanded image independently from the size of the file on disk.
// Unknown relocations are consulted for every page in subsequent scans.
const MAX_TEXT_BYTES: u32 = 32 * 1024 * 1024;
const MAX_RELOCATION_BYTES: u32 = 1024 * 1024;
const MAX_IGNORED_RELOCATIONS: usize = 256;

/// Section bytes from the file with the base relocations applied for a load
/// at `base`. `bytes` is zero-padded to the virtual size, like the mapping.
pub fn expected_text(
    file: &[u8],
    info: &PeInfo,
    section: &Section,
    base: u64,
) -> Option<TextImage> {
    if section.virtual_size > MAX_TEXT_BYTES || info.reloc_dir.1 > MAX_RELOCATION_BYTES {
        crate::telemetry::metrics::metrics().state_capacity_dropped(1);
        return None;
    }
    let raw_len = section.raw_size.min(section.virtual_size) as usize;
    let raw = file.get(section.raw_ptr as usize..section.raw_ptr as usize + raw_len)?;
    let mut bytes = raw.to_vec();
    bytes.resize(section.virtual_size as usize, 0);
    let delta = base.wrapping_sub(info.image_base);
    let mut ignore = Vec::new();
    for r in relocations_in(file, info, section.virtual_address, bytes.len()) {
        match r.kind {
            10 => {
                if let Some(slot) = bytes.get_mut(r.offset..r.offset + 8) {
                    let v = u64::from_le_bytes(slot.try_into().expect("8 bytes"));
                    slot.copy_from_slice(&v.wrapping_add(delta).to_le_bytes());
                }
            }
            3 => {
                if let Some(slot) = bytes.get_mut(r.offset..r.offset + 4) {
                    let v = u32::from_le_bytes(slot.try_into().expect("4 bytes"));
                    slot.copy_from_slice(&v.wrapping_add(delta as u32).to_le_bytes());
                }
            }
            _ if ignore.len() < MAX_IGNORED_RELOCATIONS => ignore.push((r.offset, 8)),
            _ => {
                crate::telemetry::metrics::metrics().state_capacity_dropped(1);
                return None;
            }
        }
    }
    Some(TextImage { bytes, ignore })
}

fn zero_ignored(page: &mut [u8], page_start: usize, ignore: &[(usize, usize)]) {
    for &(o, l) in ignore {
        let (s, e) = (o.max(page_start), (o + l).min(page_start + page.len()));
        if s < e {
            page[s - page_start..e - page_start].fill(0);
        }
    }
}

/// SHA-256 of the 4 KiB page starting at `page_start` (`ignore` ranges zeroed).
pub fn page_digest(page: &[u8], page_start: usize, ignore: &[(usize, usize)]) -> [u8; 32] {
    if ignore.is_empty() {
        return Sha256::digest(page).into();
    }
    let mut copy = page.to_vec();
    zero_ignored(&mut copy, page_start, ignore);
    Sha256::digest(&copy).into()
}

pub fn page_digests(text: &TextImage) -> Vec<[u8; 32]> {
    text.bytes
        .chunks(PAGE)
        .enumerate()
        .map(|(i, c)| page_digest(c, i * PAGE, &text.ignore))
        .collect()
}

/// Indices of pages whose digest differs.
pub fn changed_pages(expected: &[[u8; 32]], actual: &[[u8; 32]]) -> Vec<usize> {
    let n = expected.len().max(actual.len());
    (0..n)
        .filter(|&i| expected.get(i) != actual.get(i))
        .collect()
}

/// First differing byte offsets inside one page, merged into ranges (for the
/// evidence of a finding).
pub fn byte_diff(expected: &[u8], actual: &[u8], max_ranges: usize) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (i, (a, b)) in expected.iter().zip(actual).enumerate() {
        if a != b {
            if let Some((s, l)) = out.last_mut() {
                if *s + *l == i {
                    *l += 1;
                    continue;
                }
            }
            if out.len() >= max_ranges {
                break;
            }
            out.push((i, 1));
        }
    }
    out
}

/// Bytes of the expected image at an RVA (for critical-function prologues).
pub fn expected_at(text: &TextImage, section: &Section, rva: u32, len: usize) -> Option<Vec<u8>> {
    let off = rva.checked_sub(section.virtual_address)? as usize;
    text.bytes.get(off..off + len).map(<[u8]>::to_vec)
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! A synthetic PE32+ with one `.text` section, relocations and exports.

    pub const IMAGE_BASE: u64 = 0x1_8000_0000;
    pub const TEXT_RVA: u32 = 0x1000;
    pub const TEXT_LEN: usize = 0x2000;

    fn put(b: &mut [u8], o: usize, v: &[u8]) {
        b[o..o + v.len()].copy_from_slice(v);
    }

    /// File layout: headers 0x400, `.text` at 0x400 (0x2000), `.rdata` (exports)
    /// at 0x2400, `.reloc` at 0x2800.
    pub fn build(text: &[u8], relocs: &[(u32, u8)], exports: &[(&str, u32)]) -> Vec<u8> {
        assert!(text.len() <= TEXT_LEN);
        let mut f = vec![0u8; 0x2c00];
        put(&mut f, 0, b"MZ");
        put(&mut f, 0x3c, &0x80u32.to_le_bytes());
        put(&mut f, 0x80, b"PE\0\0");
        let coff = 0x84;
        put(&mut f, coff + 2, &3u16.to_le_bytes());
        put(&mut f, coff + 16, &240u16.to_le_bytes());
        let opt = coff + 20;
        put(&mut f, opt, &0x20bu16.to_le_bytes());
        put(&mut f, opt + 24, &IMAGE_BASE.to_le_bytes());
        put(&mut f, opt + 56, &0x6000u32.to_le_bytes());
        let dirs = opt + 112;
        put(&mut f, dirs, &0x3000u32.to_le_bytes());
        put(&mut f, dirs + 4, &0x200u32.to_le_bytes());
        put(&mut f, dirs + 40, &0x4000u32.to_le_bytes());
        put(&mut f, dirs + 44, &0x400u32.to_le_bytes());
        let table = opt + 240;
        let sec =
            |f: &mut [u8], i: usize, name: &[u8], vs: u32, va: u32, rs: u32, rp: u32, ch: u32| {
                let s = table + i * 40;
                put(f, s, name);
                put(f, s + 8, &vs.to_le_bytes());
                put(f, s + 12, &va.to_le_bytes());
                put(f, s + 16, &rs.to_le_bytes());
                put(f, s + 20, &rp.to_le_bytes());
                put(f, s + 36, &ch.to_le_bytes());
            };
        sec(
            &mut f,
            0,
            b".text",
            TEXT_LEN as u32,
            TEXT_RVA,
            0x2000,
            0x400,
            0x6000_0020,
        );
        sec(
            &mut f,
            1,
            b".rdata",
            0x1000,
            0x3000,
            0x400,
            0x2400,
            0x4000_0040,
        );
        sec(
            &mut f,
            2,
            b".reloc",
            0x1000,
            0x4000,
            0x400,
            0x2800,
            0x4200_0040,
        );
        put(&mut f, 0x400, text);
        // Export directory at RVA 0x3000 (file 0x2400).
        let dir = 0x2400;
        let n = exports.len() as u32;
        put(&mut f, dir + 24, &n.to_le_bytes());
        put(&mut f, dir + 28, &0x3100u32.to_le_bytes());
        put(&mut f, dir + 32, &0x3200u32.to_le_bytes());
        put(&mut f, dir + 36, &0x3300u32.to_le_bytes());
        let mut name_pool = 0x3380u32;
        for (i, (name, rva)) in exports.iter().enumerate() {
            put(&mut f, 0x2400 + 0x100 + i * 4, &rva.to_le_bytes());
            put(&mut f, 0x2400 + 0x200 + i * 4, &name_pool.to_le_bytes());
            put(&mut f, 0x2400 + 0x300 + i * 2, &(i as u16).to_le_bytes());
            let off = 0x2400 + (name_pool - 0x3000) as usize;
            put(&mut f, off, name.as_bytes());
            name_pool += name.len() as u32 + 1;
        }
        // One relocation block per call: page 0x1000 with the given entries.
        let mut p = 0x2800;
        put(&mut f, p, &TEXT_RVA.to_le_bytes());
        let size = 8 + relocs.len() as u32 * 2;
        put(&mut f, p + 4, &size.to_le_bytes());
        p += 8;
        for (off, kind) in relocs {
            let e = ((*kind as u16) << 12) | (*off as u16 & 0x0fff);
            put(&mut f, p, &e.to_le_bytes());
            p += 2;
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    fn sample() -> Vec<u8> {
        let mut text = vec![0x90u8; TEXT_LEN];
        // A DIR64 pointer at 0x10 holding an absolute address into the image.
        text[0x10..0x18].copy_from_slice(&(IMAGE_BASE + 0x1234).to_le_bytes());
        // A HIGHLOW at 0x20.
        text[0x20..0x24].copy_from_slice(&0x1000_0000u32.to_le_bytes());
        text[0x100..0x104].copy_from_slice(&[0x4c, 0x8b, 0xd1, 0xb8]);
        build(
            &text,
            &[(0x10, 10), (0x20, 3), (0, 0)],
            &[
                ("EtwEventWrite", 0x1100),
                ("Other", 0x1200),
                ("Fwd", 0x3010),
            ],
        )
    }

    #[test]
    fn parses_headers_sections_and_directories() {
        let file = sample();
        let info = parse(&file).unwrap();
        assert_eq!(info.image_base, IMAGE_BASE);
        let text = info.text().unwrap();
        assert_eq!((text.virtual_address, text.raw_ptr), (TEXT_RVA, 0x400));
        assert_eq!(info.sections.len(), 3);
    }

    #[test]
    fn rejects_garbage_and_truncated_input() {
        assert_eq!(parse(b"not a pe"), Err(PeError::BadMagic));
        let file = sample();
        assert!(parse(&file[..0x90]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn finds_exports_and_skips_forwarders() {
        let file = sample();
        let info = parse(&file).unwrap();
        assert_eq!(export_rva(&file, &info, "EtwEventWrite"), Some(0x1100));
        assert_eq!(export_rva(&file, &info, "Other"), Some(0x1200));
        assert_eq!(export_rva(&file, &info, "Fwd"), None, "forwarder");
        assert_eq!(export_rva(&file, &info, "Missing"), None);
    }

    #[test]
    fn reconstruction_rejects_sizes_beyond_its_transient_memory_budget() {
        let file = sample();
        let mut info = parse(&file).unwrap();
        let mut section = info.text().unwrap().clone();
        section.virtual_size = MAX_TEXT_BYTES + 1;
        assert!(expected_text(&file, &info, &section, IMAGE_BASE).is_none());
        section = info.text().unwrap().clone();
        info.reloc_dir.1 = MAX_RELOCATION_BYTES + 1;
        assert!(expected_text(&file, &info, &section, IMAGE_BASE).is_none());
    }

    #[test]
    fn relocations_are_applied_for_a_load_at_another_base() {
        let file = sample();
        let info = parse(&file).unwrap();
        let sec = info.text().unwrap().clone();
        let base = IMAGE_BASE + 0x40_0000;
        let t = expected_text(&file, &info, &sec, base).unwrap();
        assert_eq!(
            u64::from_le_bytes(t.bytes[0x10..0x18].try_into().unwrap()),
            base + 0x1234
        );
        assert_eq!(
            u32::from_le_bytes(t.bytes[0x20..0x24].try_into().unwrap()),
            0x1000_0000u32.wrapping_add(0x40_0000)
        );
        assert!(t.ignore.is_empty());
        // At the preferred base nothing moves.
        let same = expected_text(&file, &info, &sec, IMAGE_BASE).unwrap();
        assert_eq!(&same.bytes[..], &file[0x400..0x400 + TEXT_LEN]);
    }

    #[test]
    fn unknown_relocation_kinds_are_excluded_not_guessed() {
        let mut text = vec![0u8; TEXT_LEN];
        text[0x40] = 0x11;
        let file = build(&text, &[(0x40, 5)], &[]);
        let info = parse(&file).unwrap();
        let sec = info.text().unwrap().clone();
        let t = expected_text(&file, &info, &sec, IMAGE_BASE).unwrap();
        assert_eq!(t.ignore, vec![(0x40, 8)]);
        let mut mem = t.bytes.clone();
        mem[0x44] = 0xee; // inside the ignored field: not a difference
        let a = page_digests(&t);
        let b = page_digests(&TextImage {
            bytes: mem,
            ignore: t.ignore.clone(),
        });
        assert!(changed_pages(&a, &b).is_empty());
    }

    #[test]
    fn a_clean_relocated_image_matches_and_a_patch_is_found() {
        let file = sample();
        let info = parse(&file).unwrap();
        let sec = info.text().unwrap().clone();
        let base = IMAGE_BASE + 0x10_0000;
        let expected = expected_text(&file, &info, &sec, base).unwrap();
        let expected_digests = page_digests(&expected);
        let mut memory = expected.clone();
        assert!(changed_pages(&expected_digests, &page_digests(&memory)).is_empty());
        // The classic EtwEventWrite patch: first byte becomes `ret`.
        memory.bytes[0x100] = 0xc3;
        let changed = changed_pages(&expected_digests, &page_digests(&memory));
        assert_eq!(changed, vec![0]);
        let ranges = byte_diff(&expected.bytes[..PAGE], &memory.bytes[..PAGE], 8);
        assert_eq!(ranges, vec![(0x100, 1)]);
        assert_eq!(
            expected_at(&expected, &sec, 0x1100, 4).unwrap(),
            vec![0x4c, 0x8b, 0xd1, 0xb8]
        );
    }

    #[test]
    fn a_pointer_without_the_relocation_delta_is_a_difference() {
        // An image whose memory holds the *unrelocated* value although it was
        // loaded elsewhere has been rewritten.
        let file = sample();
        let info = parse(&file).unwrap();
        let sec = info.text().unwrap().clone();
        let base = IMAGE_BASE + 0x10_0000;
        let expected = expected_text(&file, &info, &sec, base).unwrap();
        let mut memory = expected.clone();
        memory.bytes[0x10..0x18].copy_from_slice(&(IMAGE_BASE + 0x1234).to_le_bytes());
        assert_eq!(
            changed_pages(&page_digests(&expected), &page_digests(&memory)),
            vec![0]
        );
    }

    #[test]
    fn byte_diff_merges_adjacent_bytes_and_is_bounded() {
        let a = vec![0u8; 64];
        let mut b = a.clone();
        b[3] = 1;
        b[4] = 1;
        b[10] = 1;
        b[20] = 1;
        assert_eq!(byte_diff(&a, &b, 8), vec![(3, 2), (10, 1), (20, 1)]);
        assert_eq!(byte_diff(&a, &b, 2), vec![(3, 2), (10, 1)]);
    }
}
