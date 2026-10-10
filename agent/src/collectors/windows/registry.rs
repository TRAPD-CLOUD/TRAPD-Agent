//! Bounded registry reads shared by MSI configuration and Windows inventory.
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegGetValueW, RegOpenKeyExW, HKEY,
    HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, RRF_NOEXPAND, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ,
    RRF_RT_REG_SZ,
};

/// Which hive a read targets.
#[derive(Clone, Copy)]
pub enum Hive {
    LocalMachine,
    #[cfg(test)]
    CurrentUser,
    /// `HKEY_USERS`: per-user keys under `<SID>\…`, present while the
    /// user's profile hive is loaded (logged on, or a service holds it).
    Users,
}

impl Hive {
    fn key(self) -> HKEY {
        match self {
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
            #[cfg(test)]
            Hive::CurrentUser => windows_sys::Win32::System::Registry::HKEY_CURRENT_USER,
            Hive::Users => HKEY_USERS,
        }
    }
}

/// Expand-suppressing flag for [`string_in`].
pub const NO_EXPAND: u32 = RRF_NOEXPAND;

pub fn dword(path: &str, name: &str, view: u32) -> Option<u32> {
    dword_in(Hive::LocalMachine, path, name, view)
}

pub fn dword_in(hive: Hive, path: &str, name: &str, view: u32) -> Option<u32> {
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut value = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: terminated strings; the out-buffer is a u32 and `size` its byte length.
    let status = unsafe {
        RegGetValueW(
            hive.key(),
            path.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD | view,
            std::ptr::null_mut(),
            (&mut value as *mut u32).cast(),
            &mut size,
        )
    };
    (status == 0 && size == std::mem::size_of::<u32>() as u32).then_some(value)
}

pub fn string(path: &str, name: &str, view: u32) -> Option<String> {
    string_in(Hive::LocalMachine, path, name, view)
}

/// A string value from `hive`. `REG_EXPAND_SZ` values are returned
/// unexpanded when `view` contains `RRF_NOEXPAND` (needed for per-user
/// values that reference *that* user's `%USERPROFILE%`, not the service's).
pub fn string_in(hive: Hive, path: &str, name: &str, view: u32) -> Option<String> {
    let root = hive.key();
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut size = 0u32;
    // SAFETY: terminated strings and valid out-parameters; null data queries size.
    let status = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | view,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if status != 0 || size == 0 || size > 65536 {
        return None;
    }
    let mut data = vec![0u16; (size as usize).div_ceil(2)];
    // SAFETY: buffer capacity is the byte count returned by the first call.
    let status = unsafe {
        RegGetValueW(
            root,
            path.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | view,
            std::ptr::null_mut(),
            data.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != 0 {
        return None;
    }
    data.truncate(size as usize / 2);
    if data.last() == Some(&0) {
        data.pop();
    }
    String::from_utf16(&data).ok()
}

pub fn subkeys(path: &str, view: u32) -> Vec<String> {
    subkeys_in(Hive::LocalMachine, path, view)
}

pub fn subkeys_in(hive: Hive, path: &str, view: u32) -> Vec<String> {
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut key = std::ptr::null_mut();
    let mut names = Vec::new();
    // SAFETY: key is a valid out-pointer and the returned handle is always closed.
    unsafe {
        if RegOpenKeyExW(hive.key(), path.as_ptr(), 0, KEY_READ | view, &mut key) != 0 {
            return names;
        }
        for index in 0..8192 {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            let status = RegEnumKeyExW(
                key,
                index,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if status == 259 {
                break;
            }
            if status != 0 {
                tracing::warn!(status, "registry inventory enumeration incomplete");
                break;
            }
            names.push(String::from_utf16_lossy(&name[..len as usize]));
        }
        RegCloseKey(key);
    }
    names
}

/// Render one raw registry value for telemetry. Text types are decoded
/// (`REG_MULTI_SZ` joined with `|`), numbers printed, anything else
/// hex-encoded. The caller truncates.
fn render_value(kind: u32, data: &[u8]) -> String {
    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_DWORD: u32 = 4;
    const REG_MULTI_SZ: u32 = 7;
    const REG_QWORD: u32 = 11;
    let wide = |bytes: &[u8]| -> Vec<u16> {
        bytes
            .chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect()
    };
    match kind {
        REG_SZ | REG_EXPAND_SZ => {
            let w = wide(data);
            let end = w.iter().position(|c| *c == 0).unwrap_or(w.len());
            String::from_utf16_lossy(&w[..end])
        }
        REG_MULTI_SZ => wide(data)
            .split(|c| *c == 0)
            .filter(|part| !part.is_empty())
            .map(String::from_utf16_lossy)
            .collect::<Vec<_>>()
            .join("|"),
        REG_DWORD if data.len() == 4 => {
            u32::from_le_bytes([data[0], data[1], data[2], data[3]]).to_string()
        }
        REG_QWORD if data.len() == 8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(data);
            u64::from_le_bytes(b).to_string()
        }
        _ => data.iter().take(64).map(|b| format!("{b:02x}")).collect(),
    }
}

/// All values of a key as `(name, rendered data)`; the unnamed value has the
/// name `""`. Bounded: at most 1024 values, 256 KiB of data each (larger values
/// are reported as `<value too large>`). Missing or unreadable keys yield an
/// empty list.
pub fn values_in(hive: Hive, path: &str, view: u32) -> Vec<(String, String)> {
    const MAX_VALUES: u32 = 1024;
    const MORE_DATA: u32 = 234;
    const MAX_DATA: usize = 256 * 1024;
    let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut key = std::ptr::null_mut();
    let mut out = Vec::new();
    // SAFETY: key is a valid out-pointer and the handle is always closed; every
    // buffer length passed to RegEnumValueW matches its allocation.
    unsafe {
        if RegOpenKeyExW(hive.key(), path.as_ptr(), 0, KEY_READ | view, &mut key) != 0 {
            return out;
        }
        for index in 0..MAX_VALUES {
            let mut name = vec![0u16; 16384]; // names are at most 16383 chars
            let mut name_len: u32;
            let mut capacity = 4 * 1024usize;
            let mut kind = 0u32;
            let rendered = loop {
                let mut data = vec![0u8; capacity];
                let mut data_len = capacity as u32;
                name_len = name.len() as u32;
                let status = RegEnumValueW(
                    key,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut data_len,
                );
                if status == 0 {
                    break Some(render_value(
                        kind,
                        &data[..(data_len as usize).min(capacity)],
                    ));
                }
                if status != MORE_DATA {
                    break None;
                }
                if (data_len as usize) > capacity && (data_len as usize) <= MAX_DATA {
                    capacity = data_len as usize;
                    continue;
                }
                // Too large to inspect: fetch the name alone so the value stays
                // visible (an oversized decoy must not hide the values after it).
                name_len = name.len() as u32;
                let status = RegEnumValueW(
                    key,
                    index,
                    name.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                break (status == 0).then(|| "<value too large>".to_string());
            };
            let Some(value) = rendered else { break };
            out.push((String::from_utf16_lossy(&name[..name_len as usize]), value));
        }
        RegCloseKey(key);
    }
    out
}

#[cfg(test)]
mod render_tests {
    use super::render_value;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn renders_text_numbers_and_binary() {
        assert_eq!(render_value(1, &utf16(r"C:.exe")), r"C:.exe");
        assert_eq!(render_value(4, &1u32.to_le_bytes()), "1");
        assert_eq!(render_value(3, &[0xde, 0xad]), "dead");
        let mut multi = utf16("a");
        multi.pop();
        multi.pop();
        multi.extend(utf16("b"));
        multi.extend([0, 0]);
        assert_eq!(render_value(7, &multi), "a|b");
    }
}
