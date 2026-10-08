//! Bounded registry reads shared by MSI configuration and Windows inventory.
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS,
    KEY_READ, RRF_NOEXPAND, RRF_RT_REG_DWORD, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ,
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
