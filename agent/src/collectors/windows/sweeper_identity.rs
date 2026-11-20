//! A service name is insufficient. Verify its live image and Authenticode locally.
use crate::detection::windows_decoy::{Accessor, WINDOWS_SWEEPERS};
use windows_sys::Win32::Security::WinTrust::*;

pub fn verified(a: &Accessor, observed: Option<u64>) -> bool {
    let name = a
        .process_name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if a.logon_type != Some(5) || !WINDOWS_SWEEPERS.contains(&name.as_str()) {
        return false;
    }
    let Some(observed) = observed else {
        return false;
    };
    let Some(start) = crate::telemetry::identity::process_start_time(a.pid) else {
        return false;
    };
    if start == 0 || observed < start {
        return false;
    }
    let Some(image) = crate::telemetry::identity::windows_process_image(a.pid) else {
        return false;
    };
    if !image.eq_ignore_ascii_case(&a.process_name) {
        return false;
    }
    // A signed tool copied and renamed in a user's writable directory is not a trusted service installation.
    let image_lc = image.replace('/', "\\").to_ascii_lowercase();
    let roots = [
        std::env::var("SystemRoot")
            .ok()
            .map(|p| format!("{p}\\System32\\")),
        std::env::var("ProgramFiles").ok().map(|p| format!("{p}\\")),
        std::env::var("ProgramFiles(x86)")
            .ok()
            .map(|p| format!("{p}\\")),
        std::env::var("ProgramData")
            .ok()
            .map(|p| format!("{p}\\Microsoft\\Windows Defender\\Platform\\")),
    ];
    if image_lc.split('\\').any(|p| p == "..")
        || !roots
            .into_iter()
            .flatten()
            .any(|r| image_lc.starts_with(&r.to_ascii_lowercase()))
    {
        return false;
    }
    let Some(protected) = protected_image(&image) else {
        return false;
    };
    use std::os::windows::io::AsRawHandle;
    let handle = protected.last().unwrap().as_raw_handle();
    let path: Vec<u16> = image.encode_utf16().chain(Some(0)).collect();
    // Windows components (Search, Defender platform files) are mostly
    // catalog-signed, not embedded-signed; accept either, as Windows does.
    let trusted = embedded_trusted(&path, handle) || catalog_trusted(&path, handle);
    trusted && crate::telemetry::identity::process_start_time(a.pid) == Some(start)
}

/// Embedded Authenticode signature of the locked image.
fn embedded_trusted(path: &[u16], handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    // SAFETY: structures and NUL-terminated path outlive the synchronous trust operation;
    // its state is closed on all return paths. No UI or external network request.
    unsafe {
        let mut file = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path.as_ptr(),
            hFile: handle,
            ..Default::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        verify(&mut data)
    }
}

/// Signature of the locked image through a system catalog: hash the open
/// handle (SHA-256), find the catalog that lists that hash, and verify the
/// member against it. Fails closed on every error.
fn catalog_trusted(path: &[u16], handle: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::Security::Cryptography::Catalog::*;
    use windows_sys::Win32::Security::Cryptography::BCRYPT_SHA256_ALGORITHM;
    // SAFETY: every out-pointer refers to a live local; the catalog admin and
    // catalog contexts are released on all paths; buffers outlive the calls.
    unsafe {
        let mut admin: isize = 0;
        if CryptCATAdminAcquireContext2(
            &mut admin,
            std::ptr::null(),
            BCRYPT_SHA256_ALGORITHM,
            std::ptr::null(),
            0,
        ) == 0
        {
            return false;
        }
        let mut hash = [0u8; 64];
        let mut len = hash.len() as u32;
        let mut trusted = false;
        if CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut len, hash.as_mut_ptr(), 0) != 0
            && (len as usize) <= hash.len()
        {
            let hash = &hash[..len as usize];
            let catalog = CryptCATAdminEnumCatalogFromHash(
                admin,
                hash.as_ptr(),
                len,
                0,
                std::ptr::null_mut(),
            );
            if catalog != 0 {
                let mut info = CATALOG_INFO {
                    cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
                    wszCatalogFile: [0; 260],
                };
                if CryptCATCatalogInfoFromContext(catalog, &mut info, 0) != 0 {
                    let tag: Vec<u16> = hash
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<String>()
                        .encode_utf16()
                        .chain(Some(0))
                        .collect();
                    let mut member = WINTRUST_CATALOG_INFO {
                        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                        pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
                        pcwszMemberTag: tag.as_ptr(),
                        pcwszMemberFilePath: path.as_ptr(),
                        hMemberFile: handle,
                        pbCalculatedFileHash: hash.as_ptr().cast_mut(),
                        cbCalculatedFileHash: len,
                        hCatAdmin: admin,
                        ..Default::default()
                    };
                    let mut data = WINTRUST_DATA {
                        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                        dwUIChoice: WTD_UI_NONE,
                        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
                        dwUnionChoice: WTD_CHOICE_CATALOG,
                        Anonymous: WINTRUST_DATA_0 {
                            pCatalog: &mut member,
                        },
                        dwStateAction: WTD_STATEACTION_VERIFY,
                        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
                        ..Default::default()
                    };
                    trusted = verify(&mut data);
                }
                CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
            }
        }
        CryptCATAdminReleaseContext(admin, 0);
        trusted
    }
}

/// Run one WinVerifyTrust verification and always close its state.
unsafe fn verify(data: &mut WINTRUST_DATA) -> bool {
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let rc = WinVerifyTrust(
        windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
        &mut action,
        (data as *mut WINTRUST_DATA).cast(),
    );
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    let _ = WinVerifyTrust(
        windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE,
        &mut action,
        (data as *mut WINTRUST_DATA).cast(),
    );
    rc == 0
}

// Fail closed for writable/custom ACLs. Trusted directory names alone are not a trust boundary.
fn protected_image(image: &str) -> Option<Vec<std::fs::File>> {
    use std::os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    };
    let mut locked = Vec::new();
    let chain: Vec<_> = std::path::Path::new(image).ancestors().collect();
    for (index, path) in chain.iter().rev().enumerate() {
        let directory = index + 1 < chain.len();
        if locked.len() >= 64 {
            return None;
        }
        let file = std::fs::OpenOptions::new()
            .access_mode(0x20000 | 0x80 | if !directory { 0x80000000 } else { 0 })
            .share_mode(1)
            .custom_flags(0x00200000 | if directory { 0x02000000 } else { 0 })
            .open(path)
            .ok()?;
        if file.metadata().ok()?.file_attributes() & 0x400 != 0
            || !protected_handle(file.as_raw_handle(), directory)
        {
            return None;
        }
        locked.push(file);
    }
    (!locked.is_empty()).then_some(locked)
}

fn protected_handle(handle: windows_sys::Win32::Foundation::HANDLE, directory: bool) -> bool {
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetAce, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PSID,
    };
    let write = 0x4000_0000 | 0x1000_0000 | 0x000d_0000 | if directory { 0x42 } else { 0x116 };
    unsafe fn privileged(sid: PSID) -> bool {
        let mut text = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut text) == 0 {
            return false;
        }
        let mut len = 0;
        while *text.add(len) != 0 && len < 256 {
            len += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        matches!(
            value.as_str(),
            "S-1-5-18"
                | "S-1-5-32-544"
                | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        )
    }
    unsafe {
        let mut owner: PSID = std::ptr::null_mut();
        let mut acl: *mut ACL = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let rc = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        let mut safe =
            rc == ERROR_SUCCESS && !acl.is_null() && !owner.is_null() && privileged(owner);
        if safe {
            for index in 0..(*acl).AceCount {
                let mut entry = std::ptr::null_mut();
                if GetAce(acl, index as u32, &mut entry) == 0 {
                    safe = false;
                    break;
                }
                let header = &*entry.cast::<ACE_HEADER>();
                if header.AceFlags & 0x08 != 0 {
                    continue;
                } // Inherit-only rules do not grant access to this object.
                match header.AceType {
                    0 => {
                        let ace = &*entry.cast::<ACCESS_ALLOWED_ACE>();
                        if ace.Mask & write != 0
                            && !privileged((&ace.SidStart as *const u32).cast_mut().cast())
                        {
                            safe = false;
                            break;
                        }
                    }
                    1 => {} // Deny ACEs only restrict access.
                    _ => {
                        safe = false;
                        break;
                    } // Complex conditional/object ACEs need explicit evaluation.
                }
            }
        }
        if !descriptor.is_null() {
            LocalFree(descriptor.cast());
        }
        safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "native trust-boundary acceptance; run elevated"]
    fn protected_file_in_a_writable_parent_is_rejected() {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows_sys::Win32::Security::{
            SetFileSecurityW, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        };
        let dir = std::env::temp_dir().join(format!("trapd-parent-acl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("searchindexer.exe");
        std::fs::write(&file, b"test").unwrap();
        unsafe {
            for (path, policy) in [
                (&file, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"),
                (&dir, "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x40;;;BU)"),
            ] {
                let sddl: Vec<u16> = policy.encode_utf16().chain(Some(0)).collect();
                let mut sd = std::ptr::null_mut();
                assert_ne!(
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        1,
                        &mut sd,
                        std::ptr::null_mut()
                    ),
                    0
                );
                let path: Vec<u16> = path
                    .to_string_lossy()
                    .encode_utf16()
                    .chain(Some(0))
                    .collect();
                assert_ne!(
                    SetFileSecurityW(
                        path.as_ptr(),
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        sd
                    ),
                    0,
                    "test needs elevated Windows runner"
                );
                LocalFree(sd.cast());
            }
        }
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        let handle = std::fs::OpenOptions::new()
            .access_mode(0x20000)
            .open(&file)
            .unwrap();
        assert!(
            protected_handle(handle.as_raw_handle(), false),
            "fixture file must be protected"
        );
        let parent = std::fs::OpenOptions::new()
            .access_mode(0x20000)
            .custom_flags(0x02000000)
            .open(&dir)
            .unwrap();
        assert!(
            !protected_handle(parent.as_raw_handle(), true),
            "delete-child permission allows replacement"
        );
        assert!(protected_image(&file.to_string_lossy()).is_none());
        drop(handle);
        drop(parent);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn name_only_missing_time_and_interactive_scanner_never_authorize() {
        let mut a = Accessor {
            process_name: "C:\\Users\\alice\\msmpeng.exe".into(),
            pid: std::process::id() as i32,
            logon_type: Some(5),
            ..Default::default()
        };
        assert!(!verified(&a, None));
        assert!(!verified(&a, Some(u64::MAX)));
        a.logon_type = Some(2);
        assert!(!verified(&a, Some(u64::MAX)));
    }
    #[test]
    fn catalog_signed_search_indexer_image_is_trusted() {
        // Windows Search binaries carry no embedded signature; they are
        // trusted only through the system catalog (real-host regression).
        let image = format!(
            "{}\\System32\\SearchProtocolHost.exe",
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())
        );
        if !std::path::Path::new(&image).exists() {
            return; // Server Core / Search not installed.
        }
        let locked = protected_image(&image).expect("System32 image must be protected");
        use std::os::windows::io::AsRawHandle;
        let handle = locked.last().unwrap().as_raw_handle();
        let path: Vec<u16> = image.encode_utf16().chain(Some(0)).collect();
        assert!(catalog_trusted(&path, handle) || embedded_trusted(&path, handle));
    }

    #[test]
    fn unsigned_file_is_neither_embedded_nor_catalog_trusted() {
        let file =
            std::env::temp_dir().join(format!("trapd-unsigned-{}.exe", uuid::Uuid::new_v4()));
        std::fs::write(&file, b"MZ not a signed image").unwrap();
        let open = std::fs::File::open(&file).unwrap();
        use std::os::windows::io::AsRawHandle;
        let path: Vec<u16> = file
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        assert!(!embedded_trusted(&path, open.as_raw_handle()));
        assert!(!catalog_trusted(&path, open.as_raw_handle()));
        drop(open);
        std::fs::remove_file(file).unwrap();
    }
}
