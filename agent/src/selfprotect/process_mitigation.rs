//! Conservative process mitigation policies for the Windows service.
//!
//! Only policies that cannot affect the agent's own behaviour are applied.
//! Deliberately NOT enabled: signature-only image loading (the agent binary
//! itself is not Authenticode-signed), dynamic-code prohibition, child-process
//! restriction (the update helper and containment spawn children) and
//! win32k/system-call filtering. Failure to apply a policy is logged and never
//! fatal: hardening must not stop telemetry.

use tracing::{info, warn};
use windows_sys::Win32::System::Threading::{
    ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, SetProcessMitigationPolicy,
    PROCESS_MITIGATION_POLICY,
};

/// `PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY.DisableExtensionPoints`:
/// legacy extension points (AppInit DLLs, Winsock LSPs, global window hooks,
/// legacy IMEs) are not loaded into this process.
const DISABLE_EXTENSION_POINTS: u32 = 1 << 0;
/// `PROCESS_MITIGATION_IMAGE_LOAD_POLICY`: no images from remote shares and
/// none from low-integrity locations.
const NO_REMOTE_IMAGES: u32 = 1 << 0;
const NO_LOW_LABEL_IMAGES: u32 = 1 << 1;

const POLICIES: [(&str, PROCESS_MITIGATION_POLICY, u32); 2] = [
    (
        "extension_points",
        ProcessExtensionPointDisablePolicy,
        DISABLE_EXTENSION_POINTS,
    ),
    (
        "image_load",
        ProcessImageLoadPolicy,
        NO_REMOTE_IMAGES | NO_LOW_LABEL_IMAGES,
    ),
];

/// Apply the policies to the current process. Call early in service start-up,
/// before worker threads load further modules.
pub fn apply() {
    for (name, policy, flags) in POLICIES {
        // SAFETY: both policy structures are a single DWORD of bit flags; the
        // buffer is a valid u32 and its size is passed.
        let ok = unsafe {
            SetProcessMitigationPolicy(
                policy,
                (&flags as *const u32).cast(),
                std::mem::size_of::<u32>(),
            )
        };
        if ok == 0 {
            warn!(
                policy = name,
                error = %std::io::Error::last_os_error(),
                "process mitigation policy not applied"
            );
        } else {
            info!(policy = name, "process mitigation policy applied");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_documented_low_risk_policies_are_requested() {
        let names: Vec<_> = POLICIES.iter().map(|(n, _, _)| *n).collect();
        assert_eq!(names, ["extension_points", "image_load"]);
        // No signature, dynamic-code or child-process restriction.
        assert!(POLICIES
            .iter()
            .all(|(_, _, f)| f & !(NO_REMOTE_IMAGES | NO_LOW_LABEL_IMAGES) == 0));
    }
}
