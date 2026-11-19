//! Platform posture and time integrity (Phase 09, layer L5).
//!
//! * Posture snapshot at start and every 15 minutes (`snapshot`, `linux`,
//!   `windows`); any change in a setting's secure/insecure judgement raises
//!   `selfprotect.platform_posture_changed` (high for weakening, info for
//!   strengthening) with before/after. The latest snapshot rides on the
//!   heartbeat for the console.
//! * Measured boot (`tcg_log`): TCG event log compared with the previous boot.
//! * Boot id and local clock jumps (`clock`): `selfprotect.time_jump`.
//!
//! Operator switches (a detector must be silenceable):
//!   `TRAPD_PLATFORM_POSTURE=off`   disable posture + measured boot
//!   `TRAPD_POSTURE_IGNORE=a,b`     setting keys never reported as changed
//!   `TRAPD_TIME_JUMP=off`          disable clock-jump detection
//!   `TRAPD_TIME_JUMP_THRESHOLD_SECS` skew threshold (default 120)
//!
//! Trust note: baselines live in the state directory. Anyone who can write it
//! can reset a baseline, but that already requires the privileges that make
//! the underlying tampering possible; the journal (WP3) covers the evidence.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::mpsc::Sender;
use tracing::{info, warn};
use trapd_schema::{AgentEvent, DetectionData, EventAction, EventClass, EventData, Severity};

pub mod clock;
pub mod linux;
pub mod snapshot;
pub mod tcg_log;
pub mod windows;

pub const INTERVAL: Duration = Duration::from_secs(15 * 60);
const CLOCK_TICK: Duration = Duration::from_secs(30);
const MEASURED_BOOT_FILE: &str = "measured_boot.json";
#[cfg(target_os = "linux")]
const LINUX_TCG_LOG: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";

static LATEST: OnceLock<Mutex<Option<snapshot::Snapshot>>> = OnceLock::new();

fn latest_slot() -> &'static Mutex<Option<snapshot::Snapshot>> {
    LATEST.get_or_init(|| Mutex::new(None))
}

/// What the heartbeat carries for the console.
#[derive(Debug, Clone, Serialize)]
pub struct PostureReport {
    pub snapshot: snapshot::Snapshot,
    pub boot_id: Option<String>,
}

pub fn heartbeat_report() -> Option<PostureReport> {
    let snapshot = latest_slot().lock().ok()?.clone()?;
    Some(PostureReport {
        snapshot,
        boot_id: clock::boot_id(),
    })
}

fn env_off(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false"
        )
    })
}

pub fn parse_ignore(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn event(agent_id: &str, hostname: &str, sev: Severity, d: DetectionData) -> AgentEvent {
    AgentEvent::new(
        agent_id.into(),
        hostname.into(),
        EventClass::Detection,
        EventAction::Detected,
        sev,
        EventData::Detection(Box::new(d)),
    )
}

fn collect_settings() -> (
    &'static str,
    std::collections::BTreeMap<String, snapshot::Setting>,
) {
    #[cfg(windows)]
    {
        ("windows", windows::evaluate(&windows::HostProbe))
    }
    #[cfg(target_os = "linux")]
    {
        ("linux", linux::collect(std::path::Path::new("/")))
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        ("other", Default::default())
    }
}

/// One posture round: collect, diff against the persisted baseline, persist.
/// Returns the finding to send (if any) and the baseline to store once it was
/// handed off.
fn posture_round(
    dir: &std::path::Path,
    ignore: &HashSet<String>,
) -> (Option<(Severity, DetectionData)>, snapshot::Snapshot) {
    let (platform, settings) = collect_settings();
    let cur = snapshot::Snapshot::new(platform, settings);
    if let Ok(mut slot) = latest_slot().lock() {
        *slot = Some(cur.clone());
    }
    let prev = snapshot::load(dir);
    let finding = prev
        .as_ref()
        .filter(|p| p.platform == cur.platform)
        .and_then(|p| snapshot::finding(&snapshot::diff(p, &cur, ignore)));
    let baseline = cur.merged_over(prev.as_ref().filter(|p| p.platform == cur.platform));
    (finding, baseline)
}

fn read_tcg_log() -> Option<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let mut buf = Vec::new();
        std::fs::File::open(LINUX_TCG_LOG)
            .ok()?
            .take(tcg_log::MAX_LOG_BYTES as u64)
            .read_to_end(&mut buf)
            .ok()?;
        Some(buf)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::TpmBaseServices::{
            Tbsi_Context_Create, Tbsi_Get_TCG_Log, Tbsip_Context_Close, TBS_CONTEXT_PARAMS,
            TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_CONTEXT_PARAMS2_0_0,
            TBS_CONTEXT_VERSION_TWO,
        };
        // A version 1 context only talks to TPM 1.2, so a TPM 2.0 host would never yield a log.
        // Version 2 with both generation bits set (bit 1 = includeTpm12, bit 2 = includeTpm20)
        // works on either.
        const INCLUDE_TPM12: u32 = 1 << 1;
        const INCLUDE_TPM20: u32 = 1 << 2;
        let params = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            Anonymous: TBS_CONTEXT_PARAMS2_0 {
                Anonymous: TBS_CONTEXT_PARAMS2_0_0 {
                    _bitfield: INCLUDE_TPM12 | INCLUDE_TPM20,
                },
            },
        };
        let mut ctx: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: valid in/out pointers; the context is closed below. TBS reads the version field
        // first and then interprets the structure as TBS_CONTEXT_PARAMS2.
        if unsafe {
            Tbsi_Context_Create(
                std::ptr::from_ref(&params).cast::<TBS_CONTEXT_PARAMS>(),
                &mut ctx,
            )
        } != 0
            || ctx.is_null()
        {
            return None;
        }
        let mut len = 0u32;
        // SAFETY: a null buffer asks TBS for the required size.
        unsafe { Tbsi_Get_TCG_Log(ctx, std::ptr::null_mut(), &mut len) };
        let out = if len > 0 && (len as usize) <= tcg_log::MAX_LOG_BYTES {
            let mut buf = vec![0u8; len as usize];
            let mut got = len;
            // SAFETY: `buf` is `len` bytes long.
            let rc = unsafe { Tbsi_Get_TCG_Log(ctx, buf.as_mut_ptr(), &mut got) };
            (rc == 0).then(|| {
                buf.truncate(got.min(len) as usize);
                buf
            })
        } else {
            None
        };
        // SAFETY: `ctx` came from Tbsi_Context_Create.
        unsafe { Tbsip_Context_Close(ctx) };
        out
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

/// Compare this boot's measurements with the previous boot's. Returns the
/// finding (if any) and the record to persist after handoff. Nothing is
/// compared within one boot (an agent restart must not re-report).
pub fn measured_boot_round(
    dir: &std::path::Path,
    log: &[u8],
    boot_id: Option<String>,
) -> Option<(Option<(Severity, DetectionData)>, tcg_log::BootMeasurements)> {
    let parsed = tcg_log::parse(log)?;
    if parsed.truncated {
        // A log that ends mid-event or stops at a record we cannot read is a prefix of the boot, not
        // the boot: diffing it would report missing measurements as removals, and persisting it
        // would replace the last complete baseline. Keep the baseline and skip this round.
        return None;
    }
    let cur = tcg_log::summarize(&parsed, boot_id);
    let prev: Option<tcg_log::BootMeasurements> =
        crate::paths::bounded_regular_bytes(&dir.join(MEASURED_BOOT_FILE), 512 * 1024)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
    if let Some(p) = &prev {
        let same_boot = matches!((&p.boot_id, &cur.boot_id), (Some(a), Some(b)) if a == b);
        if same_boot {
            return Some((None, cur));
        }
    }
    let finding = prev.as_ref().and_then(|p| {
        tcg_log::finding(
            &tcg_log::diff(p, &cur),
            p.boot_id.as_deref(),
            cur.boot_id.as_deref(),
        )
    });
    Some((finding, cur))
}

async fn run_posture(tx: Sender<AgentEvent>, agent_id: String, hostname: String) {
    let dir = crate::paths::state_dir().to_path_buf();
    let ignore = parse_ignore(&std::env::var("TRAPD_POSTURE_IGNORE").unwrap_or_default());
    let mut first = true;
    loop {
        let (d, ig) = (dir.clone(), ignore.clone());
        if let Ok((finding, baseline)) =
            tokio::task::spawn_blocking(move || posture_round(&d, &ig)).await
        {
            if let Some((sev, det)) = finding {
                warn!(rule = %det.rule_id, "platform posture changed");
                if tx
                    .send(event(&agent_id, &hostname, sev, det))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            // Persist only after the event was handed to the pipeline.
            if let Err(e) = snapshot::store(&dir, &baseline) {
                warn!(error = %e, "could not persist the platform posture baseline");
            }
        }
        if first {
            first = false;
            let d = dir.clone();
            let boot = clock::boot_id();
            let res = tokio::task::spawn_blocking(move || {
                read_tcg_log().and_then(|log| measured_boot_round(&d, &log, boot))
            })
            .await
            .ok()
            .flatten();
            match res {
                Some((finding, cur)) => {
                    if let Some((sev, det)) = finding {
                        if tx
                            .send(event(&agent_id, &hostname, sev, det))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    if let Err(e) = snapshot::write_json_atomic(&dir.join(MEASURED_BOOT_FILE), &cur)
                    {
                        warn!(error = %e, "could not persist measured-boot record");
                    }
                }
                None => info!("measured-boot log unavailable or unparseable on this host"),
            }
        }
        tokio::time::sleep(INTERVAL).await;
    }
}

async fn run_clock(tx: Sender<AgentEvent>, agent_id: String, hostname: String) {
    let dir = crate::paths::state_dir().to_path_buf();
    let threshold = std::env::var("TRAPD_TIME_JUMP_THRESHOLD_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(clock::DEFAULT_THRESHOLD_SECS);
    let boot = clock::boot_id();
    let (mono, wall) = (clock::monotonic_ms(), chrono::Utc::now());
    if let Some(a) = clock::load_anchor(&dir) {
        if let Some(j) = clock::check_against_anchor(&a, boot.as_deref(), mono, wall, threshold) {
            let (sev, det) = clock::finding(&j);
            if tx
                .send(event(&agent_id, &hostname, sev, det))
                .await
                .is_err()
            {
                return;
            }
        }
    }
    let mut watch = clock::ClockWatch::new(mono, wall, threshold);
    let mut ticks = 0u32;
    loop {
        tokio::time::sleep(CLOCK_TICK).await;
        let (mono, wall) = (clock::monotonic_ms(), chrono::Utc::now());
        if let Some(j) = watch.observe(mono, wall) {
            let (sev, det) = clock::finding(&j);
            if tx
                .send(event(&agent_id, &hostname, sev, det))
                .await
                .is_err()
            {
                return;
            }
        }
        ticks += 1;
        if ticks % 5 == 1 {
            let _ = clock::store_anchor(
                &dir,
                &clock::Anchor {
                    boot_id: boot.clone(),
                    mono_ms: mono,
                    wall,
                },
            );
        }
    }
}

/// Spawn both background loops (each honours its own switch).
pub fn spawn(tx: Sender<AgentEvent>, agent_id: String, hostname: String) {
    if env_off("TRAPD_PLATFORM_POSTURE") {
        info!("platform posture checks disabled (TRAPD_PLATFORM_POSTURE=off)");
    } else {
        tokio::spawn(run_posture(tx.clone(), agent_id.clone(), hostname.clone()));
    }
    if env_off("TRAPD_TIME_JUMP") {
        info!("clock-jump detection disabled (TRAPD_TIME_JUMP=off)");
    } else {
        tokio::spawn(run_clock(tx, agent_id, hostname));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tcg_log::fixture::boot;

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("trapd_posture_mod_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn ignore_list_parsing() {
        let s = parse_ignore(" a, b ,,c");
        assert_eq!(s.len(), 3);
        assert!(s.contains("b"));
    }

    #[test]
    fn measured_boot_first_boot_same_boot_and_changed_boot() {
        let dir = tmp();
        let ok = boot(1, 9, &[0x1000_0001]);
        // First observation: baseline only.
        let (f, cur) = measured_boot_round(&dir, &ok, Some("b1".into())).unwrap();
        assert!(f.is_none());
        snapshot::write_json_atomic(&dir.join(MEASURED_BOOT_FILE), &cur).unwrap();
        // Agent restart within the same boot: never compared.
        let weaker = boot(0, 9, &[0x1000_0001]);
        assert!(measured_boot_round(&dir, &weaker, Some("b1".into()))
            .unwrap()
            .0
            .is_none());
        // Next boot with Secure Boot turned off: high finding.
        let (f, _) = measured_boot_round(&dir, &weaker, Some("b2".into())).unwrap();
        assert_eq!(f.unwrap().0, Severity::High);
        // Unparseable log: no result, no panic.
        assert!(measured_boot_round(&dir, &[1, 2, 3], Some("b3".into())).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_truncated_log_neither_diffs_nor_replaces_the_complete_baseline() {
        let dir = tmp();
        let ok = boot(1, 9, &[0x1000_0001]);
        let (_, cur) = measured_boot_round(&dir, &ok, Some("b1".into())).unwrap();
        snapshot::write_json_atomic(&dir.join(MEASURED_BOOT_FILE), &cur).unwrap();
        // The next boot's log ends in the middle of an event: a prefix, not the boot.
        let mut cut = boot(1, 9, &[0x1000_0001]);
        cut.truncate(cut.len() - 5);
        assert!(
            tcg_log::parse(&cut).is_some_and(|p| p.truncated),
            "fixture must parse as truncated"
        );
        assert!(
            measured_boot_round(&dir, &cut, Some("b2".into())).is_none(),
            "no finding and no new baseline from an incomplete log"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn posture_round_end_to_end_on_this_host() {
        let dir = tmp();
        let (f, base) = posture_round(&dir, &HashSet::new());
        assert!(f.is_none(), "first round only records a baseline");
        snapshot::store(&dir, &base).unwrap();
        assert!(heartbeat_report().is_some());
        // Forge a stronger baseline for every judged key, then expect a weakening.
        let mut forged = base.clone();
        let mut any = false;
        for s in forged.settings.values_mut() {
            if s.secure == Some(false) {
                s.secure = Some(true);
                any = true;
            }
        }
        if any {
            snapshot::store(&dir, &forged).unwrap();
            let (f, _) = posture_round(&dir, &HashSet::new());
            assert_eq!(f.unwrap().0, Severity::High);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
