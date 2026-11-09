//! Durable record of host isolation.
//!
//! Linux firewall rules live in kernel memory, so a reboot would silently lift
//! isolation while the backend still reports the host as isolated. The record
//! is written before the rules change: a crash in between errs towards isolated.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationState {
    /// Operator-requested additions, kept so the allowlist can be re-resolved.
    pub requested: Vec<IpAddr>,
    /// Complete allowlist last applied, including the management channel.
    pub resolved: Vec<IpAddr>,
}

pub fn path() -> PathBuf {
    crate::paths::state_dir().join("isolation.json")
}

pub fn load(path: &Path) -> Result<Option<IsolationState>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .context("parse isolation state"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("read isolation state"),
    }
}

fn save(path: &Path, state: &IsolationState) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let bytes = serde_json::to_vec(state)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut file = options.open(&tmp).context("create isolation state")?;
        file.write_all(&bytes).context("write isolation state")?;
        file.sync_all().context("sync isolation state")?;
    }
    fs::rename(&tmp, path).context("publish isolation state")
}

fn clear(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("remove isolation state"),
    }
}

/// Apply isolation and record it. Returns whether the record was stored: a
/// storage failure must not delay containment, so the caller reports it instead.
/// A failed apply returns to the earlier state and never releases a host that
/// was or may have been isolated. A missing record proves nothing on its own,
/// because isolation can predate this record or have failed to store it, so
/// `held` reports what the firewall holds before anything changes.
pub fn isolate(
    path: &Path,
    state: &IsolationState,
    held: impl Fn() -> Result<bool>,
    apply: impl Fn(&[IpAddr]) -> Result<()>,
    lift: impl Fn() -> Result<()>,
) -> Result<bool> {
    let previous = load(path);
    let held_before = matches!(previous, Ok(None)).then(held);
    let persisted = match save(path, state) {
        Ok(()) => true,
        Err(error) => {
            warn!(error = %format!("{error:#}"), "isolation will not survive a reboot");
            false
        }
    };
    let Err(error) = apply(&state.resolved) else {
        return Ok(persisted);
    };
    let rollback = match &previous {
        // Restore the rules even if the record cannot be written.
        Ok(Some(earlier)) => {
            let saved = save(path, earlier);
            apply(&earlier.resolved).and(saved)
        }
        Ok(None) if matches!(held_before, Some(Ok(false))) => lift().and_then(|()| clear(path)),
        Ok(None) => clear(path).and(Err(anyhow!(
            "earlier isolation cannot be ruled out; firewall left as is"
        ))),
        Err(_) => Err(anyhow!("earlier isolation state is unreadable; left as is")),
    };
    match rollback {
        Ok(()) => Err(error),
        Err(failed) => Err(error.context(format!("rollback failed: {failed:#}"))),
    }
}

/// Lift isolation, then forget it. If lifting fails the record stays.
pub fn release(path: &Path, lift: impl Fn() -> Result<()>) -> Result<()> {
    lift()?;
    clear(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn temp() -> PathBuf {
        std::env::temp_dir().join(format!("trapd-isolation-{}.json", uuid::Uuid::new_v4()))
    }

    fn state(ip: &str) -> IsolationState {
        let ip: IpAddr = ip.parse().unwrap();
        IsolationState {
            requested: vec![],
            resolved: vec![ip],
        }
    }

    #[test]
    fn a_successful_isolation_is_recorded_and_release_forgets_it() {
        let path = temp();
        let wanted = state("10.0.0.1");
        assert!(isolate(&path, &wanted, || Ok(false), |_| Ok(()), || Ok(())).unwrap());
        assert_eq!(load(&path).unwrap(), Some(wanted));
        release(&path, || Ok(())).unwrap();
        assert_eq!(load(&path).unwrap(), None);
    }

    #[test]
    fn release_is_idempotent() {
        let path = temp();
        release(&path, || Ok(())).unwrap();
        release(&path, || Ok(())).unwrap();
    }

    #[test]
    fn a_failed_first_isolation_lifts_partial_rules_and_records_nothing() {
        let path = temp();
        let lifted = RefCell::new(0);
        let result = isolate(
            &path,
            &state("10.0.0.1"),
            || Ok(false),
            |_| Err(anyhow!("nft failed")),
            || {
                *lifted.borrow_mut() += 1;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(*lifted.borrow(), 1);
        assert_eq!(load(&path).unwrap(), None);
    }

    #[test]
    fn a_failed_change_never_releases_an_isolated_host() {
        let path = temp();
        let earlier = state("10.0.0.1");
        isolate(&path, &earlier, || Ok(false), |_| Ok(()), || Ok(())).unwrap();
        let applied = RefCell::new(Vec::new());
        let result = isolate(
            &path,
            &state("10.0.0.2"),
            || Ok(false),
            |ips| {
                applied.borrow_mut().push(ips.to_vec());
                if applied.borrow().len() == 1 {
                    Err(anyhow!("nft failed"))
                } else {
                    Ok(())
                }
            },
            || panic!("an isolated host must not be released"),
        );
        assert!(result.is_err());
        assert_eq!(applied.borrow().last().unwrap(), &earlier.resolved);
        assert_eq!(load(&path).unwrap(), Some(earlier));
        clear(&path).unwrap();
    }

    #[test]
    fn a_missing_record_never_releases_rules_already_in_place() {
        for held in [true, false] {
            let path = temp();
            let result = isolate(
                &path,
                &state("10.0.0.1"),
                || {
                    if held {
                        Ok(true)
                    } else {
                        Err(anyhow!("cannot inspect firewall"))
                    }
                },
                |_| Err(anyhow!("nft failed")),
                || panic!("possibly isolated host must not be released"),
            );
            assert!(format!("{:#}", result.unwrap_err()).contains("left as is"));
            assert_eq!(load(&path).unwrap(), None);
        }
    }

    #[test]
    fn earlier_rules_are_restored_even_when_the_record_cannot_be_written() {
        let directory = std::env::temp_dir().join(format!("trapd-iso-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("isolation.json");
        let earlier = state("10.0.0.1");
        save(&path, &earlier).unwrap();
        let applied = RefCell::new(Vec::new());
        let result = isolate(
            &path,
            &state("10.0.0.2"),
            || panic!("the record already answers this"),
            |ips| {
                applied.borrow_mut().push(ips.to_vec());
                if applied.borrow().len() == 1 {
                    fs::remove_dir_all(&directory).unwrap();
                    Err(anyhow!("nft failed"))
                } else {
                    Ok(())
                }
            },
            || panic!("an isolated host must not be released"),
        );
        assert!(result.is_err());
        assert_eq!(applied.borrow().last().unwrap(), &earlier.resolved);
    }

    #[test]
    fn a_failed_release_keeps_the_record() {
        let path = temp();
        let wanted = state("10.0.0.1");
        isolate(&path, &wanted, || Ok(false), |_| Ok(()), || Ok(())).unwrap();
        assert!(release(&path, || Err(anyhow!("nft failed"))).is_err());
        assert_eq!(load(&path).unwrap(), Some(wanted));
        clear(&path).unwrap();
    }

    #[test]
    fn a_corrupt_record_is_an_error_and_is_never_lifted_on_failure() {
        let path = temp();
        fs::write(&path, b"{not json").unwrap();
        assert!(load(&path).is_err());
        let result = isolate(
            &path,
            &state("10.0.0.1"),
            || Ok(false),
            |_| Err(anyhow!("nft failed")),
            || panic!("unknown state must not be released"),
        );
        assert!(format!("{:#}", result.unwrap_err()).contains("rollback failed"));
        clear(&path).unwrap();
    }

    #[test]
    fn containment_still_applies_when_the_record_cannot_be_stored() {
        let path = std::env::temp_dir().join("trapd-no-such-dir-x/isolation.json");
        let applied = RefCell::new(false);
        let persisted = isolate(
            &path,
            &state("10.0.0.1"),
            || Ok(false),
            |_| {
                *applied.borrow_mut() = true;
                Ok(())
            },
            || Ok(()),
        )
        .unwrap();
        assert!(*applied.borrow());
        assert!(!persisted);
    }
}
