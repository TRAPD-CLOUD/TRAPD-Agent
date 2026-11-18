use super::*;

fn t0() -> Instant {
    Instant::now()
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

// ── Hung detection timing ─────────────────────────────────────────────────────

#[test]
fn a_peer_that_keeps_answering_is_never_lost() {
    let start = t0();
    let mut m = PeerMonitor::new(start);
    for i in 0..60 {
        let now = start + secs(i * 2);
        m.observe(now, Some(10), None);
        assert_eq!(m.poll(now + secs(1)), None, "tick {i}");
    }
}

#[test]
fn silence_counts_as_hung_only_after_ten_seconds() {
    let start = t0();
    let mut m = PeerMonitor::new(start);
    m.observe(start, Some(10), None);
    assert_eq!(m.poll(start + Duration::from_millis(9_999)), None);
    assert_eq!(
        m.poll(start + secs(10)),
        None,
        "exactly ten seconds is still tolerated"
    );
    let loss = m.poll(start + Duration::from_millis(10_001)).expect("hung");
    assert_eq!(loss.reason, LossReason::Hung);
    assert!(loss.first);
    assert_eq!(loss.class, None);
}

#[test]
fn a_process_exit_is_reported_at_once_as_died() {
    let start = t0();
    let mut m = PeerMonitor::new(start);
    m.observe(start, Some(10), None);
    m.mark_exited();
    let loss = m.poll(start + Duration::from_millis(100)).expect("died");
    assert_eq!(loss.reason, LossReason::Died);
}

#[test]
fn a_peer_never_heard_from_is_given_the_startup_grace() {
    let start = t0();
    let mut m = PeerMonitor::new(start);
    assert_eq!(m.poll(start + STARTUP_GRACE), None);
    let loss = m.poll(start + STARTUP_GRACE + secs(1)).expect("absent");
    assert_eq!(loss.reason, LossReason::Died);
}

#[test]
fn a_returning_peer_ends_the_episode_and_a_new_loss_reports_again() {
    let start = t0();
    let mut m = PeerMonitor::new(start);
    m.observe(start, Some(10), None);
    assert!(m.poll(start + secs(11)).unwrap().first);
    m.observe(start + secs(12), Some(11), None);
    assert_eq!(m.poll(start + secs(13)), None);
    let again = m.poll(start + secs(30)).expect("lost again");
    assert!(again.first, "a new episode reports again");
}

#[test]
fn a_lost_peer_is_rehandled_periodically_without_reporting_again() {
    let start = t0();
    let mut m = PeerMonitor::new(start);
    m.observe(start, Some(10), None);
    assert!(m.poll(start + secs(11)).unwrap().first);
    assert_eq!(m.poll(start + secs(12)), None, "not before the interval");
    let again = m.poll(start + secs(11) + RELOSS_INTERVAL).expect("retry");
    assert!(!again.first);
}

#[test]
fn a_resumed_peer_is_not_lost_just_because_time_passed_while_suspended() {
    // `kill -STOP` then `kill -CONT` within the window: no event.
    let start = t0();
    let mut m = PeerMonitor::new(start);
    m.observe(start, Some(10), None);
    assert_eq!(m.poll(start + secs(8)), None);
    m.observe(start + secs(9), Some(10), None);
    assert_eq!(m.poll(start + secs(18)), None);
}

// ── Announced stops ───────────────────────────────────────────────────────────

fn marker(reason: Reason, now: i64) -> StopMarker {
    StopMarker::new(
        reason,
        matches!(reason, Reason::Maintenance | Reason::Uninstall)
            .then(|| "0123456789abcdef0123456789abcdef".to_owned()),
        Some("0.7.9".into()),
        None,
        now,
    )
}

fn notice(kind: NoticeKind, m: Option<StopMarker>) -> StopNotice {
    StopNotice { kind, marker: m }
}

#[test]
fn notices_are_classified_by_their_validated_marker() {
    let now = 1_800_000_000;
    let c = |n: StopNotice| classify(&n, now);
    assert_eq!(
        c(notice(NoticeKind::HostShutdown, None)),
        StopClass::HostShutdown
    );
    assert_eq!(
        c(notice(NoticeKind::ServiceStop, None)),
        StopClass::Unauthorized
    );
    assert_eq!(
        c(notice(
            NoticeKind::ServiceStop,
            Some(marker(Reason::Upgrade, now))
        )),
        StopClass::Planned
    );
    assert_eq!(
        c(notice(
            NoticeKind::ServiceStop,
            Some(marker(Reason::SelfUpdate, now))
        )),
        StopClass::Planned
    );
    assert_eq!(
        c(notice(
            NoticeKind::ServiceStop,
            Some(marker(Reason::Maintenance, now))
        )),
        StopClass::Authorized
    );
    assert_eq!(
        c(notice(
            NoticeKind::ServiceStop,
            Some(marker(Reason::Uninstall, now))
        )),
        StopClass::Authorized
    );
}

#[test]
fn an_expired_or_inconsistent_marker_is_no_authorization() {
    let now = 1_800_000_000;
    let old = marker(Reason::Uninstall, now - 10_000);
    assert_eq!(
        classify(&notice(NoticeKind::ServiceStop, Some(old)), now),
        StopClass::Unauthorized
    );
    // A token-backed reason without its nonce.
    let mut no_nonce = marker(Reason::Maintenance, now);
    no_nonce.token_nonce = None;
    assert_eq!(
        classify(&notice(NoticeKind::ServiceStop, Some(no_nonce)), now),
        StopClass::Unauthorized
    );
}

#[test]
fn decisions_suppress_only_what_was_actually_authorized() {
    let d = |c, expired| decide(c, expired);
    // Unannounced and unauthorized stops are reported and restarted.
    for c in [None, Some(StopClass::Unauthorized)] {
        let x = d(c, false);
        assert!(
            x.report && x.restart == RestartPolicy::Now && !x.watcher_exits,
            "{c:?}"
        );
    }
    // Authorized: quiet, no restart, the guard follows.
    let x = d(Some(StopClass::Authorized), false);
    assert!(!x.report && x.restart == RestartPolicy::Never && x.watcher_exits);
    // Host shutdown: quiet, nobody restarts anything.
    let x = d(Some(StopClass::HostShutdown), false);
    assert!(!x.report && x.restart == RestartPolicy::Never && !x.watcher_exits);
    // Planned: quiet until the grace period is over, then like an unannounced loss.
    let x = d(Some(StopClass::Planned), false);
    assert!(!x.report && x.restart == RestartPolicy::Never);
    let x = d(Some(StopClass::Planned), true);
    assert!(x.report && x.restart == RestartPolicy::Now);
}

#[test]
fn an_announced_stop_is_not_reported_as_hung_while_the_process_shuts_down() {
    let start = t0();
    let mut m = PeerMonitor::new(start);
    m.observe(start, Some(10), None);
    m.observe(start + secs(2), Some(10), Some(StopClass::Authorized));
    assert_eq!(
        m.poll(start + secs(30)),
        None,
        "shutdown takes longer than a hang window"
    );
    let loss = m.poll(start + secs(63)).expect("stuck shutdown");
    assert_eq!(loss.reason, LossReason::Hung);
    assert_eq!(loss.class, Some(StopClass::Authorized));
}

#[test]
fn a_planned_stop_waits_for_the_peer_to_return_then_gives_up() {
    let start = t0();
    let mut m = PeerMonitor::new(start);
    m.observe(start, Some(10), Some(StopClass::Planned));
    m.mark_exited();
    assert_eq!(m.poll(start + secs(1)), None);
    assert_eq!(m.poll(start + PLANNED_RESTART_GRACE - secs(1)), None);
    let loss = m
        .poll(start + PLANNED_RESTART_GRACE + secs(2))
        .expect("did not return");
    assert!(loss.grace_expired && loss.first);
}

#[test]
fn a_planned_peer_that_comes_back_is_not_lost() {
    let start = t0();
    let mut m = PeerMonitor::new(start);
    m.observe(start, Some(10), Some(StopClass::Planned));
    m.mark_exited();
    assert_eq!(m.poll(start + secs(5)), None);
    m.observe(start + secs(20), Some(99), None);
    // It keeps answering after the restart, well past the original grace.
    let late = start + PLANNED_RESTART_GRACE + secs(60);
    m.observe(late, Some(99), None);
    assert_eq!(m.poll(late + secs(1)), None);
}

// ── Restart rate limit ────────────────────────────────────────────────────────

#[test]
fn restarts_are_limited_per_window_and_recover_afterwards() {
    let start = t0();
    let mut l = RestartLimiter::new();
    for i in 0..MAX_RESTARTS {
        assert!(l.try_acquire(start + secs(i as u64)), "attempt {i}");
    }
    assert!(!l.try_acquire(start + secs(10)));
    assert!(!l.try_acquire(start + RESTART_WINDOW - secs(1)));
    assert!(
        l.try_acquire(start + RESTART_WINDOW),
        "the oldest attempt aged out"
    );
}

// ── Protocol and records ──────────────────────────────────────────────────────

#[test]
fn frames_round_trip_and_reject_unknown_fields_and_oversize_input() {
    let ping = Ping {
        v: PROTOCOL_VERSION,
        seq: 5,
        stop: Some(notice(
            NoticeKind::ServiceStop,
            Some(marker(Reason::Upgrade, 1_800_000_000)),
        )),
    };
    let bytes = encode_frame(&ping).unwrap();
    assert_eq!(*bytes.last().unwrap(), b'\n');
    let back: Ping = parse_frame(&bytes[..bytes.len() - 1]).unwrap();
    assert_eq!(back, ping);
    assert!(parse_frame::<Ping>(br#"{"v":1,"seq":1,"x":1}"#).is_err());
    assert!(parse_frame::<Ping>(&vec![b' '; MAX_FRAME_BYTES + 1]).is_err());
    assert!(parse_frame::<Pong>(b"{}").is_err());
}

fn loss(class: Option<StopClass>) -> Loss {
    Loss {
        reason: LossReason::Hung,
        class,
        first: true,
        grace_expired: false,
    }
}

#[test]
fn the_peer_lost_event_carries_the_agreed_fields() {
    let r = Record::peer_lost(
        Peer::Agent,
        &loss(Some(StopClass::Unauthorized)),
        RestartOutcome::Started,
        Utc::now(),
    );
    assert!(r.validate());
    let event = record_event(&r, "agent-1", "host-1");
    assert_eq!(event.event_id, r.event_id);
    assert_eq!(event.severity, Severity::High);
    let EventData::Detection(d) = event.data else {
        panic!("detection expected")
    };
    assert_eq!(d.rule_id, "selfprotect.peer_lost");
    assert_eq!(d.evidence["peer"], "agent");
    assert_eq!(d.evidence["reason"], "hung");
    assert_eq!(d.evidence["announced_stop"], true);
    assert_eq!(d.evidence["maintenance_authorized"], false);
}

#[test]
fn an_authorized_loss_is_medium_and_a_tampered_binary_is_critical() {
    let authorized = Record::peer_lost(
        Peer::Guard,
        &loss(Some(StopClass::Planned)),
        RestartOutcome::Started,
        Utc::now(),
    );
    assert_eq!(
        record_event(&authorized, "a", "h").severity,
        Severity::Medium
    );
    let h = |c: &str| format!("sha256:{}", c.repeat(64));
    let t = Record::binary_tampered(Peer::Agent, &loss(None), &h("a"), &h("b"), Utc::now());
    assert!(t.validate());
    let event = record_event(&t, "a", "h");
    assert_eq!(event.severity, Severity::Critical);
    let EventData::Detection(d) = event.data else {
        panic!()
    };
    assert_eq!(d.rule_id, "selfprotect.peer_binary_tampered");
    assert_eq!(d.evidence["current_hash"], h("b"));
}

#[test]
fn records_with_hostile_content_do_not_validate() {
    let mut r = Record::peer_lost(
        Peer::Agent,
        &loss(None),
        RestartOutcome::Started,
        Utc::now(),
    );
    r.event_id = Uuid::nil();
    assert!(!r.validate());
    let h = "sha256:zz".to_owned();
    let t = Record::binary_tampered(Peer::Agent, &loss(None), &h, &h, Utc::now());
    assert!(!t.validate());
}

#[test]
fn the_spool_is_bounded() {
    let dir = std::env::temp_dir().join(format!("trapd-guard-spool-{}", Uuid::new_v4()));
    let r = || {
        Record::peer_lost(
            Peer::Agent,
            &loss(None),
            RestartOutcome::Started,
            Utc::now(),
        )
    };
    for _ in 0..MAX_SPOOL_RECORDS {
        write_record(&dir, &r()).unwrap();
    }
    assert!(write_record(&dir, &r()).is_err());
    assert_eq!(pending_count(&dir), MAX_SPOOL_RECORDS);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tracer_pid_is_read_from_proc_status() {
    let traced = "Name:\ttrapd-agent\nState:\tt (tracing stop)\nTracerPid:\t650\nUid:\t0\n";
    assert_eq!(parse_tracer_pid(traced), Some(650));
    assert_eq!(
        parse_tracer_pid("Name:\tx\nTracerPid:\t0\n"),
        None,
        "0 = not traced"
    );
    assert_eq!(parse_tracer_pid("Name:\tx\n"), None);
    assert_eq!(parse_tracer_pid("TracerPid:\tjunk\n"), None);
}

#[test]
fn a_record_with_a_malformed_tracer_is_rejected() {
    let loss = Loss {
        reason: LossReason::Hung,
        class: None,
        first: true,
        grace_expired: false,
    };
    let base = Record::peer_lost(
        Peer::Agent,
        &loss,
        RestartOutcome::Started,
        chrono::Utc::now(),
    );
    let ok = base.clone().with_tracer(Some(Tracer {
        pid: 650,
        exe: "/usr/bin/gdb".into(),
    }));
    assert!(ok.validate());
    for bad in [
        Tracer {
            pid: 1,
            exe: "/sbin/init".into(),
        },
        Tracer {
            pid: 650,
            exe: String::new(),
        },
        Tracer {
            pid: 650,
            exe: "/tmp/x\nforged line".into(),
        },
        Tracer {
            pid: 650,
            exe: "a".repeat(4097),
        },
    ] {
        assert!(!base.clone().with_tracer(Some(bad)).validate());
    }
}
