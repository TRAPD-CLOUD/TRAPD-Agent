use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
};

use crate::{COMM_LEN, PATH_LEN};

/// File open event emitted for every openat(2) call.
#[repr(C)]
pub struct FileOpenEvent {
    pub pid:          u32,
    pub uid:          u32,
    pub gid:          u32,
    /// O_RDONLY=0, O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200, …
    pub flags:        u64,
    pub comm:         [u8; COMM_LEN],
    pub filename:     [u8; PATH_LEN],
    pub filename_len: u32,
}

// ── Honeytoken access kinds ─────────────────────────────────────────────────
// Discriminates *how* a token was touched so userspace can score it: a content
// read/exec is a full intrusion (confidence 100), while bare metadata recon
// (stat/readlink) or an evasion attempt (hardlink) is a strong-but-softer lead.
// The value travels in `HoneytokenAccessEvent::access_kind`.
pub(crate) const ACCESS_OPENAT:   u32 = 0; // openat(2)            — content access
pub(crate) const ACCESS_OPEN:     u32 = 1; // open(2)  (legacy)    — content access
pub(crate) const ACCESS_OPENAT2:  u32 = 2; // openat2(2)           — content access
pub(crate) const ACCESS_EXEC:     u32 = 3; // execve/execveat      — token executed
pub(crate) const ACCESS_STAT:     u32 = 4; // newfstatat           — metadata recon
pub(crate) const ACCESS_STATX:    u32 = 5; // statx                — metadata recon
pub(crate) const ACCESS_READLINK: u32 = 6; // readlinkat           — metadata recon
pub(crate) const ACCESS_LINK:     u32 = 7; // linkat (oldpath)     — hardlink evasion
pub(crate) const ACCESS_UNLINK:   u32 = 8; // unlinkat             — tamper (delete)
pub(crate) const ACCESS_RENAME:   u32 = 9; // renameat2 (oldpath)  — tamper (rename)
pub(crate) const ACCESS_MMAP:     u32 = 10; // mmap(token fd)      — content access
pub(crate) const ACCESS_GETDENTS: u32 = 11; // getdents64(dir fd)  — directory recon

// fd-table value kinds: distinguishes a tracked file-fd (mmap target) from a
// tracked directory-fd (getdents target) so a lookup only fires for the right
// syscall.
const FD_KIND_FILE: u32 = 0;
const FD_KIND_DIR:  u32 = 1;

/// Honeytoken-access event — emitted whenever a syscall targets a path present in
/// [`HONEYTOKEN_PATHS`], **regardless of open flags** (a `cat ~/.aws/credentials`
/// is the whole point and must fire). `access_kind` records which syscall family
/// tripped the gate (see the `ACCESS_*` constants).
#[repr(C)]
pub struct HoneytokenAccessEvent {
    pub pid:          u32,
    pub uid:          u32,
    pub gid:          u32,
    pub _pad:         u32,
    /// Token id the userspace side associated with this path.
    pub token_id:     u64,
    /// open(2) flags the accessor used (0 for non-open syscalls).
    pub flags:        u64,
    pub comm:         [u8; COMM_LEN],
    pub filename:     [u8; PATH_LEN],
    pub filename_len: u32,
    /// Which syscall family tripped the gate — one of the `ACCESS_*` constants.
    pub access_kind:  u32,
}

/// 512 KiB – openat is frequent; ring buffer drops gracefully under load.
#[map]
static FILE_OPEN_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

/// Honeytoken match table: absolute path (NUL-padded to `PATH_LEN`) → token id.
///
/// Userspace owns this map and reconciles it from the on-disk honeytoken
/// register. We match by the exact path string here rather than by inode: the
/// codebase deliberately avoids dereferencing kernel structs in BPF (CO-RE is
/// fragile across kernels — see `process_block.rs`), and the syscall tracepoints
/// expose only the user path pointer, not a resolved inode. The userspace
/// consumer re-verifies the hit against the token's recorded device+inode, so
/// the authoritative identity check is inode-based even though the cheap
/// in-kernel gate is path-based.
///
/// Path-gating cannot see a *content read through a pre-existing hardlink or
/// copy* (a different path resolving to the same inode); that residual gap is
/// closed by the out-of-band canary embedded in the token content (issue #32,
/// point 2) and by kernel inode-matching (`HONEYTOKEN_INODES`, PR #31). We do,
/// however, catch the moment a hardlink is *created* to a token — see
/// `sys_enter_linkat` — so the evasion attempt itself is signal.
#[map]
static HONEYTOKEN_PATHS: HashMap<[u8; PATH_LEN], u64> =
    HashMap::<[u8; PATH_LEN], u64>::with_max_entries(256, 0);

/// Dedicated low-volume channel for honeytoken accesses. Separate from
/// `FILE_OPEN_EVENTS` so a hit is never lost in openat traffic and so the
/// read-only suppression on the main channel can stay exactly as it is.
#[map]
static HONEYTOKEN_ACCESS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Parent directories of deployed tokens (NUL-padded path → a token id). Armed
/// by userspace so we can spot a directory listing (`getdents64`) of a folder
/// that holds bait — "someone combed the directory" (issue #32, point 1).
#[map]
static HONEYTOKEN_DIRS: HashMap<[u8; PATH_LEN], u64> =
    HashMap::<[u8; PATH_LEN], u64>::with_max_entries(256, 0);

/// What a tracked file descriptor points at, so `mmap`/`getdents64` can be
/// correlated back to the token whose `open` produced the fd.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdToken {
    pub token_id: u64,
    /// `FD_KIND_FILE` (mmap target) or `FD_KIND_DIR` (getdents target).
    pub kind:     u32,
    pub _pad:     u32,
}

/// Scratch slot bridging a token `open`'s *enter* (where we know the path) to its
/// *exit* (where we learn the returned fd). Keyed by the full `pid_tgid`, since
/// the two tracepoints fire back-to-back on the same thread.
#[map]
static HT_OPEN_PENDING: HashMap<u64, FdToken> = HashMap::<u64, FdToken>::with_max_entries(4096, 0);

/// Resolved fd table: `(tgid << 32 | fd) → FdToken`. Populated on a successful
/// token open, consulted by `mmap`/`getdents64`, and pruned on `close` so a
/// reused fd cannot produce a false hit.
#[map]
static HONEYTOKEN_FDS: HashMap<u64, FdToken> = HashMap::<u64, FdToken>::with_max_entries(4096, 0);

// ── Shared honeytoken gate ──────────────────────────────────────────────────

/// Look `path` up in [`HONEYTOKEN_PATHS`] and, on a hit, emit a
/// [`HoneytokenAccessEvent`]. `path` must already be a zero-padded buffer so it
/// matches the NUL-padded key userspace inserts. Shared by every honeytoken
/// tracepoint (open family, exec, recon, tamper) so the match+emit logic lives
/// in exactly one place.
#[inline(always)]
pub(crate) fn emit_honeytoken_buf(
    path: &[u8; PATH_LEN],
    path_len: u32,
    flags: u64,
    access_kind: u32,
) {
    if let Some(&token_id) = unsafe { HONEYTOKEN_PATHS.get(path) } {
        if let Some(mut entry) = HONEYTOKEN_ACCESS_EVENTS.reserve::<HoneytokenAccessEvent>(0) {
            let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let uid_gid = bpf_get_current_uid_gid();
            let comm = [0u8; COMM_LEN];
            let comm = bpf_get_current_comm().unwrap_or(comm);
            let ev = unsafe { entry.assume_init_mut() };
            ev.pid          = pid;
            ev.uid          = (uid_gid & 0xFFFF_FFFF) as u32;
            ev.gid          = (uid_gid >> 32) as u32;
            ev._pad         = 0;
            ev.token_id     = token_id;
            ev.flags        = flags;
            ev.comm         = comm;
            ev.filename     = *path;
            ev.filename_len = path_len;
            ev.access_kind  = access_kind;
            entry.submit(0);
        }
    }
}

/// Read a user-space path string into a bounded, zero-initialised buffer and run
/// it through the honeytoken gate. Used by tracepoints that only have a user
/// pointer to the path (open/openat2/stat/statx/readlink/linkat/unlink/rename).
#[inline(always)]
pub(crate) fn check_honeytoken_user(path_uptr: u64, flags: u64, access_kind: u32) {
    if path_uptr == 0 {
        return;
    }
    let mut path = [0u8; PATH_LEN];
    let written = unsafe {
        bpf_probe_read_user_str_bytes(path_uptr as *const u8, &mut path)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    emit_honeytoken_buf(&path, written as u32, flags, access_kind);
}

/// Honeytoken gate for the `open` family: emit the open access event *and*, if
/// the path is a token file or a token's parent directory, remember it in
/// [`HT_OPEN_PENDING`] so the matching `sys_exit_*` can bind the returned fd.
/// This is the front half of `mmap`/`getdents64` correlation.
#[inline(always)]
pub(crate) fn check_open_honeytoken(path_uptr: u64, flags: u64, access_kind: u32) {
    if path_uptr == 0 {
        return;
    }
    let mut path = [0u8; PATH_LEN];
    let written = unsafe {
        bpf_probe_read_user_str_bytes(path_uptr as *const u8, &mut path)
            .map(|s| s.len())
            .unwrap_or(0)
    };
    emit_honeytoken_buf(&path, written as u32, flags, access_kind);
    stash_open_pending(&path);
}

/// If `path` is a tracked token file or token directory, record a pending fd
/// binding for the current thread. A no-op for everything else.
#[inline(always)]
fn stash_open_pending(path: &[u8; PATH_LEN]) {
    let pid_tgid = bpf_get_current_pid_tgid();
    if let Some(&token_id) = unsafe { HONEYTOKEN_PATHS.get(path) } {
        let v = FdToken { token_id, kind: FD_KIND_FILE, _pad: 0 };
        let _ = HT_OPEN_PENDING.insert(&pid_tgid, &v, 0);
    } else if let Some(&token_id) = unsafe { HONEYTOKEN_DIRS.get(path) } {
        let v = FdToken { token_id, kind: FD_KIND_DIR, _pad: 0 };
        let _ = HT_OPEN_PENDING.insert(&pid_tgid, &v, 0);
    }
}

/// Back half of the correlation: on the exit of a token `open`, bind the
/// returned fd to the pending token. Shared by every `sys_exit_open*` variant.
#[inline(always)]
fn resolve_open_exit(ctx: &TracePointContext) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let Some(tok) = (unsafe { HT_OPEN_PENDING.get(&pid_tgid) }).copied() else {
        return;
    };
    // Consume the pending slot regardless of the syscall's outcome.
    let _ = HT_OPEN_PENDING.remove(&pid_tgid);
    let ret: i64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return,
    };
    if ret < 0 {
        return; // open failed — no fd to track
    }
    let tgid = (pid_tgid >> 32) & 0xFFFF_FFFF;
    let key = (tgid << 32) | (ret as u64 & 0xFFFF_FFFF);
    let _ = HONEYTOKEN_FDS.insert(&key, &tok, 0);
}

/// Look the current thread's `fd` up in [`HONEYTOKEN_FDS`] and, when it points at
/// a token of the wanted `kind`, emit an access event. Used by `mmap` (file fd)
/// and `getdents64` (dir fd).
#[inline(always)]
fn lookup_fd_and_emit(fd_raw: u64, want_kind: u32, access_kind: u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) & 0xFFFF_FFFF;
    let key = (tgid << 32) | (fd_raw & 0xFFFF_FFFF);
    if let Some(tok) = (unsafe { HONEYTOKEN_FDS.get(&key) }).copied() {
        if tok.kind == want_kind {
            emit_honeytoken_token(tok.token_id, access_kind);
        }
    }
}

/// Emit an access event identified only by `token_id` (no path on hand). The
/// userspace consumer resolves the path from its `token_id → path` index, so the
/// empty `filename` here is fine.
#[inline(always)]
fn emit_honeytoken_token(token_id: u64, access_kind: u32) {
    if let Some(mut entry) = HONEYTOKEN_ACCESS_EVENTS.reserve::<HoneytokenAccessEvent>(0) {
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let uid_gid = bpf_get_current_uid_gid();
        let comm = [0u8; COMM_LEN];
        let comm = bpf_get_current_comm().unwrap_or(comm);
        let ev = unsafe { entry.assume_init_mut() };
        ev.pid          = pid;
        ev.uid          = (uid_gid & 0xFFFF_FFFF) as u32;
        ev.gid          = (uid_gid >> 32) as u32;
        ev._pad         = 0;
        ev.token_id     = token_id;
        ev.flags        = 0;
        ev.comm         = comm;
        ev.filename     = [0u8; PATH_LEN];
        ev.filename_len = 0;
        ev.access_kind  = access_kind;
        entry.submit(0);
    }
}

/// Honeytoken check for `mmap`: if the mapped fd points at a token file, the
/// attacker is reading the bait's contents through a memory mapping. Called from
/// `mmap.rs` before its own (orthogonal) suspicious-mapping filter.
///
///   offset 48 │ u64  arg4  fd   (−1 for an anonymous mapping)
#[inline(always)]
pub(crate) fn check_mmap_honeytoken(ctx: &TracePointContext) {
    let fd_raw: u64 = match unsafe { ctx.read_at(48) } {
        Ok(v) => v,
        Err(_) => return,
    };
    if (fd_raw as i64) < 0 {
        return; // anonymous mapping — no backing fd
    }
    lookup_fd_and_emit(fd_raw, FD_KIND_FILE, ACCESS_MMAP);
}

// ── openat(2) — primary file-open telemetry + honeytoken gate ────────────────

/// Tracepoint: syscalls/sys_enter_openat
///
/// Record layout (sys_enter_openat, x86_64):
///   offset  8 │ i32  __syscall_nr  (4 bytes + 4 pad)
///   offset 16 │ u64  arg0  dfd
///   offset 24 │ u64  arg1  filename  ← user pointer to path string
///   offset 32 │ u64  arg2  flags
///   offset 40 │ u64  arg3  mode
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_file_open(&ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_file_open(ctx: &TracePointContext) -> Result<(), i64> {
    let filename_uptr: u64 = unsafe { ctx.read_at(24).map_err(|_| -1i64)? };
    if filename_uptr == 0 {
        return Ok(());
    }
    let flags: u64 = unsafe { ctx.read_at(32).map_err(|_| -1i64)? };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    let comm = [0u8; COMM_LEN];
    let comm = bpf_get_current_comm().unwrap_or(comm);

    // Read the path once, into a zero-initialised buffer, so the trailing bytes
    // are deterministic and the HONEYTOKEN_PATHS key matches the NUL-padded key
    // userspace inserts. We do this for *every* open (including read-only) — the
    // cost is one bounded string copy plus a hash lookup; an event is only ever
    // emitted on a (rare) honeytoken hit, so volume does not increase.
    let mut path = [0u8; PATH_LEN];
    let written = unsafe {
        bpf_probe_read_user_str_bytes(filename_uptr as *const u8, &mut path)
            .map(|s| s.len())
            .unwrap_or(0)
    };

    // ── Honeytoken gate (fires regardless of flags) ──────────────────────────
    emit_honeytoken_buf(&path, written as u32, flags, ACCESS_OPENAT);
    // Remember a token file/dir open so the matching sys_exit_openat can bind
    // the returned fd for mmap/getdents correlation.
    stash_open_pending(&path);

    // ── Normal file-open telemetry (unchanged read-only suppression) ─────────
    // O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200 – skip pure read-only opens to
    // reduce volume; read-only tracking can be re-enabled via a BPF config map later.
    const O_WRONLY: u64 = 1;
    const O_RDWR: u64 = 2;
    const O_CREAT: u64 = 0x40;
    const O_TRUNC: u64 = 0x200;
    if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) == 0 {
        return Ok(());
    }

    let mut entry = FILE_OPEN_EVENTS.reserve::<FileOpenEvent>(0).ok_or(-1i64)?;
    let ev = unsafe { entry.assume_init_mut() };
    ev.pid = pid;
    ev.uid = uid;
    ev.gid = gid;
    ev.flags = flags;
    ev.comm = comm;
    ev.filename = path;
    ev.filename_len = written as u32;

    entry.submit(0);
    Ok(())
}

// ── open(2) — legacy open, no dirfd (honeytoken gate only) ───────────────────

/// Tracepoint: syscalls/sys_enter_open
///
///   offset 16 │ u64  arg0  filename  ← user pointer
///   offset 24 │ u64  arg1  flags
///   offset 32 │ u64  arg2  mode
///
/// `open(2)` does not exist on every architecture (arm64 routes everything
/// through `openat`), so userspace attaches this best-effort.
#[tracepoint]
pub fn sys_enter_open(ctx: TracePointContext) -> u32 {
    let filename_uptr: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let flags: u64 = unsafe { ctx.read_at(24) }.unwrap_or(0);
    check_open_honeytoken(filename_uptr, flags, ACCESS_OPEN);
    0
}

// ── openat2(2) — modern open, flags live in a struct open_how ────────────────

/// Tracepoint: syscalls/sys_enter_openat2
///
///   offset 16 │ u64  arg0  dfd
///   offset 24 │ u64  arg1  filename  ← user pointer
///   offset 32 │ u64  arg2  how       ← user pointer to `struct open_how`
///   offset 40 │ u64  arg3  usize
///
/// `struct open_how` begins with `__u64 flags`, so we read the first 8 bytes of
/// `how` to recover the open flags. openat2 is kernel ≥ 5.6, so attach is
/// best-effort.
#[tracepoint]
pub fn sys_enter_openat2(ctx: TracePointContext) -> u32 {
    let filename_uptr: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let how_uptr: u64 = unsafe { ctx.read_at(32) }.unwrap_or(0);
    let flags: u64 = if how_uptr != 0 {
        unsafe { bpf_probe_read_user(how_uptr as *const u64).unwrap_or(0) }
    } else {
        0
    };
    check_open_honeytoken(filename_uptr, flags, ACCESS_OPENAT2);
    0
}

// ── Metadata recon: stat / statx / readlink on a token path ──────────────────

/// Tracepoint: syscalls/sys_enter_newfstatat (the syscall glibc `stat()`/`lstat()`
/// and `ls -l` issue).
///
///   offset 16 │ u64  arg0  dfd
///   offset 24 │ u64  arg1  pathname  ← user pointer
#[tracepoint]
pub fn sys_enter_newfstatat(ctx: TracePointContext) -> u32 {
    let pathname_uptr: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    check_honeytoken_user(pathname_uptr, 0, ACCESS_STAT);
    0
}

/// Tracepoint: syscalls/sys_enter_statx (kernel ≥ 4.11; newer glibc `stat`).
///
///   offset 16 │ u64  arg0  dfd
///   offset 24 │ u64  arg1  pathname  ← user pointer
#[tracepoint]
pub fn sys_enter_statx(ctx: TracePointContext) -> u32 {
    let pathname_uptr: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    check_honeytoken_user(pathname_uptr, 0, ACCESS_STATX);
    0
}

/// Tracepoint: syscalls/sys_enter_readlinkat (the syscall `readlink()` uses).
///
///   offset 16 │ u64  arg0  dfd
///   offset 24 │ u64  arg1  pathname  ← user pointer
#[tracepoint]
pub fn sys_enter_readlinkat(ctx: TracePointContext) -> u32 {
    let pathname_uptr: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    check_honeytoken_user(pathname_uptr, 0, ACCESS_READLINK);
    0
}

// ── Hardlink evasion: a hardlink is created *to* a token ──────────────────────

/// Tracepoint: syscalls/sys_enter_linkat
///
///   offset 16 │ u64  arg0  olddfd
///   offset 24 │ u64  arg1  oldname   ← user pointer (the existing token)
///   offset 32 │ u64  arg2  newdfd
///   offset 40 │ u64  arg3  newname   ← user pointer (the new link)
///   offset 48 │ u64  arg4  flags
///
/// Creating a second name for the token's inode is a classic attempt to read its
/// content later through a path our gate does not watch. We cannot see that
/// later read by path, but we *can* flag the link creation itself.
#[tracepoint]
pub fn sys_enter_linkat(ctx: TracePointContext) -> u32 {
    let oldname_uptr: u64 = match unsafe { ctx.read_at(24) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    check_honeytoken_user(oldname_uptr, 0, ACCESS_LINK);
    0
}

// ── fd correlation: bind a token open's returned fd, then catch mmap/getdents ─

/// Tracepoint: syscalls/sys_exit_openat — bind the fd a token openat returned.
///
///   offset 16 │ i64  ret   (the new fd, or a negative errno)
#[tracepoint]
pub fn sys_exit_openat(ctx: TracePointContext) -> u32 {
    resolve_open_exit(&ctx);
    0
}

/// Tracepoint: syscalls/sys_exit_open (legacy open; best-effort attach).
#[tracepoint]
pub fn sys_exit_open(ctx: TracePointContext) -> u32 {
    resolve_open_exit(&ctx);
    0
}

/// Tracepoint: syscalls/sys_exit_openat2 (kernel ≥ 5.6; best-effort attach).
#[tracepoint]
pub fn sys_exit_openat2(ctx: TracePointContext) -> u32 {
    resolve_open_exit(&ctx);
    0
}

/// Tracepoint: syscalls/sys_enter_getdents64 — a directory is being listed.
/// If the fd points at a token's parent directory, flag it as recon
/// ("someone combed the directory").
///
///   offset 16 │ u64  arg0  fd
#[tracepoint]
pub fn sys_enter_getdents64(ctx: TracePointContext) -> u32 {
    let fd_raw: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    lookup_fd_and_emit(fd_raw, FD_KIND_DIR, ACCESS_GETDENTS);
    0
}

/// Tracepoint: syscalls/sys_enter_close — drop any fd binding so a reused fd
/// number cannot later produce a false mmap/getdents hit.
///
///   offset 16 │ u64  arg0  fd
#[tracepoint]
pub fn sys_enter_close(ctx: TracePointContext) -> u32 {
    let fd_raw: u64 = match unsafe { ctx.read_at(16) } {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) & 0xFFFF_FFFF;
    let key = (tgid << 32) | (fd_raw & 0xFFFF_FFFF);
    let _ = HONEYTOKEN_FDS.remove(&key);
    0
}
