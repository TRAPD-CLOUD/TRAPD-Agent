//! The local channel between agent and guard.
//!
//! The guard hosts it, the agent connects once per ping (one request, one
//! response, then the connection ends), so a wedged guard shows up as a missing
//! response rather than as a half-open session to be managed.
//!
//!   * Windows: named pipe `\\.\pipe\trapd-guard`, created with the first-instance
//!     flag (a pre-created pipe of the same name makes the guard fail instead of
//!     serving a squatter) and a protected DACL that grants SYSTEM only. Remote
//!     clients are rejected. Both sides additionally compare the OS-reported
//!     peer pid with the pid the SCM reports for the peer's service
//!     (`control::service_pid`).
//!   * Linux: unix socket `/run/trapd/guard.sock`, mode `0600`, in a root-only
//!     runtime directory; the peer's credentials (`SO_PEERCRED`) must be root.
//!
//! Frames are single JSON lines of at most [`MAX_FRAME_BYTES`].

use std::io;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{encode_frame, parse_frame, Ping, Pong, MAX_FRAME_BYTES, PROTOCOL_VERSION};

/// Read one newline-terminated frame (the newline is not returned).
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.iter().position(|b| *b == b'\n') {
            buf.truncate(end);
            return Ok(buf);
        }
        if buf.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    writer.write_all(frame).await?;
    writer.flush().await
}

/// Client side: send `ping`, read and validate the pong.
pub async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    ping: &Ping,
) -> Result<Pong> {
    let bytes = encode_frame(ping)?;
    write_frame(stream, &bytes).await.context("send ping")?;
    let line = read_frame(stream).await.context("read pong")?;
    let pong: Pong = parse_frame(&line)?;
    if pong.v != PROTOCOL_VERSION || pong.seq != ping.seq {
        bail!("unexpected pong");
    }
    Ok(pong)
}

/// Server side: read one ping, let `answer` build the pong, send it.
pub async fn serve<S, F>(stream: &mut S, answer: F) -> Result<Ping>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&Ping) -> Pong,
{
    let line = read_frame(stream).await.context("read ping")?;
    let ping: Ping = parse_frame(&line)?;
    if ping.v != PROTOCOL_VERSION {
        bail!("unsupported protocol version {}", ping.v);
    }
    let pong = answer(&ping);
    write_frame(stream, &encode_frame(&pong)?)
        .await
        .context("send pong")?;
    Ok(ping)
}

/// Bounded `exchange` on a fresh connection; returns the pong and the peer
/// (server) pid as reported by the OS.
pub async fn ping_guard(ping: &Ping, timeout: Duration) -> Result<(Pong, Option<u32>)> {
    tokio::time::timeout(timeout, async {
        let (mut stream, pid) = imp::connect().await.context("connect to the guard")?;
        let pong = exchange(&mut stream, ping).await?;
        Ok((pong, pid))
    })
    .await
    .context("guard did not answer in time")?
}

pub use imp::Listener;

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
    use std::path::Path;

    use tokio::net::{UnixListener, UnixStream};

    pub const SOCKET_PATH: &str = "/run/trapd/guard.sock";

    pub struct Listener {
        inner: UnixListener,
    }

    impl Listener {
        pub fn bind() -> io::Result<Self> {
            Self::bind_at(Path::new(SOCKET_PATH))
        }

        pub fn bind_at(path: &Path) -> io::Result<Self> {
            if let Some(dir) = path.parent() {
                if !dir.exists() {
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .recursive(true)
                        .create(dir)?;
                }
            }
            // Only a stale socket is removed; anything else in the way is an error.
            match std::fs::symlink_metadata(path) {
                Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "a non-socket file is in the way of the guard socket",
                    ))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            let inner = UnixListener::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self { inner })
        }

        /// Next connection and its OS-reported pid. Peers that are not root are
        /// dropped without an answer.
        pub async fn accept(&mut self) -> io::Result<(UnixStream, Option<u32>)> {
            loop {
                let (stream, _) = self.inner.accept().await?;
                match stream.peer_cred() {
                    Ok(cred) if cred.uid() == 0 => {
                        return Ok((stream, cred.pid().and_then(|p| u32::try_from(p).ok())))
                    }
                    _ => continue,
                }
            }
        }
    }

    pub async fn connect() -> io::Result<(UnixStream, Option<u32>)> {
        connect_at(Path::new(SOCKET_PATH)).await
    }

    pub async fn connect_at(path: &Path) -> io::Result<(UnixStream, Option<u32>)> {
        let stream = UnixStream::connect(path).await?;
        let cred = stream.peer_cred()?;
        // Whoever answers on the socket must be root, like its directory.
        if cred.uid() != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "guard socket is served by a non-root process",
            ));
        }
        Ok((stream, cred.pid().and_then(|p| u32::try_from(p).ok())))
    }
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::io;

    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    };

    pub const PIPE_NAME: &str = r"\\.\pipe\trapd-guard";
    /// SYSTEM only, protected. Administrators are deliberately not listed.
    pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)";
    const ERROR_PIPE_BUSY: i32 = 231;

    fn create_instance(first: bool) -> io::Result<NamedPipeServer> {
        let sddl: Vec<u16> = PIPE_SDDL.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated; on success `descriptor` is a
        // LocalAlloc'd buffer freed below after the pipe copied it.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first)
            .reject_remote_clients(true);
        // SAFETY: `attributes` points at a valid descriptor for the duration of the call.
        let result = unsafe {
            options.create_with_security_attributes_raw(
                PIPE_NAME,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        };
        // SAFETY: allocated by the conversion above, not used afterwards.
        unsafe { LocalFree(descriptor) };
        result
    }

    pub struct Listener {
        next: NamedPipeServer,
    }

    impl Listener {
        pub fn bind() -> io::Result<Self> {
            Ok(Self {
                next: create_instance(true)?,
            })
        }

        /// Wait for a client, keep a fresh instance listening, return the
        /// connected one with the client's OS-reported pid.
        pub async fn accept(&mut self) -> io::Result<(NamedPipeServer, Option<u32>)> {
            self.next.connect().await?;
            let fresh = create_instance(false)?;
            let connected = std::mem::replace(&mut self.next, fresh);
            let mut pid = 0u32;
            use std::os::windows::io::AsRawHandle;
            // SAFETY: valid pipe handle owned by `connected`.
            let ok = unsafe { GetNamedPipeClientProcessId(connected.as_raw_handle(), &mut pid) };
            Ok((connected, (ok != 0).then_some(pid)))
        }
    }

    pub async fn connect() -> io::Result<(NamedPipeClient, Option<u32>)> {
        let client = loop {
            match ClientOptions::new().open(PIPE_NAME) {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(e) => return Err(e),
            }
        };
        let mut pid = 0u32;
        use std::os::windows::io::AsRawHandle;
        // SAFETY: valid pipe handle owned by `client`.
        let ok = unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &mut pid) };
        Ok((client, (ok != 0).then_some(pid)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selfprotect::guard::{NoticeKind, StopNotice};

    fn ping(seq: u64) -> Ping {
        Ping {
            v: PROTOCOL_VERSION,
            seq,
            stop: None,
        }
    }

    #[tokio::test]
    async fn a_ping_is_answered_with_a_matching_pong() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move {
            serve(&mut server, |p| Pong {
                v: PROTOCOL_VERSION,
                seq: p.seq,
                pending: true,
                stop: None,
            })
            .await
        });
        let pong = exchange(&mut client, &ping(7)).await.unwrap();
        assert_eq!(pong.seq, 7);
        assert!(pong.pending);
        assert_eq!(srv.await.unwrap().unwrap().seq, 7);
    }

    #[tokio::test]
    async fn a_stop_notice_travels_with_the_ping() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move {
            serve(&mut server, |p| Pong {
                v: PROTOCOL_VERSION,
                seq: p.seq,
                pending: false,
                stop: None,
            })
            .await
        });
        let mut p = ping(1);
        p.stop = Some(StopNotice {
            kind: NoticeKind::HostShutdown,
            marker: None,
        });
        exchange(&mut client, &p).await.unwrap();
        assert_eq!(srv.await.unwrap().unwrap().stop, p.stop);
    }

    #[tokio::test]
    async fn a_pong_for_another_ping_is_rejected() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let _ = serve(&mut server, |p| Pong {
                v: PROTOCOL_VERSION,
                seq: p.seq + 1,
                pending: false,
                stop: None,
            })
            .await;
        });
        assert!(exchange(&mut client, &ping(3)).await.is_err());
    }

    #[tokio::test]
    async fn malformed_oversized_and_unknown_frames_are_refused() {
        for payload in [
            b"not json\n".to_vec(),
            b"{\"v\":1,\"seq\":1,\"extra\":true}\n".to_vec(),
            b"{\"v\":9,\"seq\":1}\n".to_vec(),
            vec![b'a'; MAX_FRAME_BYTES * 2],
        ] {
            let (mut client, mut server) = tokio::io::duplex(16 * 1024);
            let srv = tokio::spawn(async move {
                serve(&mut server, |p| Pong {
                    v: PROTOCOL_VERSION,
                    seq: p.seq,
                    pending: false,
                    stop: None,
                })
                .await
            });
            let _ = client.write_all(&payload).await;
            assert!(
                srv.await.unwrap().is_err(),
                "{:?}",
                &payload[..payload.len().min(20)]
            );
        }
    }

    #[tokio::test]
    async fn a_silent_peer_times_out_instead_of_hanging_the_caller() {
        let (mut client, _server) = tokio::io::duplex(1024);
        let r =
            tokio::time::timeout(Duration::from_millis(100), exchange(&mut client, &ping(1))).await;
        assert!(r.is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_socket_is_private_and_a_non_socket_in_the_way_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("trapd-guard-ipc-{}", uuid::Uuid::new_v4()));
        let path = dir.join("guard.sock");
        let listener = Listener::bind_at(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        drop(listener);
        // A stale socket is replaced; a regular file is not.
        Listener::bind_at(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"x").unwrap();
        assert!(Listener::bind_at(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_round_trip_over_the_socket_reports_the_peer_pid() {
        // Same uid in the test, so only meaningful as root.
        if nix::unistd::geteuid().as_raw() != 0 {
            return;
        }
        let dir = std::env::temp_dir().join(format!("trapd-guard-ipc-{}", uuid::Uuid::new_v4()));
        let path = dir.join("guard.sock");
        let mut listener = Listener::bind_at(&path).unwrap();
        let srv = tokio::spawn(async move {
            let (mut s, pid) = listener.accept().await.unwrap();
            serve(&mut s, |p| Pong {
                v: PROTOCOL_VERSION,
                seq: p.seq,
                pending: false,
                stop: None,
            })
            .await
            .unwrap();
            pid
        });
        let (mut c, server_pid) = imp::connect_at(&path).await.unwrap();
        exchange(&mut c, &ping(1)).await.unwrap();
        assert_eq!(server_pid, Some(std::process::id()));
        assert_eq!(srv.await.unwrap(), Some(std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
