//! Synchronous Linux inventory helpers run on the blocking pool. Keep one
//! bounded pipe and a deadline covering both output and child termination.
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::{net::UnixStream, process::CommandExt};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

pub(crate) fn capture(
    cmd: &mut Command,
    limit: usize,
    timeout: Duration,
) -> io::Result<(ExitStatus, Vec<u8>)> {
    let (mut reader, writer) = UnixStream::pair()?;
    reader.set_read_timeout(Some(Duration::from_millis(100)))?;
    let mut child = cmd
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::null())
        .spawn()?;
    // Command retains its configured pipe after spawn.
    cmd.stdout(Stdio::null());
    let started = Instant::now();
    let result = (|| {
        let mut output = Vec::new();
        let mut chunk = [0; 8192];
        let mut eof = false;
        while started.elapsed() < timeout {
            if eof {
                if let Some(status) = child.try_wait()? {
                    return Ok((status, output));
                }
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            match reader.read(&mut chunk) {
                Ok(0) => eof = true,
                Ok(n) if n <= limit.saturating_sub(output.len()) => {
                    output.extend_from_slice(&chunk[..n])
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "inventory command exceeded output limit",
                    ))
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "inventory command exceeded deadline",
        ))
    })();
    if result.is_err() {
        // We have not reaped the child on an error path. Its group ID cannot
        // have been reused by another process.
        if let Ok(pid) = i32::try_from(child.id()) {
            if pid > 1 {
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_and_output_cap_are_distinct_failures() {
        let err = capture(
            Command::new("sleep").arg("5"),
            100,
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let err =
            capture(Command::new("printf").arg("abc"), 2, Duration::from_secs(2)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let (status, out) =
            capture(Command::new("printf").arg("abc"), 3, Duration::from_secs(2)).unwrap();
        assert!(status.success());
        assert_eq!(out, b"abc");
    }
}
