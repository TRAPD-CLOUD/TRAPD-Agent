//! Load every program in the agent's eBPF object through the kernel verifier
//! without attaching anything. Used by CI to boot older kernels (5.15 LTS) and
//! catch verifier rejections that the runner's own kernel accepts.
//!
//! Usage: ebpf_verifier_check <path-to-trapd-agent-exec>
//! Exit code 0 when every program loads, 1 otherwise. Needs root (or
//! CAP_BPF + CAP_PERFMON) on Linux.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    use aya::programs::Program;
    use aya::Ebpf;
    use std::process::ExitCode;

    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: ebpf_verifier_check <ebpf-object>");
        return ExitCode::from(2);
    };
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let mut bpf = match Ebpf::load(&bytes) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("FAIL object: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = 0usize;
    let mut loaded = 0usize;
    for (name, prog) in bpf.programs_mut() {
        let result = match prog {
            Program::TracePoint(p) => p.load(),
            Program::KProbe(p) => p.load(),
            Program::RawTracePoint(p) => p.load(),
            other => {
                eprintln!(
                    "FAIL {name}: unsupported program type {:?}",
                    other.prog_type()
                );
                failed += 1;
                continue;
            }
        };
        match result {
            Ok(()) => {
                loaded += 1;
                println!("ok   {name}");
            }
            Err(e) => {
                failed += 1;
                // `{:#}` keeps the verifier log that aya attaches to the error.
                println!("FAIL {name}: {e:#}");
                let mut source = std::error::Error::source(&e);
                while let Some(s) = source {
                    println!("     caused by: {s}");
                    source = s.source();
                }
            }
        }
    }
    println!("loaded {loaded}, failed {failed}");
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ebpf_verifier_check only runs on Linux");
}
