//! Build helper for trapd-agent.
//!
//! Usage:
//!   cargo xtask build-ebpf [--release]
//!
//! Requirements:
//!   cargo install bpf-linker
//!   rustup install nightly
//!   rustup component add rust-src --toolchain nightly

use std::{
    env,
    path::PathBuf,
    process::{Command, ExitCode},
};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("build-ebpf") => {
            let release = args.iter().any(|a| a == "--release");
            build_ebpf(release)
        }
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "Usage:\n  cargo xtask build-ebpf [--release]\n\n\
         Requirements:\n  \
           cargo install bpf-linker\n  \
           rustup install nightly\n  \
           rustup component add rust-src --toolchain nightly"
    );
    ExitCode::FAILURE
}

fn build_ebpf(release: bool) -> ExitCode {
    let workspace = workspace_root();
    // trapd-agent-ebpf has its own [workspace] and is NOT a member of the root
    // workspace, so we must cd into it before invoking cargo.
    let ebpf_dir = workspace.join("trapd-agent-ebpf");
    let profile = if release { "release" } else { "debug" };

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .args(["+nightly", "build"])
        .args(["--target", "bpfel-unknown-none"])
        .args(["-Z", "build-std=core"]);
    if release {
        cmd.arg("--release");
    }

    eprintln!("==> Building eBPF programs ({profile}) …");

    match cmd.status() {
        Err(e) => {
            eprintln!("error: failed to exec cargo: {e}");
            eprintln!("hint:  cargo install bpf-linker");
            ExitCode::FAILURE
        }
        Ok(s) if !s.success() => {
            eprintln!("error: eBPF build failed (exit {})", s.code().unwrap_or(1));
            ExitCode::FAILURE
        }
        Ok(_) => {
            let out = ebpf_dir
                .join("target/bpfel-unknown-none")
                .join(profile)
                .join("trapd-agent-exec");
            eprintln!("==> eBPF binary: {}", out.display());
            eprintln!("==> Done. Copy to /usr/lib/trapd-agent/ or set TRAPD_EBPF_PATH.");
            ExitCode::SUCCESS
        }
    }
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = xtask/ → parent = workspace root
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p
}
