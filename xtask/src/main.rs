//! Build helper for trapd-agent.
//!
//! Usage:
//!   cargo xtask build-ebpf [--release]
//!
//! Requirements:
//!   cargo install bpf-linker
//!
//! The nightly toolchain and rust-src component are pinned by
//! `trapd-agent-ebpf/rust-toolchain.toml` and installed automatically by
//! rustup when the eBPF crate is built.

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
         The pinned nightly toolchain + rust-src component are installed\n  \
         automatically from trapd-agent-ebpf/rust-toolchain.toml."
    );
    ExitCode::FAILURE
}

fn build_ebpf(release: bool) -> ExitCode {
    let workspace = workspace_root();
    // trapd-agent-ebpf has its own [workspace] and is NOT a member of the root
    // workspace, so we must cd into it before invoking cargo.
    let ebpf_dir = workspace.join("trapd-agent-ebpf");
    let profile = if release { "release" } else { "debug" };

    // The eBPF crate must build with the nightly pinned in
    // trapd-agent-ebpf/rust-toolchain.toml (for `-Z build-std` + the
    // `bpfel-unknown-none` target).
    let toolchain = pinned_ebpf_toolchain(&ebpf_dir);

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .arg("build")
        .args(["--target", "bpfel-unknown-none"])
        .args(["-Z", "build-std=core"]);
    if release {
        cmd.arg("--release");
    }

    // When this xtask runs through rustup (`cargo xtask …`, or in CI after
    // `dtolnay/rust-toolchain@stable`), rustup exports `RUSTUP_TOOLCHAIN=stable`
    // (and RUSTC/RUSTDOC) into our environment. The child `cargo` would inherit
    // it and pin to stable — OVERRIDING the directory's nightly toolchain file —
    // so `-Z build-std` fails with "the `-Z` flag is only accepted on the
    // nightly channel". We instead pin the child explicitly to the same nightly
    // for BOTH cargo and the `bpf-linker` it spawns; if they resolved to
    // different toolchains, bpf-linker would load a mismatched LLVM and reject
    // the bitcode ("aggregate returns are not supported"). Drop the inherited
    // RUSTC/wrappers so the toolchain's own rustc/rustdoc are used.
    cmd.env_remove("RUSTC")
        .env_remove("RUSTDOC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER");
    match &toolchain {
        Some(tc) => {
            cmd.env("RUSTUP_TOOLCHAIN", tc);
        }
        // No channel parsed: fall back to letting the directory's toolchain
        // file drive resolution (requires the inherited override be cleared).
        None => {
            cmd.env_remove("RUSTUP_TOOLCHAIN");
        }
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
            // trapd-agent-ebpf/.cargo/config.toml redirects target-dir to
            // ../target, so the artifact lands under the workspace target dir,
            // not inside the eBPF crate.
            let out = workspace
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

/// Parse `channel = "…"` from `<ebpf_dir>/rust-toolchain.toml` so we can pin the
/// child cargo (and the bpf-linker it spawns) to the exact same nightly the
/// crate is pinned to. Returns `None` if the file or key is absent.
fn pinned_ebpf_toolchain(ebpf_dir: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(ebpf_dir.join("rust-toolchain.toml")).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("channel") {
            // `channel = "nightly-YYYY-MM-DD"` → extract the quoted value.
            if let Some(start) = rest.find('"') {
                if let Some(end) = rest[start + 1..].find('"') {
                    return Some(rest[start + 1..start + 1 + end].to_string());
                }
            }
        }
    }
    None
}
