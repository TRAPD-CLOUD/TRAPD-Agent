//! Build helper for trapd-agent.
//!
//! Usage:
//!   cargo xtask build-ebpf [--release]
//!
//! Requirements:
//!   cargo binstall bpf-linker
//!
//! The nightly toolchain and rust-src component are pinned by
//! `trapd-agent-ebpf/rust-toolchain.toml` and installed automatically by
//! rustup when the eBPF crate is built.

mod release;

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
        Some("sign-release") => sign_release(&args[2..]),
        Some("release-keygen") => release_keygen(),
        _ => usage(),
    }
}

/// `cargo xtask sign-release --version V --os O --arch A --tag T --asset-name N
/// --file PATH` — prints one `{"payload","signature"}` JSON line. The key comes
/// from the `RELEASE_SIGNING_KEY` environment variable (base64 32-byte seed),
/// never from a CLI argument, so it cannot leak through process listings or CI
/// command logs.
fn sign_release(args: &[String]) -> ExitCode {
    let get = |name: &str| -> Option<&str> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let (Some(version), Some(os), Some(arch), Some(tag), Some(asset), Some(file)) = (
        get("--version"),
        get("--os"),
        get("--arch"),
        get("--tag"),
        get("--asset-name"),
        get("--file"),
    ) else {
        return usage();
    };
    let result = (|| -> Result<String, String> {
        let seed = env::var("RELEASE_SIGNING_KEY")
            .map_err(|_| "RELEASE_SIGNING_KEY is not set".to_string())?;
        let key = release::signing_key(&seed)?;
        let bytes = std::fs::read(file).map_err(|e| format!("read {file}: {e}"))?;
        // Optional companion: both flags or neither.
        let ebpf = match (get("--ebpf-asset-name"), get("--ebpf-file")) {
            (Some(name), Some(path)) => Some((
                name,
                std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?,
            )),
            (None, None) => None,
            _ => return Err("--ebpf-asset-name and --ebpf-file must be given together".into()),
        };
        let payload = release::statement(&release::Artifact {
            version,
            os,
            arch,
            tag,
            asset_name: asset,
            bytes: &bytes,
            ebpf: ebpf.as_ref().map(|(n, b)| (*n, b.as_slice())),
        })?;
        let signature = release::sign(&key, &payload);
        Ok(serde_json::json!({ "payload": payload, "signature": signature }).to_string())
    })();
    match result {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `cargo xtask release-keygen` — one-time, run offline. Prints the secret seed
/// (store it as the `RELEASE_SIGNING_KEY` secret, nowhere else) and the public
/// key (provision it to agents as `TRAPD_RELEASE_PUBKEY_B64` and to the backend
/// as `TRAPD_RELEASE_SIGNING_PUBKEY`).
fn release_keygen() -> ExitCode {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut seed = [0u8; 32];
    if let Err(e) = getrandom::fill(&mut seed) {
        eprintln!("error: no randomness available: {e}");
        return ExitCode::FAILURE;
    }
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    println!("RELEASE_SIGNING_KEY (secret) = {}", STANDARD.encode(seed));
    println!(
        "public key (base64)          = {}",
        STANDARD.encode(key.verifying_key().to_bytes())
    );
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!(
        "Usage:\n  cargo xtask build-ebpf [--release]\n  \
         cargo xtask sign-release --version V --os O --arch A --tag T \\\n    \
           --asset-name N --file PATH [--ebpf-asset-name N --ebpf-file PATH]\n    \
           (key in $RELEASE_SIGNING_KEY)\n  \
         cargo xtask release-keygen\n\n\
         Requirements:\n  \
           cargo binstall bpf-linker\n  \
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
            eprintln!("hint:  cargo binstall bpf-linker");
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
