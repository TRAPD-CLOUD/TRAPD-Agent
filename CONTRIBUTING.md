# Contributing to TRAPD Agent

Thank you for helping. Please read this before opening a pull request.

## Security issues

Do not report vulnerabilities in issues or pull requests. Follow [SECURITY.md](SECURITY.md).

## License of contributions

This repository is licensed under the [Apache License 2.0](LICENSE). Under section 5 of that license, a contribution you submit is licensed under the same terms unless you state otherwise. By opening a pull request you confirm that you have the right to submit the code under Apache-2.0.

The server side of TRAPD (`TRAPD-CLOUD/TRAPD`) uses a different license and a Contributor License Agreement. That does not apply to this repository.

## Workflow

- Open the pull request against `main`. Keep it small and focused on one topic.
- Run `cargo fmt`, `cargo clippy` and `cargo test` before pushing. CI runs them on Linux and the Windows build and package checks on pull requests.
- New behavior needs tests. Bug fixes need a regression test where practical.
- Platform code (`cfg(windows)`, `cfg(target_os = "linux")`) must compile on both targets. Do not break the other platform.
- Do not add a dependency without explaining why the existing crates cannot solve the problem. New dependencies must have a compatible license (Apache-2.0, MIT, BSD, ISC or similar permissive).
- Changes to the wire format, signature handling or response actions need a description of the security impact in the pull request.
- Update `CAPABILITIES.md` when a capability changes status.
