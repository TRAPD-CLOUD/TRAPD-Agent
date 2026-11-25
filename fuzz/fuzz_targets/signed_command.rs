#![no_main]

// Arbitrary command batches as the backend (or anyone on the path) could
// deliver them. Properties:
// 1. Decoding never panics.
// 2. Without the signing key nothing verifies, whatever the bytes.
// 3. Canonicalisation is stable: a decoded envelope, once signed, still
//    verifies after another encode/decode round trip.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;

mod paths {
    pub fn write_atomic(_: &std::path::Path, _: &[u8], _: u32) -> anyhow::Result<()> {
        Ok(())
    }
}
#[allow(dead_code)]
#[path = "../../agent/src/prevention/commands.rs"]
mod commands;
#[allow(dead_code)]
#[path = "../../agent/src/prevention/policy.rs"]
mod policy;

use commands::{verify_canonical, SignedCommand};

fuzz_target!(|data: &[u8]| {
    let Ok(batch) = serde_json::from_slice::<Vec<serde_json::Value>>(data) else {
        return;
    };
    let signer = SigningKey::from_bytes(&[7; 32]);
    let key = signer.verifying_key();
    for item in batch {
        let Ok(command) = serde_json::from_value::<SignedCommand>(item) else {
            continue;
        };
        assert!(verify_canonical(&key, &command.envelope, &command.signature).is_err());

        let canonical = serde_json::to_vec(&command.envelope).unwrap();
        let signature =
            base64::engine::general_purpose::STANDARD.encode(signer.sign(&canonical).to_bytes());
        let signed = SignedCommand {
            envelope: command.envelope,
            signature,
        };
        let wire = serde_json::to_vec(&signed).unwrap();
        let again: SignedCommand = serde_json::from_slice(&wire).unwrap();
        assert!(verify_canonical(&key, &again.envelope, &again.signature).is_ok());
    }
});
