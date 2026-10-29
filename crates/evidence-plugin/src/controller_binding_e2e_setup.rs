//! Setup for the controller binding step of the two-node run
//! (`scripts/e2e-two-node.sh`), run by the script while both nodes are up.
//!
//! The provider's operator binds the provider's node key to a Nostr key
//! (AAC Controller Binding §4.1). The Nostr key is a test key ([`nostr_key`]);
//! a real operator signs with their own Nostr signer. The script hands the
//! binding to the provider's `join`, and also a binding of another node's key
//! to the same Nostr key, which `join` must refuse. The requester then fetches
//! the provider's commitment over the mesh (`mesh_commitment_fetch`), and the
//! scenario check (`two_node_e2e`) finds the binding named there by its
//! digest alone.
//!
//! Not under `two_node_e2e::`, so the scenario checks never run it.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const SEED_PREFIX: &str = "capsules-e2e-controller-binding/v1/";
const FROM: &str = "2026-01-01T00:00:00Z";
const UNTIL: &str = "2100-01-01T00:00:00Z";

/// A test key whose secret is SHA-256 of [`SEED_PREFIX`] and `label`.
fn seed(label: &str) -> [u8; 32] {
    Sha256::digest(format!("{SEED_PREFIX}{label}")).into()
}

/// The operator's Nostr key for this run only.
pub(crate) fn nostr_key() -> k256::schnorr::SigningKey {
    k256::schnorr::SigningKey::from_bytes(&seed("operator-nostr")).unwrap()
}

/// Writes `binding.json`, the provider's key bound to [`nostr_key`], and
/// `binding-other.json`, another node's key bound to it, into the directory
/// `E2E_BINDINGS` names, for the node whose data directory
/// `E2E_PROVIDER_DIR` names.
#[test]
#[ignore = "run by scripts/e2e-two-node.sh"]
fn write_bindings() {
    let var = |name: &str| PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("{name}")));
    let pem = std::fs::read_to_string(var("E2E_PROVIDER_DIR").join("keys").join("node-key.pem"))
        .expect("the provider's signing key");
    let provider = capsule_emit_lib::keys::load_signing_key_pem(&pem).unwrap();
    let other = SigningKey::from_bytes(&seed("another-node"));
    let out = var("E2E_BINDINGS");
    for (name, node, nonce) in [
        ("binding.json", &provider, "1"),
        ("binding-other.json", &other, "2"),
    ] {
        let nonce = hex::encode(&seed(&format!("nonce-{nonce}"))[..16]);
        let record = crate::controller_binding::bind_to_nostr_for_test(
            node,
            &nostr_key(),
            &nonce,
            FROM,
            UNTIL,
        );
        std::fs::write(out.join(name), record.to_string()).unwrap();
    }
}
