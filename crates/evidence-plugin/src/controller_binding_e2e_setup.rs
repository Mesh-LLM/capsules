//! Setup for the controller binding step of the two-node run
//! (`scripts/e2e-two-node.sh`), run by the script while both nodes are up.
//!
//! The provider's operator binds the provider's node key to a Nostr key
//! (AAC Controller Binding §4.1) through `join`'s ceremony: `join` with the
//! operator's key signs the node's half and returns a Nostr event, the
//! operator signs that event ([`sign_event`], standing in for their own
//! Nostr signer, with a test key: [`nostr_key`]), and `join` with the signed
//! event stores the binding. The script also hands `join` a binding of
//! another node's key to the same Nostr key, which `join` must refuse. The
//! requester then fetches the provider's commitment over the mesh
//! (`mesh_commitment_fetch`), and the scenario check (`two_node_e2e`) finds
//! the binding named there by its digest alone.
//!
//! Not under `two_node_e2e::`, so the scenario checks never run it.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use serde_json::Value;
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

fn out_dir() -> PathBuf {
    PathBuf::from(std::env::var("E2E_BINDINGS").expect("E2E_BINDINGS"))
}

/// Writes `controller.txt`, the operator's Nostr public key, and
/// `binding-other.json`, another node's key bound to it, into the directory
/// `E2E_BINDINGS` names.
#[test]
#[ignore = "run by scripts/e2e-two-node.sh"]
fn write_controller() {
    let out = out_dir();
    let nostr = nostr_key();
    std::fs::write(
        out.join("controller.txt"),
        hex::encode(nostr.verifying_key().to_bytes()),
    )
    .unwrap();
    let other = crate::controller_binding::bind_to_nostr_for_test(
        &SigningKey::from_bytes(&seed("another-node")),
        &nostr,
        &hex::encode(&seed("nonce")[..16]),
        FROM,
        UNTIL,
    );
    std::fs::write(out.join("binding-other.json"), other.to_string()).unwrap();
}

/// The operator's signer: reads the event `join` returned
/// (`ceremony-event.json`) and writes it signed (`signed-event.json`), as a
/// NIP-01 signer does: its id over the serialized event, and a BIP-340
/// signature of that id.
#[test]
#[ignore = "run by scripts/e2e-two-node.sh"]
fn sign_event() {
    let out = out_dir();
    let event: Value =
        serde_json::from_slice(&std::fs::read(out.join("ceremony-event.json")).unwrap()).unwrap();
    let event = crate::controller_binding::sign_event_for_test(&nostr_key(), &event);
    std::fs::write(out.join("signed-event.json"), event.to_string()).unwrap();
}
