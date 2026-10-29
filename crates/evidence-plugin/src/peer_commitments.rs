//! The commitments this node holds for its peers (loop step 7, Ask,
//! acceptance item 4): the last one `mesh_commitment_fetch` fetched from
//! each peer that passed every check, so an ask can be judged against what
//! the peer advertised. A refusal carries no policy digest; what is checked
//! is the refusal against the policy the peer's commitment pins (Sherlock2,
//! Mesh-LLM/capsules-plugin#56).
//!
//! **Where.** `<data_dir>/`[`DIR`]`/<peer id>.json`, the frame as fetched
//! (`commitment::Signed::to_wire`). A later passing fetch replaces it. It is
//! never served.
//!
//! **What an ask records** ([`pinned`]): the digest of the held commitment
//! (SHA-256 of its JCS), the policy digest it pins and that policy's body,
//! in the `evidence_request` record (`crate::ask_book`), so a later fetch
//! never changes what the ask is judged against.
//!
//! **The check** ([`policy_check`]) on a signed refusal:
//! - `NOT_CHECKED` when no commitment was held at ask time;
//! - `MATCH` when the pinned policy allows the refusal: its reason is not a
//!   policy reason, or the commitment does not answer the subject form;
//! - `MISMATCH` when the policy answers it to a stranger (`stranger_safe`)
//!   and the refusal withholds it by policy;
//! - `NOT_CHECKED` otherwise: whether the peer answers depends on who asks,
//!   which the policy alone does not settle.

use std::path::{Path, PathBuf};

use evidence_request::registry::Reason;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::commitment::{self, Signed};

/// The directory under the data directory.
pub const DIR: &str = "peer-commitments";

/// The refusal reasons that say the peer withheld by policy.
const POLICY_REASONS: [Reason; 3] = [
    Reason::NotAuthorized,
    Reason::PolicyDeclined,
    Reason::DerivationUnsupported,
];

fn path(data_dir: &Path, peer_id: &str) -> Option<PathBuf> {
    // A mesh id is lowercase hex: nothing else names a file here.
    (!peer_id.is_empty()
        && peer_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
    .then(|| data_dir.join(DIR).join(format!("{peer_id}.json")))
}

/// Hold `frame`, a commitment fetched from `peer_id` that passed every
/// check, in place of any held before.
pub fn hold(data_dir: &Path, peer_id: &str, frame: &Value) -> std::io::Result<()> {
    let path = path(data_dir, peer_id).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a mesh peer id")
    })?;
    std::fs::create_dir_all(path.parent().expect("under DIR"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(frame)?)?;
    std::fs::rename(tmp, path)
}

/// What an ask of `peer_id` records of the commitment held for it:
/// `{digest, policy_digest, policy, subjects}`. `None` when none is held, or
/// the held one no longer checks or names another node.
pub fn pinned(data_dir: &Path, peer_id: &str) -> Option<Value> {
    let bytes = std::fs::read(path(data_dir, peer_id)?).ok()?;
    let signed = Signed::from_wire(&serde_json::from_slice(&bytes).ok()?).ok()?;
    if !commitment::verify(&signed).is_empty() || signed.commitment["node_id"] != peer_id {
        return None;
    }
    let policy: Value = serde_json::from_slice(&signed.policy).ok()?;
    Some(json!({
        "digest": hex::encode(Sha256::digest(evidence_request::jcs::to_string(&signed.commitment).ok()?)),
        "policy_digest": signed.commitment.pointer("/lcap/policy_digest")?,
        "policy": policy.get("policy")?,
        "subjects": signed.commitment.pointer("/answers/subjects")?,
    }))
}

/// The check of a signed refusal of `request` for `reason` against the
/// commitment `pinned` at ask time (see the module doc).
pub fn policy_check(pinned: Option<&Value>, request: &Value, reason: &str) -> Value {
    let Some(pinned) = pinned else {
        return json!({"status": "NOT_CHECKED", "why": "no commitment held for the peer"});
    };
    let status = |status: &str, why: &str| json!({"status": status, "why": why, "policy_digest": pinned["policy_digest"]});
    let by_policy = POLICY_REASONS.iter().any(|r| r.token() == reason);
    if !by_policy {
        return status("MATCH", "the refusal is not a policy decision");
    }
    let Some(form) = subject_form(request) else {
        return status("NOT_CHECKED", "the request names no subject form");
    };
    let answered = pinned["subjects"]
        .as_array()
        .is_some_and(|s| s.iter().any(|f| f == form));
    if !answered {
        return status("MATCH", "the commitment does not answer this subject form");
    }
    let stranger_safe = pinned
        .pointer("/policy/stranger_safe")
        .and_then(Value::as_array)
        .is_some_and(|safe| {
            let asked = match request.get("derivation").and_then(Value::as_str) {
                Some(derivation) if form == "full_history" => derivation,
                None if form == "checkpoints" => "checkpoints",
                _ => return false,
            };
            safe.iter().any(|s| s == asked)
        });
    if stranger_safe {
        return status(
            "MISMATCH",
            "the pinned policy answers this to any asker, and the refusal withholds it by policy",
        );
    }
    status(
        "NOT_CHECKED",
        "whether this is answered depends on who asks",
    )
}

/// The request's subject form token (`full_history`, `checkpoints`, ...).
fn subject_form(request: &Value) -> Option<&str> {
    let subject = request.get("subject")?.as_object()?;
    (subject.len() == 1)
        .then(|| subject.keys().next().map(String::as_str))
        .flatten()
}

#[cfg(test)]
mod tests;
