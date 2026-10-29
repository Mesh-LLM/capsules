//! A controller declaration: the Controller Binding v0 record (AAC
//! `spec/controller-binding-v0.md`, cited as CB), checked as CB §3, §4 and
//! §6 say, so a key the holders of two keys bound together can be accepted
//! in place of a key some host announced for a peer id (D-34).
//!
//! A binding record shows that whoever held each of its two keys signed it,
//! and nothing more (CB §7): never who holds either key. This node uses one
//! only to extend acceptance from a key it already accepts to the other key
//! the same record binds (`peer_keys::accepted_via`), and records that it
//! did. Nothing gates on it beyond that.
//!
//! **What is used.** Only the claim `same_controller_asserted` under
//! `dual_signature/0`, the declaration D-29 names. A record that is
//! malformed, signed by one key, outside its window at the time asked about,
//! or under a method this node does not implement does not apply (CB §6.2).
//! No revocation statement reaches this node on any channel, so revocation
//! is never checked: a binding is used until its window ends (CB §5 and
//! CB-1).
//!
//! **Where it travels.** As the member [`MEMBER`] of a pushed bundle
//! (`record_push_receive`) or of a signed evidence request
//! (`requester_auth`), as the record object itself.
//!
//! **This node's own binding** (loop step 12, Mesh-LLM/capsules-plugin#54).
//! A node holds at most one binding of its own key to its operator's, in
//! [`HELD_FILE`] in the data directory. `join` stores one only when it
//! binds this node's key and applies ([`binds_own`]); `doctor` reports it
//! `bound`, naming the other key, while it still applies, and `unbound`
//! with the reason otherwise.

use ed25519_dalek::{Signature, VerifyingKey};
use evidence_request::time::{parse_utc, UtcTime};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The member a push bundle or a signed request carries a declaration in.
pub const MEMBER: &str = "controller_binding";

/// `binding_version` of every record this document reads (CB §3.1).
pub const VERSION: &str = "controller-binding/0";

/// The one claim this node uses, and its method (CB §3.2).
pub const CLAIM_SAME_CONTROLLER: &str = "same_controller_asserted";
pub const METHOD_DUAL_SIGNATURE: &str = "dual_signature/0";

const CLAIM_DELEGATED_BY: &str = "delegated_by";
const CLAIM_SAME_ORGANIZATION: &str = "same_organization_credentialed";
const METHOD_DUAL_SIGNATURE_CREDENTIAL: &str = "dual_signature_credential/0";

const BASE_MEMBERS: [&str; 10] = [
    "binding_version",
    "claim",
    "method",
    "keys",
    "issued_at",
    "not_before",
    "not_after",
    "revocation",
    "nonce",
    "sigs",
];

/// A CB §6.1 property, in the IP §7.1 vocabulary this node uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    NotChecked,
}

/// What [`evaluate`] found. `signatures` and `window` are `None` when the
/// form failed: CB §6.1 reports no other property then.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// The binding digest (CB §4), when the record without `sigs` has a JCS
    /// form at all.
    pub digest: Option<String>,
    pub form: Status,
    pub signatures: Option<Status>,
    pub window: Option<Status>,
}

/// A binding that applies: its two keys and its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    pub keys: [String; 2],
    pub digest: String,
}

impl Applied {
    /// The other key this binding binds `key` to, when it binds `key`.
    pub fn other(&self, key: &str) -> Option<&str> {
        match &self.keys {
            [a, b] if a == key => Some(b),
            [a, b] if b == key => Some(a),
            _ => None,
        }
    }
}

/// `record` checked at each of `times` (CB §6.1): form, signatures and
/// window. Revocation is not evaluated here (see the module doc).
pub fn evaluate(record: &Value, times: &[UtcTime]) -> Evaluation {
    let digest = signing_input(record).map(|input| hex::encode(Sha256::digest(input)));
    let Some(map) = record.as_object().filter(|map| well_formed(map)) else {
        return Evaluation {
            digest,
            form: Status::Fail,
            signatures: None,
            window: None,
        };
    };
    let signatures = match map["method"].as_str() {
        Some(METHOD_DUAL_SIGNATURE) => {
            if both_signed(map, record) {
                Status::Pass
            } else {
                Status::Fail
            }
        }
        // `dual_signature_credential/0` needs a credential format this
        // revision does not register (CB-3), and an undefined method is
        // one this node cannot check.
        _ => Status::NotChecked,
    };
    let window = match (time(&map["not_before"]), time(&map["not_after"])) {
        (Some(from), Some(until))
            if times
                .iter()
                .all(|t| from.seconds <= t.seconds && t.seconds < until.seconds) =>
        {
            Status::Pass
        }
        _ => Status::Fail,
    };
    Evaluation {
        digest,
        form: Status::Pass,
        signatures: Some(signatures),
        window: Some(window),
    }
}

/// `record`, when it is a `same_controller_asserted` binding under
/// `dual_signature/0` that applies at `at` (CB §6.2): well formed, both keys
/// signed it, and `at` is inside its window.
pub fn applies(record: &Value, at: UtcTime) -> Option<Applied> {
    if record.get("claim").and_then(Value::as_str) != Some(CLAIM_SAME_CONTROLLER) {
        return None;
    }
    let evaluation = evaluate(record, &[at]);
    if evaluation.signatures != Some(Status::Pass) || evaluation.window != Some(Status::Pass) {
        return None;
    }
    let keys = record["keys"].as_array()?;
    Some(Applied {
        keys: [keys[0].as_str()?.to_string(), keys[1].as_str()?.to_string()],
        digest: evaluation.digest?,
    })
}

/// The file in the data directory that holds this node's own binding.
pub const HELD_FILE: &str = "controller-binding.json";

/// This node's own binding as stored, when there is one. A file that does
/// not parse reads as JSON `null`, which [`binds_own`] refuses.
pub fn read_held(data_dir: &std::path::Path) -> Option<Value> {
    let bytes = std::fs::read(data_dir.join(HELD_FILE)).ok()?;
    Some(serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// `record`, when it binds `own_key` and applies at `at` (CB §6.2); why
/// not otherwise, in words a `doctor` finding or a refused `join` carries.
pub fn binds_own(record: &Value, own_key: &str, at: UtcTime) -> Result<Applied, String> {
    let evaluation = evaluate(record, &[at]);
    if evaluation.form != Status::Pass {
        return Err(
            "it is not a well-formed controller binding record (controller-binding/0)".into(),
        );
    }
    if record["claim"].as_str() != Some(CLAIM_SAME_CONTROLLER) {
        return Err(format!("its claim is not {CLAIM_SAME_CONTROLLER}"));
    }
    match evaluation.signatures {
        Some(Status::Pass) => {}
        Some(Status::NotChecked) => {
            return Err(format!(
                "its method {} is one this node does not check",
                record["method"]
            ))
        }
        _ => return Err("its two signatures do not both verify".into()),
    }
    if evaluation.window != Some(Status::Pass) {
        return Err("it is outside its window (not_before to not_after)".into());
    }
    let applied = applies(record, at).ok_or("it does not apply")?;
    if applied.other(own_key).is_none() {
        return Err(format!("it does not bind this node's key {own_key}"));
    }
    Ok(applied)
}

/// Store `record` as this node's own binding, after [`binds_own`].
pub fn store_held(
    data_dir: &std::path::Path,
    record: &Value,
    own_key: &str,
    at: UtcTime,
) -> Result<Applied, String> {
    let applied = binds_own(record, own_key, at)?;
    crate::network_join::write_atomically(&data_dir.join(HELD_FILE), record)
        .map_err(|e| format!("the binding could not be stored: {e}"))?;
    Ok(applied)
}

/// CB §4: UTF-8 of JCS of the record with `sigs` removed.
fn signing_input(record: &Value) -> Option<Vec<u8>> {
    let mut covered = record.as_object()?.clone();
    covered.remove("sigs");
    evidence_request::jcs::to_string(&Value::Object(covered))
        .ok()
        .map(String::into_bytes)
}

/// CB §3.1 and §3.2: exactly the members of the record's claim type, each
/// in its form. `sigs` need only be an array here; what it holds is the
/// signatures property.
fn well_formed(map: &Map<String, Value>) -> bool {
    let claim = map.get("claim").and_then(Value::as_str);
    let (added, method_for_claim): (&[&str], &str) = match claim {
        Some(CLAIM_SAME_CONTROLLER) => (&[], METHOD_DUAL_SIGNATURE),
        Some(CLAIM_DELEGATED_BY) => (&["delegator"], METHOD_DUAL_SIGNATURE),
        Some(CLAIM_SAME_ORGANIZATION) => (&["credential"], METHOD_DUAL_SIGNATURE_CREDENTIAL),
        _ => return false,
    };
    if map.len() != BASE_MEMBERS.len() + added.len()
        || !BASE_MEMBERS
            .iter()
            .chain(added)
            .all(|k| map.contains_key(*k))
    {
        return false;
    }
    if map["binding_version"].as_str() != Some(VERSION) {
        return false;
    }
    // A method §3.2 defines for another claim type is malformed; one it does
    // not define at all is well formed and not checked.
    match map["method"].as_str() {
        Some(m) if m == method_for_claim => {}
        Some(METHOD_DUAL_SIGNATURE | METHOD_DUAL_SIGNATURE_CREDENTIAL) | None => return false,
        Some(_) => {}
    }
    let keys: Vec<&str> = match map["keys"].as_array() {
        Some(keys) if keys.len() == 2 => keys.iter().filter_map(Value::as_str).collect(),
        _ => return false,
    };
    if keys.len() != 2 || !keys.iter().all(|k| is_key(k)) || keys[0] >= keys[1] {
        return false;
    }
    let (Some(issued), Some(from), Some(until)) = (
        time(&map["issued_at"]),
        time(&map["not_before"]),
        time(&map["not_after"]),
    ) else {
        return false;
    };
    if from.seconds > issued.seconds || until.seconds <= issued.seconds {
        return false;
    }
    if !map["revocation"].is_string() || !map["nonce"].is_string() || !map["sigs"].is_array() {
        return false;
    }
    match claim {
        Some(CLAIM_DELEGATED_BY) => map["delegator"].as_str().is_some_and(|d| keys.contains(&d)),
        Some(CLAIM_SAME_ORGANIZATION) => map["credential"].as_object().is_some_and(|c| {
            c.len() == 3
                && c.get("issuer").and_then(Value::as_str).is_some_and(is_key)
                && c.get("method").is_some_and(Value::is_string)
                && c.get("digest").and_then(Value::as_str).is_some_and(is_key)
        }),
        _ => true,
    }
}

/// CB §4: exactly two entries `{key_id, sig}`, naming `keys` in order, each
/// verifying over the signing input.
fn both_signed(map: &Map<String, Value>, record: &Value) -> bool {
    let (Some(keys), Some(sigs), Some(input)) = (
        map["keys"].as_array(),
        map["sigs"].as_array(),
        signing_input(record),
    ) else {
        return false;
    };
    sigs.len() == 2
        && sigs.iter().zip(keys).all(|(entry, key)| {
            let Some(entry) = entry.as_object().filter(|e| e.len() == 2) else {
                return false;
            };
            entry.get("key_id") == Some(key) && verifies(key, entry.get("sig"), &input)
        })
}

fn verifies(key: &Value, sig: Option<&Value>, input: &[u8]) -> bool {
    let key = key
        .as_str()
        .and_then(|k| hex::decode(k).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok());
    let sig = sig
        .and_then(Value::as_str)
        .filter(|s| is_lower_hex(s, 128))
        .and_then(|s| hex::decode(s).ok())
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .map(|b| Signature::from_bytes(&b));
    match (key, sig) {
        (Some(key), Some(sig)) => key.verify_strict(input, &sig).is_ok(),
        _ => false,
    }
}

/// A CB time: RFC 3339 UTC with `Z` and seconds precision (IP §5.2).
fn time(value: &Value) -> Option<UtcTime> {
    let text = value
        .as_str()
        .filter(|t| t.len() == 20 && t.ends_with('Z'))?;
    parse_utc(text)
}

fn is_key(text: &str) -> bool {
    is_lower_hex(text, 64)
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A `same_controller_asserted` binding of `a` and `b`, signed by both,
/// in effect from `not_before` until `not_after`: for tests that need a
/// declaration.
#[cfg(test)]
pub fn bind_for_test(
    a: &ed25519_dalek::SigningKey,
    b: &ed25519_dalek::SigningKey,
    not_before: &str,
    not_after: &str,
) -> Value {
    use ed25519_dalek::Signer;
    let mut pair = [a, b];
    pair.sort_by_key(|k| hex::encode(k.verifying_key().to_bytes()));
    let keys: Vec<String> = pair
        .iter()
        .map(|k| hex::encode(k.verifying_key().to_bytes()))
        .collect();
    let mut record = serde_json::json!({
        "binding_version": VERSION,
        "claim": CLAIM_SAME_CONTROLLER,
        "method": METHOD_DUAL_SIGNATURE,
        "keys": keys,
        "issued_at": not_before,
        "not_before": not_before,
        "not_after": not_after,
        "revocation": "revocation_statement/0",
        "nonce": "test-ceremony",
    });
    let input = signing_input(&record).unwrap();
    let sigs: Vec<Value> = pair
        .iter()
        .map(|k| {
            serde_json::json!({
                "key_id": hex::encode(k.verifying_key().to_bytes()),
                "sig": hex::encode(k.sign(&input).to_bytes()),
            })
        })
        .collect();
    record["sigs"] = Value::Array(sigs);
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn vectors() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vectors/controller-binding-v0/vectors.json");
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
    }

    fn status(s: Status) -> &'static str {
        match s {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::NotChecked => "NOT_CHECKED",
        }
    }

    /// AAC's Controller Binding v0 corpus, copied verbatim: every case's
    /// binding digest, form, and, for the two claim types whose method this
    /// node implements, its signatures and window, as the corpus states
    /// them. The window is asked at each half's `issued_at` (CB §6.1).
    /// Revocation and the credential are not evaluated (module doc), so
    /// their properties are not compared.
    #[test]
    fn the_aac_vectors_evaluate_as_stated() {
        let corpus = vectors();
        let cases = corpus["cases"].as_array().unwrap();
        assert_eq!(cases.len(), corpus["count"].as_u64().unwrap() as usize);
        let mut compared = 0;
        for case in cases {
            let id = case["id"].as_str().unwrap();
            let binding: Value =
                serde_json::from_str(case["inputs"]["binding"]["octets_text"].as_str().unwrap())
                    .unwrap();
            let times: Vec<UtcTime> = case["inputs"]["halves"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| {
                    let half: Value =
                        serde_json::from_str(h["octets_text"].as_str().unwrap()).unwrap();
                    parse_utc(half["issued_at"].as_str().unwrap()).unwrap()
                })
                .collect();
            let expected = &case["expected"]["binding"];
            let got = evaluate(&binding, &times);
            assert_eq!(
                got.digest.as_deref(),
                expected["binding_digest"].as_str(),
                "{id}: digest"
            );
            let props = &expected["properties"];
            assert_eq!(
                status(got.form),
                props["controller_binding_form"],
                "{id}: form"
            );
            if got.form == Status::Fail {
                assert!(props.get("controller_binding_signatures").is_none(), "{id}");
                continue;
            }
            if binding["claim"] == CLAIM_SAME_ORGANIZATION {
                assert_eq!(got.signatures, Some(Status::NotChecked), "{id}");
                continue;
            }
            assert_eq!(
                status(got.signatures.unwrap()),
                props["controller_binding_signatures"],
                "{id}: signatures"
            );
            assert_eq!(
                status(got.window.unwrap()),
                props["controller_binding_window"],
                "{id}: window"
            );
            compared += 1;
        }
        assert!(compared >= 8, "only {compared} cases compared in full");
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn at(t: &str) -> UtcTime {
        parse_utc(t).unwrap()
    }

    const FROM: &str = "2026-10-01T00:00:00Z";
    const UNTIL: &str = "2027-10-01T00:00:00Z";

    #[test]
    fn a_dual_signed_same_controller_binding_applies_inside_its_window_only() {
        let (a, b) = (key(1), key(2));
        let record = bind_for_test(&a, &b, FROM, UNTIL);
        let applied = applies(&record, at("2026-10-28T00:00:00Z")).expect("applies");
        let ka = hex::encode(a.verifying_key().to_bytes());
        let kb = hex::encode(b.verifying_key().to_bytes());
        assert_eq!(applied.other(&ka), Some(kb.as_str()));
        assert_eq!(applied.other(&kb), Some(ka.as_str()));
        assert_eq!(applied.other(&"0".repeat(64)), None);
        assert!(
            applies(&record, at("2026-09-30T23:59:59Z")).is_none(),
            "before"
        );
        assert!(
            applies(&record, at(UNTIL)).is_none(),
            "not_after is excluded"
        );
    }

    #[test]
    fn a_binding_that_does_not_apply_is_not_used() {
        let (a, b) = (key(1), key(2));
        let now = at("2026-10-28T00:00:00Z");
        let good = bind_for_test(&a, &b, FROM, UNTIL);

        let mut one_signed = good.clone();
        one_signed["sigs"].as_array_mut().unwrap().pop();
        let mut swapped = good.clone();
        swapped["sigs"].as_array_mut().unwrap().swap(0, 1);
        let mut resigned_by_one = good.clone();
        resigned_by_one["sigs"][1] = resigned_by_one["sigs"][0].clone();
        let mut other_method = good.clone();
        other_method["method"] = "dual_signature_v2/0".into();
        let mut delegated = good.clone();
        delegated["claim"] = CLAIM_DELEGATED_BY.into();
        let mut extra = good.clone();
        extra["note"] = "x".into();
        let mut changed = good.clone();
        changed["not_after"] = "2030-01-01T00:00:00Z".into();
        let mut fractional = good.clone();
        fractional["issued_at"] = "2026-10-01T00:00:00.5Z".into();

        for (why, record) in [
            ("one signature", one_signed),
            ("signatures out of key order", swapped),
            ("one key twice", resigned_by_one),
            ("a method this node does not implement", other_method),
            ("another claim", delegated),
            ("an unknown member", extra),
            ("a member changed after signing", changed),
            ("a time outside its form", fractional),
            ("not an object", Value::Array(vec![])),
        ] {
            assert!(applies(&record, now).is_none(), "{why}");
        }
    }

    /// `join` stores a binding of this node's key that applies, and a
    /// refused one leaves the binding already held in place.
    #[test]
    fn only_a_binding_of_this_nodes_key_that_applies_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let (node, operator, other) = (key(1), key(2), key(3));
        let own = hex::encode(node.verifying_key().to_bytes());
        let now = at("2026-10-28T00:00:00Z");
        assert_eq!(read_held(dir.path()), None);

        let good = bind_for_test(&node, &operator, FROM, UNTIL);
        let applied = store_held(dir.path(), &good, &own, now).expect("stored");
        assert_eq!(
            applied.other(&own),
            Some(hex::encode(operator.verifying_key().to_bytes()).as_str())
        );
        assert_eq!(read_held(dir.path()), Some(good.clone()));

        let mut unsigned = bind_for_test(&node, &other, FROM, UNTIL);
        unsigned["sigs"] = Value::Array(vec![]);
        for record in [bind_for_test(&other, &operator, FROM, UNTIL), unsigned] {
            assert!(store_held(dir.path(), &record, &own, now).is_err());
            assert_eq!(read_held(dir.path()), Some(good.clone()), "kept");
        }

        std::fs::write(dir.path().join(HELD_FILE), b"not json").unwrap();
        assert_eq!(read_held(dir.path()), Some(Value::Null));
        assert!(binds_own(&Value::Null, &own, now).is_err());
    }
}
