//! D-34's acceptance cases (Mesh-LLM/capsules-plugin#69), end to end over
//! real sealed records: what the receiver does with a push
//! (`record_push_receive`), and the citing record this node then seals
//! (`producer::capsule::seal_citing_record`), which records the sender's key
//! and how it was accepted. The same cases are written to
//! `vectors/evidence-key-acceptance/cases.json`, the records the loop's
//! step 5 finding reads; [`the_committed_fixtures_verify`] holds that file to
//! what it claims.

use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::{Signature, SigningKey};
use serde_json::{json, Value};

use crate::capsule_emit::{CapsuleState, ExchangeRecord};
use crate::peer_keys::{Accepted, AcceptedVia};
use crate::producer::capsule::ReceivedHalfProvenance;
use crate::record_push_receive::{
    receive_via, Receiver, MAX_REJECTED_LOG_BYTES, REASON_SIGNATURE_UNVERIFIED,
    RECEIVED_CAPSULES_FILENAME,
};

const NOW: &str = "2026-10-28T12:00:00Z";
const FROM: &str = "2026-10-01T00:00:00Z";
const UNTIL: &str = "2027-10-01T00:00:00Z";

fn key_id(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

/// A node with its own key and ledger.
struct Node {
    _dir: tempfile::TempDir,
    state: CapsuleState,
}

fn node(name: &str) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let state = CapsuleState::open(dir.path(), name).unwrap();
    Node { _dir: dir, state }
}

/// A half `sender` sealed of one exchange: what it pushes bare.
fn bare_half(sender: &Node) -> Value {
    let exchange = ExchangeRecord {
        model: "m",
        client_nonce: Some("n"),
        request_bytes: br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#,
        response_bytes: br#"{"id":"x","choices":[{"message":{"role":"assistant","content":"y"}}]}"#,
        latency_ms: 1.0,
        exchange_id: Some("e-1"),
        requesting_party: Some("party-1"),
        host_provenance: None,
    };
    sender.state.emit_for_exchange(&exchange).unwrap().capsule
}

/// A pushed bundle sealed by a fresh node, and that node's key.
fn bundle(dir: &Path) -> (Value, SigningKey) {
    let body = crate::record_push_bridge::tests::real_bundle(dir);
    let key = CapsuleState::open(dir, "rust-node")
        .unwrap()
        .signing_key()
        .clone();
    (body, key)
}

/// `body`, pushed under `sender` to `receiver`, whose registry is the
/// operator's map `configured` and the host's `announced` keys.
fn push(
    receiver: &Node,
    configured: Option<&str>,
    announced: &BTreeMap<String, String>,
    body: &Value,
    sender: &str,
) -> (Value, Option<Accepted>) {
    let node = Receiver {
        ledger_dir: receiver.state.ledger_dir(),
        signing_key: receiver.state.signing_key(),
        peer_keys: configured,
        announced,
        record_at_completion_off: false,
        rejected_log_limit: MAX_REJECTED_LOG_BYTES,
    };
    receive_via(
        &node,
        &body.to_string().into_bytes(),
        Some(sender),
        NOW,
        "push",
    )
    .unwrap()
}

/// The citing record `receiver` seals for a half it held from `sender`.
fn cite(receiver: &Node, sender: &str, half: &Value, accepted: &Accepted) -> Value {
    let prov = ReceivedHalfProvenance {
        foreign_capsule_id: half["capsule_id"].as_str().unwrap(),
        received_from: sender,
        via: "push",
        received_at: NOW,
        signature_ok: true,
        digest_match: None,
        foreign_agent_input_digest: None,
        foreign_agent_output_digest: None,
        sender_key_id: half["key_id"].as_str(),
        accepted_via: Some(&accepted.via),
    };
    receiver
        .state
        .emit_citing_record(&prov)
        .unwrap()
        .expect("a new citing record")
        .capsule
}

fn received_half(citing: &Value) -> &Value {
    &citing["model_attestation"]["compute_attestation"]["received_half"]
}

fn held(receiver: &Node) -> usize {
    std::fs::read_to_string(receiver.state.ledger_dir().join(RECEIVED_CAPSULES_FILENAME))
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

/// Whether `reply` is a refusal signed by `node_key` over its members,
/// `refused_key_id` included when present.
fn refusal_verifies(reply: &Value, node_key: &str) -> bool {
    let text = |k: &str| reply[k].as_str().unwrap_or_default().to_string();
    let mut body = json!({
        "issued_at": text("issued_at"),
        "reason": text("reason"),
        "request_digest": text("request_digest"),
    });
    if let Some(refused) = reply.get("refused_key_id") {
        body["refused_key_id"] = refused.clone();
    }
    let signed = evidence_request::jcs::to_string(&body).unwrap();
    let key = hex::decode(node_key)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok());
    let sig = hex::decode(text("sig"))
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .map(|b| Signature::from_bytes(&b));
    text("key_id") == node_key
        && matches!((key, sig), (Some(k), Some(s)) if k.verify_strict(signed.as_bytes(), &s).is_ok())
}

/// One fixture case: the push, the reply, and the citing record when held.
fn case(
    name: &str,
    covers: &str,
    receiver: &Node,
    configured: Option<&str>,
    announced: &BTreeMap<String, String>,
    sender: &str,
    body: &Value,
) -> Value {
    let (reply, accepted) = push(receiver, configured, announced, body, sender);
    let half = body.get("capsule").unwrap_or(body);
    let citing = accepted.map(|a| cite(receiver, sender, half, &a));
    json!({
        "name": name,
        "covers": covers,
        "receiver": {
            "key_id": key_id(receiver.state.signing_key()),
            "peer_keys_env": configured,
            "announced": announced,
        },
        "push": {"sender": sender, "body": body},
        "reply": reply,
        "citing_record": citing,
    })
}

/// Every case, run fresh.
fn cases() -> Vec<Value> {
    let receiver = node("receiver");
    let sender = node("sender");
    let half = bare_half(&sender);
    let kb = key_id(sender.state.signing_key());
    let own = BTreeMap::from([("receiver".to_string(), key_id(receiver.state.signing_key()))]);
    let mut out = Vec::new();

    let announced = BTreeMap::from([("node-b".to_string(), kb.clone())]);
    out.push(case(
        "known_key_other_transport_id",
        "a half signed by the key a host announced for node-b, pushed under another id, is held: accepted_via host_announced",
        &receiver,
        None,
        &announced,
        "node-b-restarted",
        &half,
    ));

    let stranger = node("stranger");
    let other = key_id(stranger.state.signing_key());
    let announced = BTreeMap::from([("node-b".to_string(), other)]);
    out.push(case(
        "known_transport_id_unknown_key",
        "a push under node-b's id signed by a key nobody announced is refused signature_unverified, signed, naming the refused key",
        &receiver,
        None,
        &announced,
        "node-b",
        &half,
    ));

    // Another half of the same sender: each held half is cited once.
    let second = bare_half(&sender);
    let configured = format!(r#"{{"muse-vm": "{kb}"}}"#);
    out.push(case(
        "operator_stopgap_key",
        "a key only CAPSULES_PEER_KEYS lists, for a host with no stable transport id, is held under any id: accepted_via operator_stopgap",
        &receiver,
        Some(&configured),
        &BTreeMap::new(),
        "ephemeral-7f3a",
        &second,
    ));

    let bundle_dir = tempfile::tempdir().unwrap();
    let (body, node_key) = bundle(bundle_dir.path());
    let controller = SigningKey::from_bytes(&[0x42; 32]);
    let configured = format!(r#"{{"muse-controller": "{}"}}"#, key_id(&controller));
    let mut declared = body.clone();
    declared[crate::controller_binding::MEMBER] =
        crate::controller_binding::bind_for_test(&controller, &node_key, FROM, UNTIL);
    out.push(case(
        "controller_declaration",
        "a bundle whose half's key a carried controller-binding/0 binds to an accepted key is held: accepted_via controller_declaration, with the binding digest",
        &receiver,
        Some(&configured),
        &BTreeMap::new(),
        "ephemeral-91c2",
        &declared,
    ));

    let mut on_own = body;
    on_own[crate::controller_binding::MEMBER] = crate::controller_binding::bind_for_test(
        receiver.state.signing_key(),
        &node_key,
        FROM,
        UNTIL,
    );
    out.push(case(
        "controller_declaration_on_receivers_own_key",
        "a declaration binding the half's key to the receiver's own key is never used, so it cannot make a different counterparty: refused signature_unverified",
        &receiver,
        None,
        &own,
        "ephemeral-91c2",
        &on_own,
    ));

    let mut announced_and_own = own.clone();
    announced_and_own.insert("node-n".to_string(), key_id(&node_key));
    out.push(case(
        "known_key_declared_on_receivers_own_key",
        "a key a host announced, carrying a declaration that binds it to the receiver's own key, is refused signature_unverified: the two keys stated one controller, so it is never a different counterparty",
        &receiver,
        None,
        &announced_and_own,
        "node-n",
        &on_own,
    ));
    out
}

fn by_name<'a>(cases: &'a [Value], name: &str) -> &'a Value {
    cases.iter().find(|c| c["name"] == name).unwrap()
}

/// What each case claims, checked on a case: the fresh run and the
/// committed fixture are both held to it.
fn assert_case_holds(case: &Value) {
    let name = case["name"].as_str().unwrap();
    let receiver_key = case["receiver"]["key_id"].as_str().unwrap();
    let reply = &case["reply"];
    let half = case["push"]["body"]
        .get("capsule")
        .unwrap_or(&case["push"]["body"]);
    let expect_held = |via: &str| {
        assert_eq!(reply["status"], "received", "{name}: {reply}");
        let citing = &case["citing_record"];
        assert!(
            capsule_emit_lib::cose::verify_producer_envelope(citing)
                .is_ok_and(|signer| signer == receiver_key),
            "{name}: the citing record is signed by the receiver"
        );
        let facts = received_half(citing);
        assert_eq!(facts["cited_capsule_id"], half["capsule_id"], "{name}");
        assert_eq!(facts["received_from"], case["push"]["sender"], "{name}");
        assert_eq!(facts["sender_key_id"], half["key_id"], "{name}");
        assert_eq!(facts["accepted_via"], via, "{name}");
        facts.clone()
    };
    match name {
        "known_key_other_transport_id" => {
            expect_held("host_announced");
        }
        "operator_stopgap_key" => {
            expect_held("operator_stopgap");
        }
        "controller_declaration" => {
            let facts = expect_held("controller_declaration");
            let binding = &case["push"]["body"][crate::controller_binding::MEMBER];
            let applied = crate::controller_binding::applies(
                binding,
                evidence_request::time::parse_utc(NOW).unwrap(),
            )
            .expect("the carried binding applies");
            assert_eq!(facts["controller_binding_digest"], json!(applied.digest));
            assert_eq!(
                facts["controller_anchor_key_id"].as_str(),
                applied.other(half["key_id"].as_str().unwrap())
            );
        }
        "known_transport_id_unknown_key"
        | "controller_declaration_on_receivers_own_key"
        | "known_key_declared_on_receivers_own_key" => {
            assert_eq!(reply["reason"], REASON_SIGNATURE_UNVERIFIED, "{name}");
            assert_eq!(reply["refused_key_id"], half["key_id"], "{name}");
            assert!(refusal_verifies(reply, receiver_key), "{name}: {reply}");
            assert!(case["citing_record"].is_null(), "{name}");
        }
        other => panic!("unknown case {other}"),
    }
}

#[test]
fn every_acceptance_case_holds_on_a_fresh_run() {
    let cases = cases();
    assert_eq!(cases.len(), 6);
    for case in &cases {
        assert_case_holds(case);
    }
}

/// The receiver holds nothing for a refused push, and the half's key,
/// pushed under the id the host announced for it, is held as before.
#[test]
fn a_refused_push_holds_nothing_and_the_announced_id_still_works() {
    let receiver = node("receiver");
    let sender = node("sender");
    let half = bare_half(&sender);
    let stranger = node("stranger");
    let announced = BTreeMap::from([("node-b".to_string(), key_id(stranger.state.signing_key()))]);
    let (reply, accepted) = push(&receiver, None, &announced, &half, "node-b");
    assert_eq!(reply["reason"], REASON_SIGNATURE_UNVERIFIED);
    assert!(accepted.is_none());
    assert_eq!(held(&receiver), 0);

    let announced = BTreeMap::from([("node-b".to_string(), key_id(sender.state.signing_key()))]);
    let (reply, accepted) = push(&receiver, None, &announced, &half, "node-b");
    assert_eq!(reply["status"], "received");
    let accepted = accepted.unwrap();
    assert_eq!(accepted.via, AcceptedVia::HostAnnounced);
    assert_eq!(accepted.peers, ["node-b"]);
    assert_eq!(held(&receiver), 1);

    // The same half again, under other ids: acknowledged, never stored twice.
    for relay in ["node-b-restarted", "anyone-else"] {
        let (reply, _) = push(&receiver, None, &announced, &half, relay);
        assert_eq!(reply["status"], "received", "{relay}");
    }
    assert_eq!(
        held(&receiver),
        1,
        "one held copy whatever id it came under"
    );
}

/// A declaration that does not apply is not used: without it, expired, or
/// signed by one key, the bundle's key is unknown.
#[test]
fn a_declaration_that_does_not_apply_leaves_the_key_unknown() {
    let receiver = node("receiver");
    let dir = tempfile::tempdir().unwrap();
    let (body, node_key) = bundle(dir.path());
    let controller = SigningKey::from_bytes(&[0x42; 32]);
    let configured = format!(r#"{{"muse-controller": "{}"}}"#, key_id(&controller));
    let good = crate::controller_binding::bind_for_test(&controller, &node_key, FROM, UNTIL);
    let expired = crate::controller_binding::bind_for_test(
        &controller,
        &node_key,
        "2026-01-01T00:00:00Z",
        "2026-02-01T00:00:00Z",
    );
    let mut one_signed = good.clone();
    one_signed["sigs"].as_array_mut().unwrap().pop();
    let unrelated = crate::controller_binding::bind_for_test(
        &controller,
        &SigningKey::from_bytes(&[0x43; 32]),
        FROM,
        UNTIL,
    );
    let none = BTreeMap::new();
    for (why, binding) in [
        ("expired", Some(expired)),
        ("one signature", Some(one_signed)),
        ("binds another key", Some(unrelated)),
        ("no declaration", None),
    ] {
        let mut pushed = body.clone();
        if let Some(binding) = binding {
            pushed[crate::controller_binding::MEMBER] = binding;
        }
        let (reply, accepted) = push(&receiver, Some(&configured), &none, &pushed, "x");
        assert_eq!(
            reply["reason"], REASON_SIGNATURE_UNVERIFIED,
            "{why}: {reply}"
        );
        assert!(accepted.is_none(), "{why}");
    }
    let mut pushed = body;
    pushed[crate::controller_binding::MEMBER] = good;
    let (reply, _) = push(&receiver, Some(&configured), &none, &pushed, "x");
    assert_eq!(reply["status"], "received", "{reply}");
    let mut not_object = pushed.clone();
    not_object[crate::controller_binding::MEMBER] = json!("binding");
    let (reply, _) = push(&receiver, Some(&configured), &none, &not_object, "x");
    assert_eq!(
        reply["reason"],
        crate::record_push_receive::REASON_BUNDLE_MALFORMED
    );
}

fn fixture_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors/evidence-key-acceptance/cases.json")
}

/// The committed fixtures hold to what each case claims: the citing
/// records verify under the receiver's key and carry the sender's key and
/// how it was accepted; the refusals verify and name the refused key.
#[test]
fn the_committed_fixtures_verify() {
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path()).unwrap()).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for name in [
        "known_key_other_transport_id",
        "known_transport_id_unknown_key",
        "operator_stopgap_key",
        "controller_declaration",
        "controller_declaration_on_receivers_own_key",
        "known_key_declared_on_receivers_own_key",
    ] {
        assert_case_holds(by_name(cases, name));
    }
}

/// Writes `vectors/evidence-key-acceptance/cases.json`. Run to regenerate:
///   cargo test writes_the_evidence_key_acceptance_fixtures -- --ignored
#[test]
#[ignore = "regenerates a committed fixture"]
fn writes_the_evidence_key_acceptance_fixtures() {
    let doc = json!({
        "v": 1,
        "about": "D-34 acceptance (Mesh-LLM/capsules-plugin#69): pushes are accepted on the half's evidence key, not the sender id. Each case is a push to a receiver, its reply, and the citing record the receiver sealed when it held the half. Test keys only.",
        "now": NOW,
        "cases": cases(),
    });
    std::fs::create_dir_all(fixture_path().parent().unwrap()).unwrap();
    std::fs::write(
        fixture_path(),
        serde_json::to_string_pretty(&doc).unwrap() + "\n",
    )
    .unwrap();
}
