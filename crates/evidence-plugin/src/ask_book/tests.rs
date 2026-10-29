use super::*;

use sha2::{Digest, Sha256};

const ASKED_AT: &str = "2026-10-29T12:00:00Z";
const PEER: &str = "peer-asked";

fn state() -> (CapsuleState, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let capsules = CapsuleState::open(dir.path(), "node-under-test").expect("open state");
    (capsules, dir)
}

fn request(deadline: Option<&str>) -> Value {
    let mut request = json!({
        "subject": {"full_history": null},
        "coverage": {"min_freshness": 1},
        "derivation": "history_card/1",
        "audience": PEER,
        "nonce": "n-1",
    });
    if let Some(deadline) = deadline {
        request["deadline"] = json!(deadline);
    }
    request
}

fn digest_of(request: &Value) -> String {
    hex::encode(Sha256::digest(
        evidence_request::jcs::to_string(request).unwrap(),
    ))
}

/// The book's records, as `(record id, header)`, in ledger order.
fn records(capsules: &CapsuleState) -> Vec<(String, Map<String, Value>)> {
    AskBook::open(capsules, ASKED_AT).records
}

fn header_of(capsules: &CapsuleState, id: &str) -> Map<String, Value> {
    records(capsules)
        .into_iter()
        .find(|(rid, _)| rid == id)
        .expect("recorded")
        .1
}

fn cites(header: &Map<String, Value>) -> Vec<String> {
    header["links"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["type"] == "cites")
        .map(|l| l["target"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn the_ask_is_sealed_as_an_evidence_request_holding_the_request_sent() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();

    let header = header_of(&capsules, &asked.record_id);
    assert_eq!(header["record_type"], "evidence_request");
    assert_eq!(header["epistemic_type"], "observed_event");
    assert_eq!(header["committed_at"], ASKED_AT);
    assert_eq!(header["statement"]["request"], sent);
    assert_eq!(header["statement"]["responder_ref"], PEER);
    assert_eq!(
        capsules.chain_head().as_deref(),
        Some(asked.record_id.as_str())
    );
    assert_eq!(asked.window_closes, "2026-10-29T12:01:00Z");
}

#[test]
fn an_ask_record_never_leaves_this_node() {
    let (capsules, _dir) = state();
    let asked = record_request(&capsules, &request(None), PEER, None, ASKED_AT).unwrap();
    let record = capsules.lookup(&asked.record_id).unwrap().unwrap().capsule;
    assert!(is_ask_record(&record));
    let index = crate::evidence_log::with_index(capsules.ledger_dir(), "k", |index| {
        index
            .leaves
            .iter()
            .map(|l| l.never_leaves)
            .collect::<Vec<_>>()
    })
    .unwrap();
    assert_eq!(index, [true], "the request record is holder-only");
}

#[test]
fn the_window_closes_at_the_later_of_the_deadline_and_the_minimum() {
    assert_eq!(
        window_closes(None, ASKED_AT).as_deref(),
        Some("2026-10-29T12:01:00Z"),
        "never before the crate's 60 s minimum"
    );
    assert_eq!(
        window_closes(Some("2026-10-29T12:02:00Z"), ASKED_AT).as_deref(),
        Some("2026-10-29T12:02:00Z"),
        "never before the request's own deadline"
    );
    assert_eq!(
        window_closes(Some("2026-10-29T12:00:30Z"), ASKED_AT).as_deref(),
        Some("2026-10-29T12:01:00Z")
    );
    assert_eq!(
        window_closes(None, "2026-10-29T12:00:00.250Z").as_deref(),
        Some("2026-10-29T12:01:01Z"),
        "rounded up to a whole second"
    );
    assert_eq!(window_closes(Some("tomorrow"), ASKED_AT), None);
}

#[test]
fn a_request_the_book_could_not_resolve_is_never_recorded() {
    let (capsules, _dir) = state();
    let refused = |request: Value| {
        let result = record_request(&capsules, &request, PEER, None, ASKED_AT);
        assert!(
            matches!(result, Err(AskError::Invalid(_))),
            "{request}: {result:?}"
        );
    };
    refused(request(Some("tomorrow")));
    refused(json!({"subject": {"kind": "record", "capsule_id": "aa"}}));
    let mut bad_derivation = request(None);
    bad_derivation["derivation"] = json!("Foo");
    refused(bad_derivation);
    assert!(records(&capsules).is_empty(), "nothing sealed");
    assert_eq!(capsules.chain_head(), None);
}

#[test]
fn a_nonce_is_never_used_twice() {
    let (capsules, _dir) = state();
    record_request(&capsules, &request(None), PEER, None, ASKED_AT).unwrap();
    let again = record_request(&capsules, &request(None), PEER, None, ASKED_AT);
    assert!(matches!(again, Err(AskError::Invalid(_))), "{again:?}");
    let mut fresh = request(None);
    fresh["nonce"] = json!("n-2");
    record_request(&capsules, &fresh, PEER, None, ASKED_AT).unwrap();
    assert_eq!(records(&capsules).len(), 2);
}

#[test]
fn no_answer_by_the_close_is_a_recorded_absence_citing_the_request() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();

    let absence = record_absence(
        &capsules,
        &asked.record_id,
        &asked.window_closes,
        "2026-10-29T12:01:01Z",
    )
    .unwrap();
    let header = header_of(&capsules, &absence.record_id);
    assert_eq!(header["record_type"], "recorded_absence");
    assert_eq!(cites(&header), std::slice::from_ref(&asked.record_id));
    let statement = &header["statement"];
    assert_eq!(statement["outcome"], "recorded_absence");
    assert_eq!(statement["request_digest"], digest_of(&sent));
    assert_eq!(
        statement["window"],
        json!({"opened": ASKED_AT, "closed": "2026-10-29T12:01:00Z"})
    );
    assert_eq!(statement["recorded_at"], "2026-10-29T12:01:01Z");
}

#[test]
fn a_pending_request_is_never_recorded_as_absent() {
    let (capsules, _dir) = state();
    let asked = record_request(&capsules, &request(None), PEER, None, ASKED_AT).unwrap();
    let early = record_absence(
        &capsules,
        &asked.record_id,
        &asked.window_closes,
        "2026-10-29T12:00:30Z",
    );
    assert!(matches!(early, Err(AskError::Invalid(_))), "{early:?}");
    let short = record_absence(
        &capsules,
        &asked.record_id,
        "2026-10-29T12:00:10Z",
        "2026-10-29T12:05:00Z",
    );
    assert!(matches!(short, Err(AskError::Invalid(_))), "{short:?}");
    assert_eq!(records(&capsules).len(), 1, "nothing but the request");
}

#[test]
fn a_reply_in_the_window_is_the_response_and_forecloses_an_absence() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();
    let answer = json!({"artifact": "AAAA", "derivation": "history_card/1"});
    let verification = json!({"state": "artifact", "anchor": "a", "records": [], "checkpoints": 1});

    let response = record_response(
        &capsules,
        &asked.record_id,
        &digest_of(&sent),
        &answer,
        &verification,
        "2026-10-29T12:00:02Z",
    )
    .unwrap();
    let header = header_of(&capsules, &response.0.record_id);
    assert_eq!(header["record_type"], "evidence_response");
    assert_eq!(cites(&header), std::slice::from_ref(&asked.record_id));
    assert_eq!(
        header["statement"],
        json!({"outcome": "artifact", "request_digest": digest_of(&sent), "verification": verification})
    );

    let absence = record_absence(
        &capsules,
        &asked.record_id,
        &asked.window_closes,
        "2026-10-29T12:01:01Z",
    );
    assert!(matches!(absence, Err(AskError::Invalid(_))), "{absence:?}");
}

#[test]
fn a_late_reply_never_replaces_the_absence() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();
    record_absence(
        &capsules,
        &asked.record_id,
        &asked.window_closes,
        "2026-10-29T12:01:01Z",
    )
    .unwrap();

    let late = record_response(
        &capsules,
        &asked.record_id,
        &digest_of(&sent),
        &json!({"reason": "policy_declined"}),
        &json!({"state": "refusal", "reason": "policy_declined"}),
        "2026-10-29T12:01:05Z",
    );
    assert!(matches!(late, Err(AskError::Invalid(_))), "{late:?}");
    let kinds: Vec<_> = records(&capsules)
        .into_iter()
        .map(|(_, h)| h["record_type"].clone())
        .collect();
    assert_eq!(kinds, ["evidence_request", "recorded_absence"]);
}

#[test]
fn a_response_cites_only_a_recorded_request() {
    let (capsules, _dir) = state();
    let late = record_response(
        &capsules,
        &"0".repeat(64),
        "d",
        &json!({}),
        &json!({"state": "artifact"}),
        ASKED_AT,
    );
    assert!(matches!(late, Err(AskError::NotFound(_))), "{late:?}");
}

#[test]
fn each_reply_is_recorded_as_what_it_is_never_as_an_absence() {
    let refusal = json!({"reason": "not_authorized", "sig": "s"});
    let artifact = json!({"artifact": "AAAA"});
    let state = |s: &str| json!({"state": s});
    assert_eq!(outcome(&artifact, &state("artifact")), "artifact");
    assert_eq!(outcome(&refusal, &state("refusal")), "refusal");
    assert_eq!(
        outcome(&refusal, &state("not_evidence")),
        "refusal_nonconformant"
    );
    assert_eq!(
        outcome(&artifact, &state("not_evidence")),
        "artifact_verification_failed"
    );
    assert_eq!(outcome(&refusal, &state("no_announced_key")), "refusal");
    assert_eq!(outcome(&artifact, &state("no_announced_key")), "artifact");
}

fn with_nonce(mut request: Value, nonce: &str) -> Value {
    request["nonce"] = json!(nonce);
    request
}

#[test]
fn at_start_the_absences_owed_are_sealed_once_and_open_windows_returned() {
    let (capsules, _dir) = state();
    let overdue = record_request(&capsules, &request(None), PEER, None, ASKED_AT).unwrap();
    let answered = record_request(
        &capsules,
        &with_nonce(request(None), "n-2"),
        PEER,
        None,
        ASKED_AT,
    )
    .unwrap();
    record_response(
        &capsules,
        &answered.record_id,
        "d",
        &json!({"artifact": "AAAA"}),
        &json!({"state": "artifact"}),
        "2026-10-29T12:00:01Z",
    )
    .unwrap();
    let still_open = record_request(
        &capsules,
        &with_nonce(request(Some("2026-10-29T12:10:00Z")), "n-3"),
        PEER,
        None,
        ASKED_AT,
    )
    .unwrap();

    let now = "2026-10-29T12:05:00Z";
    let (sealed, open) = resume_asks(&capsules, now);
    assert_eq!(sealed, 1);
    assert_eq!(
        open,
        std::slice::from_ref(&still_open),
        "the open window is the caller's to close"
    );
    assert_eq!(still_open.window_closes, "2026-10-29T12:10:00Z");
    let absences: Vec<_> = records(&capsules)
        .into_iter()
        .filter(|(_, h)| h["record_type"] == "recorded_absence")
        .map(|(_, h)| (cites(&h), h["statement"]["window"]["closed"].clone()))
        .collect();
    assert_eq!(
        absences,
        [(vec![overdue.record_id], json!("2026-10-29T12:01:00Z"))]
    );
    assert_eq!(resume_asks(&capsules, now).0, 0, "once");

    let (sealed, open) = resume_asks(&capsules, "2026-10-29T12:10:00Z");
    assert_eq!(
        (sealed, open.len()),
        (1, 0),
        "the third, once its deadline passed"
    );
    let last = records(&capsules).pop().expect("a record").1;
    assert_eq!(last["record_type"], "recorded_absence");
    assert_eq!(cites(&last), [still_open.record_id]);
}

#[test]
fn a_signed_refusal_is_checked_against_the_commitment_the_ask_recorded() {
    let (capsules, _dir) = state();
    let commitment = json!({
        "digest": "c".repeat(64),
        "policy_digest": "p".repeat(64),
        "policy": {"stranger_safe": ["checkpoints", "history_card/1"]},
        "subjects": ["checkpoints", "full_history"],
    });
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, Some(commitment.clone()), ASKED_AT).unwrap();
    assert_eq!(
        header_of(&capsules, &asked.record_id)["statement"]["commitment"],
        commitment
    );

    let (response, verification) = record_response(
        &capsules,
        &asked.record_id,
        &digest_of(&sent),
        &json!({"reason": "no_such_subject"}),
        &json!({"state": "refusal", "reason": "no_such_subject"}),
        "2026-10-29T12:00:02Z",
    )
    .unwrap();
    assert_eq!(verification["policy_check"]["status"], "MISMATCH");
    let header = header_of(&capsules, &response.record_id);
    assert_eq!(header["statement"]["outcome"], "refusal");
    assert_eq!(header["statement"]["verification"], verification);
}

#[test]
fn an_artifact_carries_no_policy_check() {
    let (capsules, _dir) = state();
    let sent = request(None);
    let asked = record_request(&capsules, &sent, PEER, None, ASKED_AT).unwrap();
    let (_, verification) = record_response(
        &capsules,
        &asked.record_id,
        &digest_of(&sent),
        &json!({"artifact": "AAAA"}),
        &json!({"state": "artifact"}),
        "2026-10-29T12:00:02Z",
    )
    .unwrap();
    assert_eq!(verification, json!({"state": "artifact"}));
}
