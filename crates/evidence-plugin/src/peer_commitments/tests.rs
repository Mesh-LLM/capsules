use super::*;

use crate::commitment::tests::{built, defaults, NODE};

fn held() -> (tempfile::TempDir, Value) {
    let dir = tempfile::tempdir().unwrap();
    hold(dir.path(), NODE, &built(&defaults()).to_wire()).unwrap();
    let pinned = pinned(dir.path(), NODE).expect("a held commitment");
    (dir, pinned)
}

fn history_card() -> Value {
    json!({"subject": {"full_history": null}, "coverage": {"min_freshness": 1}, "derivation": "history_card/1"})
}

#[test]
fn an_ask_pins_the_held_commitment_its_policy_and_what_it_answers() {
    let signed = built(&defaults());
    let (_dir, pinned) = held();
    assert_eq!(
        pinned["digest"],
        json!(hex::encode(Sha256::digest(
            evidence_request::jcs::to_string(&signed.commitment).unwrap()
        )))
    );
    assert_eq!(
        pinned["policy_digest"],
        signed.commitment["lcap"]["policy_digest"]
    );
    assert_eq!(pinned["policy"], defaults().body());
    assert_eq!(pinned["subjects"], signed.commitment["answers"]["subjects"]);
}

#[test]
fn nothing_is_pinned_without_a_held_commitment_that_still_checks() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(pinned(dir.path(), NODE), None, "none held");

    let mut wire = built(&defaults()).to_wire();
    wire["commitment"]["issued_at"] = json!("2030-01-01T00:00:00Z");
    hold(dir.path(), NODE, &wire).unwrap();
    assert_eq!(pinned(dir.path(), NODE), None, "no longer verifies");

    hold(dir.path(), &"ab".repeat(32), &built(&defaults()).to_wire()).unwrap();
    assert_eq!(
        pinned(dir.path(), &"ab".repeat(32)),
        None,
        "it names another node"
    );
    assert!(hold(dir.path(), "../escape", &wire).is_err());
}

#[test]
fn withholding_what_the_policy_gives_any_asker_is_a_mismatch() {
    let (_dir, pinned) = held();
    let checkpoints = json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": 1}});
    let mut card_over_checkpoints = checkpoints.clone();
    card_over_checkpoints["derivation"] = json!("history_card/1");
    for request in [history_card(), checkpoints, card_over_checkpoints] {
        for reason in ["derivation_unsupported", "no_such_subject"] {
            let check = policy_check(Some(&pinned), &request, reason);
            assert_eq!(check["status"], "MISMATCH", "{request} {reason}: {check}");
            assert_eq!(check["policy_digest"], pinned["policy_digest"]);
        }
    }
}

#[test]
fn a_reason_honest_limits_also_send_is_not_checked() {
    let (_dir, pinned) = held();
    for reason in ["policy_declined", "not_authorized"] {
        assert_eq!(
            policy_check(Some(&pinned), &history_card(), reason)["status"],
            "NOT_CHECKED",
            "{reason}"
        );
    }
}

/// Under evidence-interop/1 (IP v1 §6.3) `policy_declined` and
/// `not_authorized` are statements about policy: withholding by policy what
/// the pinned policy gives any asker is a MISMATCH. `capacity_exceeded`
/// reads NOT_CHECKED under either identifier, and `request_unauthenticated`
/// blames the request.
#[test]
fn under_v1_a_policy_reason_is_judged_against_the_pinned_policy() {
    let (_dir, pinned) = held();
    let mut v1 = history_card();
    v1["profile"] = json!("evidence-interop/1");
    for reason in ["policy_declined", "not_authorized"] {
        let check = policy_check(Some(&pinned), &v1, reason);
        assert_eq!(check["status"], "MISMATCH", "{reason}: {check}");
        let mut v0 = history_card();
        v0["profile"] = json!("evidence-interop/0");
        assert_eq!(
            policy_check(Some(&pinned), &v0, reason)["status"],
            "NOT_CHECKED",
            "{reason}"
        );
    }
    for request in [v1.clone(), history_card()] {
        assert_eq!(
            policy_check(Some(&pinned), &request, "capacity_exceeded")["status"],
            "NOT_CHECKED"
        );
    }
    assert_eq!(
        policy_check(Some(&pinned), &v1, "request_unauthenticated")["status"],
        "MATCH"
    );
    // A request over the responder's size limit is refused before its
    // profile is read: its policy_declined is that limit.
    let mut big = v1.clone();
    big["nonce"] = json!("x".repeat(crate::evidence_answer::MAX_REQUEST_BYTES));
    assert_eq!(
        policy_check(Some(&pinned), &big, "policy_declined")["status"],
        "NOT_CHECKED"
    );
    // A record-carrying ask: whether a counterparty is answered depends on
    // who asks, which the refusal alone does not settle.
    let record = json!({"subject": {"record": "ab".repeat(32)}, "coverage": {"min_freshness": 1},
                        "profile": "evidence-interop/1"});
    assert_ne!(
        policy_check(Some(&pinned), &record, "not_authorized")["status"],
        "MISMATCH"
    );
}

#[test]
fn a_refusal_the_policy_allows_is_a_match() {
    let (_dir, pinned) = held();
    for reason in [
        "request_malformed",
        "deadline_unmet",
        "coverage_unsatisfiable",
        "retention_expired",
    ] {
        assert_eq!(
            policy_check(Some(&pinned), &history_card(), reason)["status"],
            "MATCH",
            "{reason} blames the request"
        );
    }
    let mut standard = history_card();
    standard["derivation"] = json!("standard_history/1");
    // `standard_history/1` is answered through `full_history`, but the
    // default policy does not give it to a stranger.
    assert_eq!(
        policy_check(Some(&pinned), &standard, "no_such_subject")["status"],
        "NOT_CHECKED"
    );
}

#[test]
fn a_refusal_of_a_subject_form_the_commitment_does_not_answer_is_a_match() {
    let segments_off = crate::commitment::Policy::from_settings(|env| {
        (env == crate::share_policy::ENV_HISTORY_SEGMENTS).then(|| "off".to_string())
    });
    let dir = tempfile::tempdir().unwrap();
    hold(dir.path(), NODE, &built(&segments_off).to_wire()).unwrap();
    let pinned = pinned(dir.path(), NODE).unwrap();
    let record = json!({"subject": {"record": "a".repeat(64)}, "coverage": {"min_freshness": 1}});
    assert_eq!(
        policy_check(Some(&pinned), &record, "no_such_subject")["status"],
        "MATCH"
    );
}

#[test]
fn without_a_commitment_a_refusal_is_not_checked_never_a_mismatch() {
    let check = policy_check(None, &history_card(), "no_such_subject");
    assert_eq!(check["status"], "NOT_CHECKED");
    assert_eq!(check.get("policy_digest"), None);
}

#[test]
fn whether_a_counterparty_is_answered_is_not_checked() {
    let (_dir, pinned) = held();
    let record = json!({"subject": {"record": "a".repeat(64)}, "coverage": {"min_freshness": 1}});
    assert_eq!(
        policy_check(Some(&pinned), &record, "no_such_subject")["status"],
        "NOT_CHECKED"
    );
}

#[test]
fn two_holds_of_one_peer_at_once_leave_one_whole_commitment() {
    let dir = tempfile::tempdir().unwrap();
    let frame = built(&defaults()).to_wire();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| hold(dir.path(), NODE, &frame).unwrap());
        }
    });
    assert!(pinned(dir.path(), NODE).is_some());
    let left: Vec<_> = std::fs::read_dir(dir.path().join(DIR))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, [std::ffi::OsString::from(format!("{NODE}.json"))]);
}
