use super::*;
use crate::commitment::tests::{defaults, NODE};
use crate::evidence_request_parity::{corpus_ledger_dir, NODE_KEY_SEED};
use crate::requester_auth::{Keys, ReplayCache};
use ed25519_dalek::SigningKey;
use std::path::Path;

const NOW: &str = "2026-10-28T00:00:00Z";

fn key() -> SigningKey {
    SigningKey::from_bytes(&NODE_KEY_SEED)
}

/// Run `f` with a responder over `dir` under `policy`, as
/// `commitment::with_responder` builds one.
fn with<T>(dir: &Path, policy: &Policy, f: impl FnOnce(&Responder<'_>) -> T) -> T {
    let key = key();
    let digest = policy.digest(&key);
    let announced = BTreeMap::new();
    let replay = ReplayCache::default();
    let responder = Responder {
        ledger_dir: dir,
        signing_key: &key,
        now: NOW,
        history_segments: policy.history_segments,
        share_standard_history: policy.share_standard_history,
        share_exchange_corroboration: policy.share_exchange_corroboration,
        keys: Keys {
            announced: &announced,
            configured: None,
            own_key: None,
        },
        replay: &replay,
        node_id: Some(NODE),
        policy_digest: Some(&digest),
    };
    f(&responder)
}

fn corpus() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    corpus_ledger_dir(dir.path(), &key());
    dir
}

/// The commitment `commitment/1` would serve over `dir` under `policy`, as
/// `commitment_bridge::own` builds it.
fn serve(dir: &Path, policy: &Policy, node: Option<&str>) -> Served {
    let node = node.ok_or("this node's mesh id is not known yet")?;
    with(dir, policy, |r| {
        commitment::build(r, node, policy).map_err(|u| u.why)
    })
}

fn doctor(dir: &Path, node: Option<&str>, probe: bool) -> Vec<Finding> {
    let policy = defaults();
    let served = serve(dir, &policy, node);
    with(dir, &policy, |r| {
        findings(r, &policy, &served, &Witnesses::default(), probe).unwrap()
    })
}

fn state<'a>(found: &'a [Finding], check: &str) -> &'a Finding {
    found
        .iter()
        .find(|f| f.check == check)
        .unwrap_or_else(|| panic!("no {check} finding"))
}

#[test]
fn the_findings_are_evidencebooks_checks_in_its_order() {
    let dir = corpus();
    let names: Vec<_> = doctor(dir.path(), Some(NODE), true)
        .iter()
        .map(|f| f.check)
        .collect();
    assert_eq!(
        names,
        [
            SELF_ATTESTED,
            CONTROLLER_BINDING,
            CHECKPOINT,
            WITNESS,
            NOT_CHECKED,
            UNSUPPORTED,
            SHARING,
            POLICY_IN_COMMITMENT,
            STRANGER_VIEW,
            IDENTIFIED_VIEW,
            PROBE_CHECKPOINTS,
            PROBE_HISTORY_CARD,
        ]
    );
    // Without probe, the two probe findings are absent and nothing else changes.
    let without: Vec<_> = doctor(dir.path(), Some(NODE), false);
    assert_eq!(without.len(), 10);
}

#[test]
fn a_healthy_node_matches_both_probes_and_has_its_policy_in_its_commitment() {
    let dir = corpus();
    let found = doctor(dir.path(), Some(NODE), true);
    assert_eq!(state(&found, CHECKPOINT).state, STATE_PRESENT);
    assert_eq!(state(&found, POLICY_IN_COMMITMENT).state, STATE_PRESENT);
    assert_eq!(
        state(&found, POLICY_IN_COMMITMENT).records,
        [defaults().digest(&key())]
    );
    for check in [PROBE_CHECKPOINTS, PROBE_HISTORY_CARD] {
        let f = state(&found, check);
        assert_eq!(f.state, STATE_MATCH, "{check}: {}", f.detail);
        assert_eq!(f.records.len(), 1, "the anchor answered at");
    }
    assert_eq!(state(&found, CONTROLLER_BINDING).state, STATE_UNBOUND);
    assert_eq!(state(&found, WITNESS).state, STATE_UNWITNESSED);
    // The defaults share the record at completion with the counterparty (#72).
    assert_eq!(state(&found, SHARING).state, STATE_ON);
}

#[test]
fn doctor_with_probe_seals_nothing_and_cuts_no_checkpoint() {
    let dir = corpus();
    let read = |name: &str| std::fs::read(dir.path().join(name)).unwrap();
    let before = (
        read(crate::evidence_log::CAPSULES_FILE),
        read(crate::evidence_log::CHECKPOINTS_FILE),
    );
    doctor(dir.path(), Some(NODE), true);
    let after = (
        read(crate::evidence_log::CAPSULES_FILE),
        read(crate::evidence_log::CHECKPOINTS_FILE),
    );
    assert_eq!(before, after);
}

#[test]
fn a_fresh_node_names_its_checkpoint_missing_and_checks_no_probe() {
    let dir = tempfile::tempdir().unwrap();
    let found = doctor(dir.path(), Some(NODE), true);
    assert_eq!(state(&found, CHECKPOINT).state, STATE_MISSING);
    assert_eq!(state(&found, POLICY_IN_COMMITMENT).state, STATE_MISSING);
    assert_eq!(state(&found, WITNESS).state, STATE_UNWITNESSED);
    for check in [PROBE_CHECKPOINTS, PROBE_HISTORY_CARD] {
        assert_eq!(state(&found, check).state, STATE_NOT_CHECKED);
    }
    assert!(state(&found, STRANGER_VIEW)
        .detail
        .starts_with("refusals only"));
    assert_eq!(
        state(&found, SELF_ATTESTED).detail,
        "the book has no records yet"
    );
}

#[test]
fn with_no_commitment_served_the_probe_checks_under_the_nodes_own_key() {
    let dir = corpus();
    let found = doctor(dir.path(), None, true);
    let f = state(&found, POLICY_IN_COMMITMENT);
    assert_eq!(f.state, STATE_MISSING);
    assert!(f.detail.contains("mesh id"), "{}", f.detail);
    for check in [PROBE_CHECKPOINTS, PROBE_HISTORY_CARD] {
        let f = state(&found, check);
        assert_eq!(f.state, STATE_MATCH, "{check}: {}", f.detail);
        assert!(f.detail.contains("own key"), "{}", f.detail);
    }
}

#[test]
fn a_served_commitment_under_another_policy_is_not_the_policy_in_commitment() {
    let dir = corpus();
    let served = serve(dir.path(), &defaults(), Some(NODE));
    let wider = Policy {
        share_standard_history: true,
        ..defaults()
    };
    let found = with(dir.path(), &wider, |r| {
        findings(r, &wider, &served, &Witnesses::default(), false).unwrap()
    });
    let f = state(&found, POLICY_IN_COMMITMENT);
    assert_eq!(f.state, STATE_MISSING);
    assert!(
        f.detail.contains("but this node answers under"),
        "{}",
        f.detail
    );
}

#[test]
fn an_answer_at_a_checkpoint_cut_after_doctor_read_the_book_still_matches() {
    let dir = corpus();
    let served = serve(dir.path(), &defaults(), Some(NODE));
    with(dir.path(), &defaults(), |r| {
        // The book as read before the latest checkpoint was cut.
        let mut before = read_book(r).unwrap();
        before.anchors.pop();
        assert!(
            !before.anchors.is_empty(),
            "the corpus has two checkpoints or more"
        );
        for (check, request) in probe_requests() {
            let f = probe_one(check, &request, r, &before, served.as_ref().ok());
            assert_eq!(f.state, STATE_MATCH, "{check}: {}", f.detail);
        }
    });
}

#[test]
fn a_book_past_the_answer_cap_names_the_issue_that_owns_it() {
    let long = Book {
        records: 1,
        leaves: 1,
        anchors: vec!["00".repeat(32); MAX_ANSWER_CHECKPOINTS as usize + 1],
        covered: 1,
        latest_size: Some(1),
    };
    assert!(long_log_note(&long).contains(LONG_LOG_ISSUE));
    let dir = corpus();
    with(dir.path(), &defaults(), |r| {
        let refused: Served =
            Err("this node refused its own history_card/1: policy_declined".into());
        let f = policy_in_commitment(r, &refused, &long);
        assert_eq!(f.state, STATE_MISSING);
        assert!(f.detail.contains(LONG_LOG_ISSUE), "{}", f.detail);
        let short = read_book(r).unwrap();
        assert!(!policy_in_commitment(r, &refused, &short)
            .detail
            .contains(LONG_LOG_ISSUE));
    });
}

#[test]
fn an_answer_under_another_policy_than_advertised_is_a_mismatch() {
    let dir = corpus();
    // The commitment advertises the defaults; the node now answers with
    // standard history shared.
    let advertised = with(dir.path(), &defaults(), |r| {
        commitment::build(r, NODE, &defaults()).unwrap()
    });
    let wider = Policy {
        share_standard_history: true,
        ..defaults()
    };
    with(dir.path(), &wider, |r| {
        let book = read_book(r).unwrap();
        for (check, request) in probe_requests() {
            let f = probe_one(check, &request, r, &book, Some(&advertised));
            assert_eq!(f.state, STATE_MISMATCH, "{check}");
            assert!(f.detail.contains("not the"), "{}", f.detail);
        }
    });
}

#[test]
fn an_answer_under_another_key_than_advertised_is_a_mismatch() {
    let dir = corpus();
    let advertised = with(dir.path(), &defaults(), |r| {
        commitment::build(r, NODE, &defaults()).unwrap()
    });
    // The same commitment, re-signed by another key: the answers do not
    // verify under the key it now names.
    let other = SigningKey::from_bytes(&[0x11; 32]);
    let mut doc = advertised.commitment.clone();
    doc["key_id"] = json!(commitment::key_id(&other));
    let forged = Signed {
        commitment: doc,
        policy: advertised.policy.clone(),
    };
    with(dir.path(), &defaults(), |r| {
        let book = read_book(r).unwrap();
        let (check, request) = &probe_requests()[0];
        let f = probe_one(check, request, r, &book, Some(&forged));
        assert_eq!(f.state, STATE_MISMATCH);
        assert!(f.detail.contains("does not verify"), "{}", f.detail);
    });
}

#[test]
fn the_witness_finding_says_which_witness_holds_the_latest_checkpoint() {
    let none = Witnesses::default();
    assert_eq!(witness(Some(7), &none, 3).state, STATE_UNWITNESSED);
    assert!(witness(Some(7), &none, 3)
        .detail
        .contains("no witness is configured"));
    let configured = vec!["https://w.example".to_string()];
    let unheld = Witnesses {
        configured: configured.clone(),
        held: BTreeMap::new(),
    };
    assert_eq!(witness(Some(7), &unheld, 3).state, STATE_UNWITNESSED);
    // A receipt for an earlier checkpoint does not witness the latest one.
    let earlier = Witnesses {
        configured: configured.clone(),
        held: BTreeMap::from([(4, vec!["w.example".to_string()])]),
    };
    assert_eq!(witness(Some(7), &earlier, 3).state, STATE_UNWITNESSED);
    let held = Witnesses {
        configured,
        held: BTreeMap::from([(7, vec!["w.example".to_string()])]),
    };
    let f = witness(Some(7), &held, 3);
    assert_eq!(f.state, STATE_WITNESSED);
    assert!(f.detail.contains("w.example"));
    assert_eq!(witness(None, &held, 0).state, STATE_UNWITNESSED);
    // A receipt that checks still witnesses after the witness is removed
    // from the settings.
    let removed = Witnesses {
        configured: vec![],
        ..held
    };
    assert_eq!(witness(Some(7), &removed, 3).state, STATE_WITNESSED);
}

#[test]
fn witnesses_are_read_from_the_checkpoint_lines_whose_receipts_check() {
    use crate::witness_status::fixture;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("witness-keys.json"), fixture::keys_json()).unwrap();
    let mut unheld = fixture::held_line();
    unheld["mmr_size"] = json!(4);
    unheld["witnesses"] = json!([]);
    let lines = [fixture::held_line(), unheld];
    let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
    std::fs::write(dir.path().join(crate::evidence_log::CHECKPOINTS_FILE), text).unwrap();
    let read = Witnesses::read_with(
        dir.path(),
        vec![fixture::WITNESS.to_string()],
        &BTreeMap::new(),
    );
    assert_eq!(read.held.keys().copied().collect::<Vec<_>>(), [3]);
    assert_eq!(
        read.held[&3],
        [crate::witness_status::display_url(fixture::WITNESS)]
    );
}

#[test]
fn sharing_is_off_only_when_every_switch_is_off() {
    let dir = corpus();
    let off = Policy {
        record_at_completion: false,
        history_segments: "off",
        share_standard_history: false,
        share_exchange_corroboration: false,
        advertise_evidence_requests: false,
        adjudications_delivered: false,
    };
    let served = serve(dir.path(), &off, Some(NODE));
    let found = with(dir.path(), &off, |r| {
        findings(r, &off, &served, &Witnesses::default(), false).unwrap()
    });
    assert_eq!(state(&found, SHARING).state, STATE_OFF);
}

#[test]
fn join_is_idempotent_and_complete_on_a_node_with_a_checkpoint() {
    let dir = corpus();
    let policy = defaults();
    let served = serve(dir.path(), &policy, Some(NODE));
    let run = || {
        with(dir.path(), &policy, |r| {
            join_report(r, &policy, &served, &Witnesses::default()).unwrap()
        })
    };
    let first = run();
    assert_eq!(first["joined"], json!(true), "{first:#}");
    assert_eq!(first["pending"], json!([]));
    assert_eq!(
        first["commitment"],
        served.as_ref().unwrap().to_wire(),
        "join returns the commitment served, not another build"
    );
    assert_eq!(first["unbound"].as_array().unwrap().len(), 1);
    assert_eq!(first["unwitnessed"].as_array().unwrap().len(), 1);
    assert_eq!(run(), first, "a second join changes nothing");
}

#[test]
fn join_on_a_fresh_node_names_the_missing_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let policy = defaults();
    let served = serve(dir.path(), &policy, Some(NODE));
    let report = with(dir.path(), &policy, |r| {
        join_report(r, &policy, &served, &Witnesses::default()).unwrap()
    });
    assert_eq!(report["joined"], json!(false));
    let pending = report["pending"].as_array().unwrap();
    assert!(
        pending[0]
            .as_str()
            .unwrap()
            .starts_with("the first checkpoint"),
        "{pending:?}"
    );
    assert!(report["commitment"].is_null());
    // A fresh node's book stays empty: join sealed nothing.
    assert!(!dir.path().join(crate::evidence_log::CAPSULES_FILE).exists());
}

#[test]
fn install_md_carries_the_generated_quickstart() {
    let install = include_str!("../../../../INSTALL.md");
    let begin = install
        .find(QUICKSTART_BEGIN)
        .expect("INSTALL.md has the quickstart's begin marker");
    let end = install
        .find(QUICKSTART_END)
        .expect("INSTALL.md has the quickstart's end marker");
    let carried = install[begin + QUICKSTART_BEGIN.len()..end].trim();
    assert_eq!(
        carried,
        quickstart(crate::PLUGIN_ID).trim(),
        "INSTALL.md's join quickstart differs from `capsules --print-join-quickstart`; \
         paste its output between the markers"
    );
}
