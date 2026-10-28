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

fn doctor(dir: &Path, node: Option<&str>, probe: bool) -> Vec<Finding> {
    let policy = defaults();
    with(dir, &policy, |r| {
        findings(r, &policy, node, &Witnesses::default(), probe).unwrap()
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
}

#[test]
fn with_no_mesh_id_there_is_no_commitment_to_match() {
    let dir = corpus();
    let found = doctor(dir.path(), None, true);
    let f = state(&found, POLICY_IN_COMMITMENT);
    assert_eq!(f.state, STATE_MISSING);
    assert!(f.detail.contains("mesh id"), "{}", f.detail);
    assert_eq!(state(&found, PROBE_CHECKPOINTS).state, STATE_NOT_CHECKED);
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
    assert_eq!(witness(true, &none, 3).state, STATE_UNWITNESSED);
    assert!(witness(true, &none, 3)
        .detail
        .contains("no witness is configured"));
    let unheld = Witnesses {
        configured: vec!["https://w.example".into()],
        latest_held: vec![],
    };
    assert_eq!(witness(true, &unheld, 3).state, STATE_UNWITNESSED);
    let held = Witnesses {
        latest_held: vec!["w.example".into()],
        ..unheld
    };
    let f = witness(true, &held, 3);
    assert_eq!(f.state, STATE_WITNESSED);
    assert!(f.detail.contains("w.example"));
    assert_eq!(witness(false, &held, 0).state, STATE_UNWITNESSED);
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
    let found = with(dir.path(), &off, |r| {
        findings(r, &off, Some(NODE), &Witnesses::default(), false).unwrap()
    });
    assert_eq!(state(&found, SHARING).state, STATE_OFF);
}

#[test]
fn join_is_idempotent_and_complete_on_a_node_with_a_checkpoint() {
    let dir = corpus();
    let policy = defaults();
    let run = || {
        with(dir.path(), &policy, |r| {
            join_report(r, &policy, Some(NODE), &Witnesses::default()).unwrap()
        })
    };
    let first = run();
    assert_eq!(first["joined"], json!(true), "{first:#}");
    assert_eq!(first["pending"], json!([]));
    assert!(first["commitment"]["commitment"].is_object());
    assert_eq!(first["unbound"].as_array().unwrap().len(), 1);
    assert_eq!(first["unwitnessed"].as_array().unwrap().len(), 1);
    assert_eq!(run(), first, "a second join changes nothing");
}

#[test]
fn join_on_a_fresh_node_names_the_missing_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let policy = defaults();
    let report = with(dir.path(), &policy, |r| {
        join_report(r, &policy, Some(NODE), &Witnesses::default()).unwrap()
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
