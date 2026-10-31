//! Two nodes' books, sealed the way the plugin seals them: the provider's
//! `settlement-bundle`, verified and paired against the payer's records.

use super::*;
use crate::capsule_emit::CapsuleState;
use crate::deal_receipt::tests::cut;
use crate::producer::jcs;
use crate::settlement_channel::parse_and_check;

fn hash(b: &str) -> String {
    b.repeat(32)
}

/// Seal one host-shaped `payment.lifecycle.v1` event on `state`.
fn seal(
    state: &CapsuleState,
    role: &str,
    phase: &str,
    h: &str,
    amount: u64,
    wallet: Option<(u64, u64)>,
) {
    let settlement = phase.ends_with("_settlement_observed");
    let mut event = json!({
        "exchange_id": format!("{role}-ex"),
        "event_ref": "",
        "terms_digest": "7d".repeat(32),
        "role": role,
        "phase": phase,
        "source": if settlement { "wallet_reported" } else { "provider_asserted" },
        "settlement": settlement.then_some("terminal"),
        "segment": 0,
        "payment_hash": h,
        "amount_msat": amount,
        "tokens": null,
    });
    if let Some((credited, fee)) = wallet {
        event["credited_msat"] = json!(credited);
        event["fee_msat"] = json!(fee);
    }
    event["event_ref"] = json!(jcs::json_digest(&event).unwrap());
    let checked = parse_and_check(&serde_json::to_vec(&event).unwrap()).unwrap();
    state
        .emit_settlement_record(&checked.observation())
        .unwrap();
}

fn paid(state: &CapsuleState, h: &str, amount: u64) {
    seal(state, "payer", "input_settlement_observed", h, amount, None);
}

fn received(state: &CapsuleState, h: &str, credited: u64, fee: u64) {
    seal(
        state,
        "provider",
        "input_settlement_observed",
        h,
        credited + fee,
        Some((credited, fee)),
    );
}

fn node(dir: &tempfile::TempDir, id: &str) -> CapsuleState {
    CapsuleState::open(dir.path(), id).unwrap()
}

fn key(state: &CapsuleState) -> String {
    crate::commitment::key_id(state.signing_key())
}

fn bundle_of(state: &CapsuleState) -> Value {
    cut(state);
    bundle(state.ledger_dir(), &key(state)).unwrap()
}

/// Accept exactly `peer_key`, as the counterparty `b`.
fn accepting(peer_key: String) -> impl Fn(&str) -> Option<Vec<String>> {
    move |k| (k == peer_key).then(|| vec!["b".to_string()])
}

fn own_observations(state: &CapsuleState) -> Vec<Observation> {
    state
        .capsule_ids_in_order()
        .iter()
        .filter_map(|id| state.lookup(id).unwrap())
        .filter_map(|e| Observation::from_lifecycle_record(&e.capsule))
        .collect()
}

fn check(payer: &CapsuleState, provider: &CapsuleState) -> Value {
    let verified = verify(&bundle_of(provider), accepting(key(provider))).unwrap();
    let own = own_observations(payer);
    cross_check(&own.iter().collect::<Vec<_>>(), &verified)
}

#[test]
fn a_payment_both_books_hold_with_equal_amounts_pairs() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (node(&da, "a"), node(&db, "b"));
    paid(&a, &hash("aa"), 1000);
    received(&b, &hash("aa"), 995, 5);
    let r = check(&a, &b);
    assert_eq!(r["status"], "PASS", "{r:#}");
    assert_eq!(r["paired"], 1);
    assert_eq!(r["unpaired"], json!([]));
    assert_eq!(r["counterparty_key"], json!(key(&b)));
    assert_eq!(r["counterparty_peers"], json!(["b"]));
}

#[test]
fn both_books_disagreeing_on_a_payment_fails() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (node(&da, "a"), node(&db, "b"));
    paid(&a, &hash("aa"), 1000);
    received(&b, &hash("aa"), 900, 5);
    let r = check(&a, &b);
    assert_eq!(r["status"], "FAIL", "{r:#}");
    assert!(r["unpaired"][0]["reason"]
        .as_str()
        .unwrap()
        .starts_with("conflicting amounts"));
}

#[test]
fn both_books_naming_the_same_role_fails() {
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (node(&da, "a"), node(&db, "b"));
    paid(&a, &hash("aa"), 1000);
    paid(&b, &hash("aa"), 1000);
    assert_eq!(check(&a, &b)["status"], "FAIL");
}

#[test]
fn a_payment_one_book_holds_is_unpaired_not_failed() {
    // The payer also paid a third node; the counterparty never saw it.
    let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, b) = (node(&da, "a"), node(&db, "b"));
    paid(&a, &hash("aa"), 1000);
    received(&b, &hash("aa"), 995, 5);
    paid(&a, &hash("cc"), 2000);
    received(&b, &hash("dd"), 300, 0);
    let r = check(&a, &b);
    assert_eq!(r["status"], "INCONCLUSIVE", "{r:#}");
    assert_eq!(r["paired"], 1);
    assert_eq!(
        r["unpaired"],
        json!([
            {"payment_hash": hash("cc"), "reason": "recorded by this node only"},
            {"payment_hash": hash("dd"), "reason": "recorded by the counterparty only"},
        ])
    );
}

#[test]
fn the_bundle_carries_terminal_settlements_only() {
    let db = tempfile::tempdir().unwrap();
    let b = node(&db, "b");
    seal(
        &b,
        "provider",
        "input_invoice_issued",
        &hash("aa"),
        1000,
        None,
    );
    received(&b, &hash("aa"), 995, 5);
    let bundle = bundle_of(&b);
    let records = bundle["records"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{bundle:#}");
    assert_eq!(
        records[0].pointer(&format!("{SETTLEMENT_BLOCK_POINTER}/phase")),
        Some(&json!("input_settlement_observed"))
    );
}

#[test]
fn no_settlement_and_no_checkpoint_are_refusals() {
    let db = tempfile::tempdir().unwrap();
    let b = node(&db, "b");
    seal(
        &b,
        "provider",
        "input_invoice_issued",
        &hash("aa"),
        1000,
        None,
    );
    assert!(matches!(
        bundle(b.ledger_dir(), &key(&b)),
        Err(Failure::Refused(Refusal::NoSettlement))
    ));
    received(&b, &hash("aa"), 995, 5);
    assert!(matches!(
        bundle(b.ledger_dir(), &key(&b)),
        Err(Failure::Refused(Refusal::NotCheckpointed))
    ));
}

#[test]
fn a_bundle_under_an_unaccepted_or_own_key_is_not_used() {
    let db = tempfile::tempdir().unwrap();
    let b = node(&db, "b");
    received(&b, &hash("aa"), 995, 5);
    let bundle = bundle_of(&b);
    assert!(verify(&bundle, |_| None).is_err());
    assert!(verify(&bundle, accepting(key(&b))).is_ok());
}

#[test]
fn a_tampered_record_is_not_used() {
    let db = tempfile::tempdir().unwrap();
    let b = node(&db, "b");
    received(&b, &hash("aa"), 995, 5);
    let mut bundle = bundle_of(&b);
    bundle["records"][0]["model_attestation"]["compute_attestation"]["x-mesh-settlement-v1"]
        ["amount_msat"] = json!(1);
    assert!(verify(&bundle, accepting(key(&b))).is_err());
}

#[test]
fn the_report_names_why_the_count_was_not_cross_checked() {
    let absent = crate::settlement_adapter::report(Vec::new(), None, None);
    assert_eq!(absent["counterparty_count"]["status"], "NOT_PRESENT");
    let failed =
        crate::settlement_adapter::report(Vec::new(), None, Some(Err("did not verify".into())));
    assert_eq!(failed["counterparty_count"]["status"], "NOT_CHECKED");
    assert_eq!(failed["counterparty_count"]["reason"], "did not verify");
    assert_eq!(failed["public_ledger_count"]["status"], "NOT_CHECKED");
}
