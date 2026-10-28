//! The adapter over records sealed the way the plugin seals them: a
//! host-shaped event (the mock rail) goes through `parse_and_check` and
//! `seal_settlement_record`, and the adapter reads the sealed record.

use super::*;
use crate::producer::capsule::seal_settlement_record;
use crate::settlement_channel::parse_and_check;
use serde_json::json;

const EX: &str = "ex-paid-1";

fn hash(b: &str) -> String {
    b.repeat(32)
}

/// The event mesh-llm main's emitter serializes: every member, `null`s
/// present, `credited_msat`/`fee_msat` only when the wallet said.
fn host_event(
    role: &str,
    phase: &str,
    segment: Option<u32>,
    payment_hash: Option<&str>,
    amount: u64,
) -> Value {
    let source = match phase {
        "input_invoice_issued" | "output_invoice_issued" => "provider_asserted",
        "input_settlement_observed" | "output_settlement_observed" => "wallet_reported",
        "final_accounted" => "payer_asserted",
        _ => {
            if role == "payer" {
                "payer_asserted"
            } else {
                "provider_asserted"
            }
        }
    };
    json!({
        "exchange_id": EX,
        "event_ref": "",
        "terms_digest": "7d".repeat(32),
        "role": role,
        "phase": phase,
        "source": source,
        "settlement": (source == "wallet_reported").then_some("terminal"),
        "segment": segment,
        "payment_hash": payment_hash,
        "amount_msat": amount,
        "tokens": null,
    })
}

fn digest(mut event: Value) -> Value {
    event["event_ref"] = json!("");
    event["event_ref"] = json!(jcs::json_digest(&event).unwrap());
    event
}

/// Seal one host event as the plugin does, after the intake check.
fn seal(event: Value) -> Value {
    let event = digest(event);
    let checked = parse_and_check(&serde_json::to_vec(&event).unwrap()).unwrap();
    let key = crate::producer::keys::KeyPair::generate();
    seal_settlement_record(&checked.observation(), None, &key.signing_key).unwrap()
}

fn invoice(role: &str, segment: u32, h: &str, amount: u64) -> Value {
    let phase = if segment == 0 {
        "input_invoice_issued"
    } else {
        "output_invoice_issued"
    };
    seal(host_event(role, phase, Some(segment), Some(h), amount))
}

fn settled(role: &str, segment: u32, h: Option<&str>, amount: u64) -> Value {
    let phase = if segment == 0 {
        "input_settlement_observed"
    } else {
        "output_settlement_observed"
    };
    seal(host_event(role, phase, Some(segment), h, amount))
}

fn one(records: Vec<Value>) -> Value {
    let r = report(records, Some(EX));
    assert_eq!(r["exchanges"].as_array().unwrap().len(), 1, "{r:#}");
    r["exchanges"][0].clone()
}

fn property<'a>(exchange: &'a Value, i: usize, name: &str) -> &'a str {
    exchange["settlements"][i]["properties"][name]["result"]
        .as_str()
        .unwrap()
}

#[test]
fn a_payer_deposit_and_final_settle_and_pass() {
    let ex = one(vec![
        seal(host_event("payer", "terms_accepted", None, None, 5000)),
        invoice("payer", 0, &hash("aa"), 1000),
        settled("payer", 0, Some(&hash("aa")), 1000),
        invoice("payer", 1, &hash("bb"), 250_000),
        settled("payer", 1, Some(&hash("bb")), 250_000),
        seal(host_event("payer", "final_accounted", None, None, 251_000)),
    ]);
    assert_eq!(ex["result"], "PASS", "{ex:#}");
    assert_eq!(ex["adapter"], LIGHTNING_ADAPTER);
    for i in 0..2 {
        assert_eq!(property(&ex, i, "object_held"), "PASS");
        assert_eq!(property(&ex, i, "invoice_join"), "PASS");
        assert_eq!(property(&ex, i, "amount"), "PASS");
        assert_eq!(property(&ex, i, "finality"), "PASS");
        assert_eq!(property(&ex, i, "preimage"), "NOT_CHECKED");
        assert_eq!(property(&ex, i, "payee_credit"), "NOT_CHECKED");
    }
    assert_eq!(ex["settlements"][0]["band"], "sat:e0");
    assert_eq!(ex["settlements"][1]["band"], "sat:e+2");
    assert_eq!(ex["invoices_without_settlement"], json!([]));
}

#[test]
fn a_provider_settlement_checks_what_the_wallet_credited() {
    let mut good = host_event(
        "provider",
        "input_settlement_observed",
        Some(0),
        Some(&hash("aa")),
        1000,
    );
    good["credited_msat"] = json!(995);
    good["fee_msat"] = json!(5);
    let ex = one(vec![
        invoice("provider", 0, &hash("aa"), 1000),
        seal(good.clone()),
    ]);
    assert_eq!(ex["result"], "PASS", "{ex:#}");
    assert_eq!(property(&ex, 0, "payee_credit"), "PASS");
    assert_eq!(ex["settlements"][0]["side"], "provider");

    good["credited_msat"] = json!(990);
    let ex = one(vec![
        invoice("provider", 0, &hash("aa"), 1000),
        seal(good.clone()),
    ]);
    assert_eq!(property(&ex, 0, "payee_credit"), "FAIL");
    assert_eq!(ex["result"], "FAIL");

    // No wallet numbers: not checked, and the exchange still passes.
    let bare = host_event(
        "provider",
        "input_settlement_observed",
        Some(0),
        Some(&hash("aa")),
        1000,
    );
    let ex = one(vec![invoice("provider", 0, &hash("aa"), 1000), seal(bare)]);
    assert_eq!(property(&ex, 0, "payee_credit"), "NOT_CHECKED");
    assert_eq!(ex["result"], "PASS");
}

#[test]
fn a_settlement_under_another_hash_fails_the_join() {
    let ex = one(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        settled("payer", 0, Some(&hash("cc")), 1000),
    ]);
    assert_eq!(property(&ex, 0, "invoice_join"), "FAIL");
    assert_eq!(ex["result"], "FAIL");
}

#[test]
fn a_settled_amount_off_the_invoice_fails() {
    let ex = one(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        settled("payer", 0, Some(&hash("aa")), 999),
    ]);
    assert_eq!(property(&ex, 0, "amount"), "FAIL");
    assert_eq!(ex["result"], "FAIL");
}

#[test]
fn a_settlement_with_no_hash_is_not_checked_for_the_join() {
    let ex = one(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        settled("payer", 0, None, 1000),
    ]);
    assert_eq!(property(&ex, 0, "invoice_join"), "NOT_CHECKED");
    assert_eq!(ex["result"], "PASS");
}

#[test]
fn an_invoice_with_no_settlement_is_inconclusive_never_unpaid() {
    let ex = one(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        settled("payer", 0, Some(&hash("aa")), 1000),
        invoice("payer", 1, &hash("bb"), 2000),
    ]);
    assert_eq!(ex["result"], "INCONCLUSIVE");
    assert_eq!(ex["invoices_without_settlement"][0]["segment"], 1);

    let ex = one(vec![invoice("payer", 0, &hash("aa"), 1000)]);
    assert_eq!(ex["result"], "INCONCLUSIVE");
    assert_eq!(ex["settlements"], json!([]));
}

#[test]
fn a_settlement_with_no_invoice_held_is_inconclusive() {
    let ex = one(vec![settled("payer", 0, Some(&hash("aa")), 1000)]);
    assert_eq!(property(&ex, 0, "invoice_join"), "INCONCLUSIVE");
    assert_eq!(property(&ex, 0, "amount"), "INCONCLUSIVE");
    assert_eq!(ex["result"], "INCONCLUSIVE");
}

#[test]
fn an_amountless_invoice_leaves_the_amount_not_checked() {
    let ex = one(vec![
        invoice("payer", 0, &hash("aa"), 0),
        settled("payer", 0, Some(&hash("aa")), 1000),
    ]);
    assert_eq!(property(&ex, 0, "amount"), "NOT_CHECKED");
    assert_eq!(ex["result"], "PASS");
}

/// An invoice the payer saw is not joined to a settlement the provider
/// sealed: each side's book is checked on its own.
#[test]
fn sides_are_never_joined() {
    let ex = one(vec![
        invoice("provider", 0, &hash("aa"), 1000),
        settled("payer", 0, Some(&hash("aa")), 1000),
    ]);
    assert_eq!(property(&ex, 0, "invoice_join"), "INCONCLUSIVE");
}

#[test]
fn a_record_whose_event_ref_does_not_recompute_is_inconclusive() {
    let mut record = settled("payer", 0, Some(&hash("aa")), 1000);
    record["model_attestation"]["compute_attestation"]["x-mesh-settlement-v1"]["amount_msat"] =
        json!(1001);
    let obs = Observation::from_lifecycle_record(&record).unwrap();
    assert_eq!(obs.held.outcome, Outcome::Inconclusive);
    let ex = one(vec![invoice("payer", 0, &hash("aa"), 1001), record]);
    assert_eq!(property(&ex, 0, "object_held"), "INCONCLUSIVE");
    assert_eq!(ex["result"], "INCONCLUSIVE");
}

#[test]
fn a_record_with_no_event_ref_fails_object_held() {
    let mut record = invoice("payer", 0, &hash("aa"), 1000);
    record["model_attestation"]["compute_attestation"]["x-mesh-settlement-v1"]
        .as_object_mut()
        .unwrap()
        .remove("event_ref");
    let ex = one(vec![record, settled("payer", 0, Some(&hash("aa")), 1000)]);
    assert_eq!(ex["result"], "FAIL");
}

/// A host from before `role` and `tokens` emitted neither; its records
/// still recompute.
#[test]
fn an_older_payer_only_host_event_recomputes() {
    let mut event = host_event(
        "payer",
        "input_settlement_observed",
        Some(0),
        Some(&hash("aa")),
        1000,
    );
    let obj = event.as_object_mut().unwrap();
    obj.remove("role");
    obj.remove("tokens");
    let obs = Observation::from_lifecycle_record(&seal(event)).unwrap();
    assert_eq!(obs.held.outcome, Outcome::Pass);
    assert_eq!(obs.side, Side::Payer);
}

#[test]
fn the_report_counts_every_settlement_record_and_filters_by_exchange() {
    let mut other = host_event(
        "payer",
        "input_invoice_issued",
        Some(0),
        Some(&hash("dd")),
        7,
    );
    other["exchange_id"] = json!("ex-other");
    let records = vec![
        json!({"capsule_id": "not-a-settlement"}),
        invoice("payer", 0, &hash("aa"), 1000),
        settled("payer", 0, Some(&hash("aa")), 1000),
        seal(other),
    ];
    let all = report(records.clone(), None);
    assert_eq!(all["settlement_records"], 3);
    assert_eq!(all["settlement_records_unread"], 0);
    assert_eq!(all["exchanges_with_settlement_records"], 2);
    assert_eq!(all["exchanges"].as_array().unwrap().len(), 2);
    assert_eq!(all["exchanges"][0]["exchange_id"], EX);

    let one = report(records, Some("ex-other"));
    assert_eq!(one["settlement_records"], 3);
    assert_eq!(one["exchanges"].as_array().unwrap().len(), 1);
    assert_eq!(one["exchanges"][0]["result"], "INCONCLUSIVE");

    let none = report(Vec::<Value>::new(), Some("missing"));
    assert_eq!(none["exchanges"], json!([]));
}

#[test]
fn an_unreadable_settlement_record_is_counted_not_dropped() {
    let mut record = invoice("payer", 0, &hash("aa"), 1000);
    record["model_attestation"]["compute_attestation"]["x-mesh-settlement-v1"]["observed_by"] =
        json!("someone");
    let r = report(vec![record], None);
    assert_eq!(r["settlement_records"], 1);
    assert_eq!(r["settlement_records_unread"], 1);
    assert_eq!(r["exchanges"], json!([]));
}

#[test]
fn bands_are_decades_of_the_amount_in_sats() {
    assert_eq!(band(0), None);
    assert_eq!(band(1).as_deref(), Some("sat:e-3"));
    assert_eq!(band(9).as_deref(), Some("sat:e-3"));
    assert_eq!(band(10).as_deref(), Some("sat:e-2"));
    assert_eq!(band(999).as_deref(), Some("sat:e-1"));
    assert_eq!(band(1000).as_deref(), Some("sat:e0"));
    assert_eq!(band(9999).as_deref(), Some("sat:e0"));
    assert_eq!(band(10_000).as_deref(), Some("sat:e+1"));
    assert_eq!(band(250_000).as_deref(), Some("sat:e+2"));
    // The largest amount a record can carry (JCS's 2^53-1).
    assert_eq!(band((1u64 << 53) - 1).as_deref(), Some("sat:e+12"));
    assert_eq!(band(u64::MAX).as_deref(), Some("sat:e+16"));
}
