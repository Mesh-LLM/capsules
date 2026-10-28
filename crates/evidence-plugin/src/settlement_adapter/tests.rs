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

fn paid(role: &str, segment: u32, h: Option<&str>, amount: u64) -> Value {
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

/// The one side's book an exchange holds.
fn book(records: Vec<Value>) -> Value {
    let ex = one(records);
    let books = ex["books"].as_array().unwrap();
    assert_eq!(books.len(), 1, "{ex:#}");
    books[0].clone()
}

fn settled(book: &Value) -> &str {
    book["settled"]["status"].as_str().unwrap()
}

/// A settlement's check by name, as a `native_check` report.
fn chk<'a>(book: &'a Value, i: usize, name: &str) -> &'a str {
    let checks = book["settlements"][i]["checks"].as_array().unwrap();
    let c = checks
        .iter()
        .find(|c| c["detail"]["check"] == name)
        .unwrap_or_else(|| panic!("no {name} check: {book:#}"));
    assert_eq!(c["property"], "native_check");
    assert_eq!(c["detail"]["object"], "payment.lifecycle.v1");
    assert!(c["method"].as_str().is_some_and(|m| !m.is_empty()));
    c["status"].as_str().unwrap()
}

#[test]
fn a_payer_deposit_and_final_settle() {
    let b = book(vec![
        seal(host_event("payer", "terms_accepted", None, None, 5000)),
        invoice("payer", 0, &hash("aa"), 1000),
        paid("payer", 0, Some(&hash("aa")), 1000),
        invoice("payer", 1, &hash("bb"), 250_000),
        paid("payer", 1, Some(&hash("bb")), 250_000),
        seal(host_event("payer", "final_accounted", None, None, 251_000)),
    ]);
    assert_eq!(settled(&b), "PASS", "{b:#}");
    assert_eq!(b["side"], "payer");
    for i in 0..2 {
        assert_eq!(chk(&b, i, "object_held"), "PASS");
        assert_eq!(chk(&b, i, "invoice_join"), "PASS");
        assert_eq!(chk(&b, i, "amount"), "PASS");
        assert_eq!(chk(&b, i, "finality"), "PASS");
        assert_eq!(chk(&b, i, "preimage"), "NOT_PRESENT");
        assert_eq!(chk(&b, i, "payee_credit"), "NOT_CHECKED");
    }
    let finality = b["settlements"][0]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["detail"]["check"] == "finality")
        .unwrap();
    assert_eq!(finality["method"], FINALITY_METHOD);
    // One band for the exchange: deposit and final together.
    assert_eq!(b["band"], json!({"currency": "BTC", "decade": -6}));
    assert_eq!(b["invoices_without_settlement"], json!([]));
    assert_eq!(b["invoices"][0]["checks"][0]["status"], "PASS");
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
    let b = book(vec![
        invoice("provider", 0, &hash("aa"), 1000),
        seal(good.clone()),
    ]);
    assert_eq!(settled(&b), "PASS", "{b:#}");
    assert_eq!(chk(&b, 0, "payee_credit"), "PASS");
    assert_eq!(b["side"], "provider");

    good["credited_msat"] = json!(990);
    let b = book(vec![invoice("provider", 0, &hash("aa"), 1000), seal(good)]);
    assert_eq!(chk(&b, 0, "payee_credit"), "FAIL");
    assert_eq!(settled(&b), "FAIL");

    // No wallet numbers: absent, and the exchange still settles.
    let bare = host_event(
        "provider",
        "input_settlement_observed",
        Some(0),
        Some(&hash("aa")),
        1000,
    );
    let b = book(vec![invoice("provider", 0, &hash("aa"), 1000), seal(bare)]);
    assert_eq!(chk(&b, 0, "payee_credit"), "NOT_PRESENT");
    assert_eq!(settled(&b), "PASS");
}

#[test]
fn a_settlement_under_another_hash_fails_the_join() {
    let b = book(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        paid("payer", 0, Some(&hash("cc")), 1000),
    ]);
    assert_eq!(chk(&b, 0, "invoice_join"), "FAIL");
    assert_eq!(settled(&b), "FAIL");
}

#[test]
fn a_settled_amount_off_the_invoice_fails() {
    let b = book(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        paid("payer", 0, Some(&hash("aa")), 999),
    ]);
    assert_eq!(chk(&b, 0, "amount"), "FAIL");
    assert_eq!(settled(&b), "FAIL");
}

/// No hash, no join: the settlement is compared by amount with its
/// segment's only invoice, but the exchange never reads settled.
#[test]
fn a_settlement_with_no_hash_joins_nothing() {
    let b = book(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        paid("payer", 0, None, 1000),
    ]);
    assert_eq!(chk(&b, 0, "invoice_join"), "NOT_PRESENT");
    assert_eq!(chk(&b, 0, "amount"), "PASS");
    assert_eq!(settled(&b), "INCONCLUSIVE");
    assert_eq!(b["invoices_without_settlement"][0]["segment"], 0);
}

/// A retry under the same exchange id: two invoices on one segment.
#[test]
fn a_retried_segment_joins_by_hash() {
    // Only the second invoice was paid: the first stays unanswered.
    let b = book(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        invoice("payer", 0, &hash("bb"), 1000),
        paid("payer", 0, Some(&hash("bb")), 1000),
    ]);
    assert_eq!(chk(&b, 0, "invoice_join"), "PASS", "{b:#}");
    assert_eq!(chk(&b, 0, "amount"), "PASS");
    assert_eq!(settled(&b), "INCONCLUSIVE");
    assert_eq!(
        b["invoices_without_settlement"],
        json!([{"segment": 0, "payment_hash": hash("aa")}])
    );

    // Both paid: both join, and the exchange settles.
    let b = book(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        invoice("payer", 0, &hash("bb"), 2000),
        paid("payer", 0, Some(&hash("aa")), 1000),
        paid("payer", 0, Some(&hash("bb")), 2000),
    ]);
    assert_eq!(chk(&b, 0, "amount"), "PASS");
    assert_eq!(chk(&b, 1, "amount"), "PASS");
    assert_eq!(settled(&b), "PASS");
    assert_eq!(b["band"], json!({"currency": "BTC", "decade": -8}));

    // A hashless settlement cannot say which of two invoices it paid.
    let b = book(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        invoice("payer", 0, &hash("bb"), 1000),
        paid("payer", 0, None, 1000),
    ]);
    assert_eq!(chk(&b, 0, "amount"), "NOT_PRESENT");
    assert_eq!(settled(&b), "INCONCLUSIVE");
    assert_eq!(
        b["invoices_without_settlement"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn an_invoice_with_no_settlement_never_reads_unpaid() {
    let b = book(vec![
        invoice("payer", 0, &hash("aa"), 1000),
        paid("payer", 0, Some(&hash("aa")), 1000),
        invoice("payer", 1, &hash("bb"), 2000),
    ]);
    assert_eq!(settled(&b), "INCONCLUSIVE");
    assert_eq!(b["invoices_without_settlement"][0]["segment"], 1);

    let b = book(vec![invoice("payer", 0, &hash("aa"), 1000)]);
    assert_eq!(settled(&b), "INCONCLUSIVE");
    assert_eq!(b["settlements"], json!([]));
    assert_eq!(b["band"], Value::Null);
}

#[test]
fn a_settlement_with_no_invoice_held_has_nothing_to_join() {
    let b = book(vec![paid("payer", 0, Some(&hash("aa")), 1000)]);
    assert_eq!(chk(&b, 0, "invoice_join"), "NOT_PRESENT");
    assert_eq!(chk(&b, 0, "amount"), "NOT_PRESENT");
    assert_eq!(settled(&b), "INCONCLUSIVE");
}

#[test]
fn an_amountless_invoice_leaves_the_amount_absent() {
    let b = book(vec![
        invoice("payer", 0, &hash("aa"), 0),
        paid("payer", 0, Some(&hash("aa")), 1000),
    ]);
    assert_eq!(chk(&b, 0, "amount"), "NOT_PRESENT");
    assert_eq!(settled(&b), "PASS");
}

/// Each side's records form their own book; an invoice the provider saw
/// never answers for the payer's settlement.
#[test]
fn sides_are_never_joined() {
    let ex = one(vec![
        invoice("provider", 0, &hash("aa"), 1000),
        paid("payer", 0, Some(&hash("aa")), 1000),
    ]);
    let books = ex["books"].as_array().unwrap();
    assert_eq!(books.len(), 2);
    assert_eq!(books[0]["side"], "payer");
    assert_eq!(chk(&books[0], 0, "invoice_join"), "NOT_PRESENT");
    assert_eq!(books[1]["side"], "provider");
    assert_eq!(books[1]["settlements"], json!([]));
}

#[test]
fn a_record_whose_event_ref_does_not_recompute_is_inconclusive() {
    let mut record = paid("payer", 0, Some(&hash("aa")), 1000);
    record["model_attestation"]["compute_attestation"]["x-mesh-settlement-v1"]["amount_msat"] =
        json!(1001);
    let obs = Observation::from_lifecycle_record(&record).unwrap();
    assert_eq!(obs.held.status, Status::Inconclusive);
    let b = book(vec![invoice("payer", 0, &hash("aa"), 1001), record]);
    assert_eq!(chk(&b, 0, "object_held"), "INCONCLUSIVE");
    assert_eq!(settled(&b), "INCONCLUSIVE");
}

/// An invoice record that does not recompute is reported on the invoice and
/// keeps the exchange from reading settled.
#[test]
fn an_invoice_with_no_event_ref_is_reported_and_blocks_settled() {
    let mut record = invoice("payer", 0, &hash("aa"), 1000);
    record["model_attestation"]["compute_attestation"]["x-mesh-settlement-v1"]
        .as_object_mut()
        .unwrap()
        .remove("event_ref");
    let b = book(vec![record, paid("payer", 0, Some(&hash("aa")), 1000)]);
    assert_eq!(b["invoices"][0]["checks"][0]["status"], "NOT_PRESENT");
    assert_eq!(settled(&b), "INCONCLUSIVE");
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
    assert_eq!(obs.held.status, Status::Pass);
    assert_eq!(obs.side, Side::Payer);
}

#[test]
fn the_report_counts_distinct_settlements_and_never_checks_a_public_ledger() {
    let mut other = host_event(
        "payer",
        "input_settlement_observed",
        Some(0),
        Some(&hash("dd")),
        7,
    );
    other["exchange_id"] = json!("ex-other");
    let mut hashless = host_event("payer", "output_settlement_observed", Some(1), None, 9);
    hashless["exchange_id"] = json!("ex-other");
    let records = vec![
        json!({"capsule_id": "not-a-settlement"}),
        invoice("payer", 0, &hash("aa"), 1000),
        paid("payer", 0, Some(&hash("aa")), 1000),
        seal(other),
        seal(hashless),
    ];
    let all = report(records.clone(), None);
    assert_eq!(all["settlement_records"], 4);
    assert_eq!(all["settlement_records_unread"], 0);
    assert_eq!(all["disclosed_count"]["settlements"], 3);
    assert_eq!(
        all["disclosed_count"]["settlements_without_payment_hash"],
        1
    );
    assert_eq!(
        all["public_ledger_count"],
        json!({"status": "NOT_CHECKED", "reason": "no_public_ledger"})
    );
    assert_eq!(all["exchanges"].as_array().unwrap().len(), 2);
    assert_eq!(all["exchanges"][0]["exchange_id"], EX);
    assert!(all["exchanges"][0].get("result").is_none());

    let one = report(records, Some("ex-other"));
    assert_eq!(
        one["disclosed_count"]["settlements"], 3,
        "the count is the book's, not the filter's"
    );
    assert_eq!(one["exchanges"].as_array().unwrap().len(), 1);

    let none = report(Vec::<Value>::new(), Some("missing"));
    assert_eq!(none["exchanges"], json!([]));
    assert_eq!(none["disclosed_count"]["settlements"], 0);
}

/// The same payment observed twice (two records under one hash) is one
/// settlement, in the count and in the band.
#[test]
fn one_payment_is_counted_once() {
    let first = paid("payer", 0, Some(&hash("aa")), 1000);
    let mut again = host_event(
        "payer",
        "input_settlement_observed",
        Some(0),
        Some(&hash("aa")),
        1000,
    );
    again["fee_msat"] = json!(1);
    let records = vec![invoice("payer", 0, &hash("aa"), 1000), first, seal(again)];
    let r = report(records.clone(), None);
    assert_eq!(r["disclosed_count"]["settlements"], 1);
    assert_eq!(
        book(records)["band"],
        json!({"currency": "BTC", "decade": -8})
    );
}

/// A node that holds both sides of one payment counts it once; each side's
/// book still checks it on its own.
#[test]
fn both_sides_of_one_payment_count_once() {
    let records = vec![
        invoice("payer", 0, &hash("aa"), 1000),
        paid("payer", 0, Some(&hash("aa")), 1000),
        invoice("provider", 0, &hash("aa"), 1000),
        paid("provider", 0, Some(&hash("aa")), 1000),
    ];
    let r = report(records.clone(), None);
    assert_eq!(r["disclosed_count"]["settlements"], 1);
    let books = one(records)["books"].as_array().unwrap().clone();
    assert_eq!(books.len(), 2);
    for b in &books {
        assert_eq!(settled(b), "PASS", "{b:#}");
        assert_eq!(b["band"], json!({"currency": "BTC", "decade": -8}));
    }
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

fn btc(decade: i64) -> Option<Value> {
    Some(json!({"currency": "BTC", "decade": decade}))
}

/// `decade` = floor(log10(msat / 10^11)): digits(msat) - 12.
#[test]
fn bands_are_signed_decades_of_the_amount_in_btc() {
    assert_eq!(band(0), None);
    assert_eq!(band(1), btc(-11));
    assert_eq!(band(9), btc(-11));
    assert_eq!(band(10), btc(-10));
    assert_eq!(band(1000), btc(-8)); // 1 sat
    assert_eq!(band(250_000), btc(-6)); // 250 sats
    assert_eq!(band(99_999_999_999), btc(-1));
    assert_eq!(band(100_000_000_000), btc(0)); // 1 BTC
    assert_eq!(band(999_999_999_999), btc(0));
    assert_eq!(band(1_000_000_000_000), btc(1));
    // The largest amount a record can carry (JCS's 2^53-1), and u64::MAX.
    assert_eq!(band((1u64 << 53) - 1), btc(4));
    assert_eq!(band(u64::MAX), btc(8));
}
