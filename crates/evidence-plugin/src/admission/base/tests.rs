use super::*;

const PEER: &str = "5500000000000000000000000000000000000000000000000000000000000003";
const OTHER: &str = "6600000000000000000000000000000000000000000000000000000000000004";
const REFEREE: &str = "7700000000000000000000000000000000000000000000000000000000000005";
/// The peer's announced record key in these tests.
const KEY: &str = "ab00000000000000000000000000000000000000000000000000000000000006";

fn card(age_days: i64) -> CardOutcome {
    CardOutcome::Read(Card {
        artifact_digest: "c".repeat(64),
        first_checkpoint_at: Some(Utc::now() - chrono::Duration::days(age_days)),
        key_id: KEY.to_string(),
    })
}

impl Base {
    /// [`Base::read`] with [`KEY`] announced for the peer.
    fn read_keyed(&self, peer: &str, at: Instant, now: DateTime<Utc>) -> Read {
        self.read_with_key(peer, Some(KEY), at, now)
    }
}

fn passing() -> LocalFacts {
    LocalFacts {
        settled: 1,
        held_halves: 1,
        adverse: 0,
    }
}

fn base() -> (Base, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    (Base::new(dir.path().to_path_buf()), dir)
}

#[test]
fn no_card_read_yet_is_not_read_and_queues_one_ask() {
    let (base, _dir) = base();
    let (sender, mut asks) = tokio::sync::mpsc::unbounded_channel();
    base.asks.set(sender).unwrap();
    let at = Instant::now();
    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(read.card, None);
    assert_eq!(read.rows, [RowResult::NotRead; 5], "nothing read yet");
    assert_eq!(asks.try_recv().as_deref(), Ok(PEER));
    base.read_keyed(PEER, at, Utc::now());
    assert!(asks.try_recv().is_err(), "one ask in flight per peer");
}

#[test]
fn a_failed_ask_leaves_the_card_rows_not_read_and_is_retried_only_after_an_hour() {
    let (base, _dir) = base();
    let (sender, mut asks) = tokio::sync::mpsc::unbounded_channel();
    base.asks.set(sender).unwrap();
    let at = Instant::now();
    base.read_keyed(PEER, at, Utc::now());
    asks.try_recv().unwrap();
    base.record_card(PEER, CardOutcome::NotRead, at);
    base.set_facts_for_test(PEER, passing());

    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(read.rows[..2], [RowResult::NotRead; 2]);
    assert_eq!(read.rows[2..], [RowResult::Pass; 3]);
    assert!(asks.try_recv().is_err(), "not asked again within the hour");

    base.read_keyed(PEER, at + ASK_RETRY, Utc::now());
    assert_eq!(asks.try_recv().as_deref(), Ok(PEER));
}

#[test]
fn a_card_that_does_not_verify_fails_identity() {
    let (base, _dir) = base();
    let at = Instant::now();
    base.record_card(PEER, CardOutcome::Unverifiable, at);
    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(read.rows[0], RowResult::Fail);
    assert_eq!(read.rows[1], RowResult::NotRead);
}

#[test]
fn each_row_fails_on_its_own_input_alone() {
    let cases: [(CardOutcome, LocalFacts, usize); 4] = [
        (card(KEY_AGE_DAYS - 1), passing(), 1),
        (
            card(30),
            LocalFacts {
                settled: 0,
                ..passing()
            },
            2,
        ),
        (
            card(30),
            LocalFacts {
                adverse: 1,
                ..passing()
            },
            3,
        ),
        (
            card(30),
            LocalFacts {
                held_halves: 0,
                ..passing()
            },
            4,
        ),
    ];
    for (card, facts, failing) in cases {
        let (base, _dir) = base();
        let at = Instant::now();
        base.record_card(PEER, card, at);
        base.set_facts_for_test(PEER, facts);
        let read = base.read_keyed(PEER, at, Utc::now());
        for (i, row) in read.rows.iter().enumerate() {
            let expected = if i == failing {
                RowResult::Fail
            } else {
                RowResult::Pass
            };
            assert_eq!(*row, expected, "{} while {} fails", ROWS[i], ROWS[failing]);
        }
    }
}

#[test]
fn a_card_old_enough_passes_every_row_and_is_cited() {
    let (base, _dir) = base();
    let at = Instant::now();
    base.record_card(PEER, card(KEY_AGE_DAYS), at);
    base.set_facts_for_test(PEER, passing());
    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(read.rows, [RowResult::Pass; 5]);
    assert_eq!(read.card.as_deref(), Some("c".repeat(64).as_str()));
}

#[test]
fn before_the_first_refresh_the_local_rows_are_not_read() {
    let (base, _dir) = base();
    let at = Instant::now();
    base.record_card(PEER, card(30), at);
    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(
        read.rows[2..],
        [RowResult::NotRead; 3],
        "an unread dispute row never passes"
    );
}

#[test]
fn a_later_refusal_keeps_the_card_already_read() {
    let (base, _dir) = base();
    let at = Instant::now();
    base.record_card(PEER, card(30), at);
    base.record_card(PEER, CardOutcome::NotRead, at + CARD_TTL);
    let read = base.read_keyed(PEER, at + CARD_TTL, Utc::now());
    assert_eq!(read.rows[..2], [RowResult::Pass; 2]);
    assert!(read.card.is_some());
}

fn write_ledger(dir: &Path, records: &[Value]) {
    let lines: Vec<String> = records.iter().map(Value::to_string).collect();
    std::fs::write(dir.join("capsules.jsonl"), lines.join("\n")).unwrap();
}

fn exchange(peer: &str, exchange_id: &str) -> Value {
    json!({"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {
        "role": "requested",
        "serving_provenance": {"exchange_id": exchange_id, "served_by_node_id": peer},
    }}}})
}

fn settlement(exchange_id: &str, phase: &str) -> Value {
    let source = if phase.ends_with("_settlement_observed") {
        "wallet_reported"
    } else {
        "provider_asserted"
    };
    json!({"model_attestation": {"compute_attestation": {"x-mesh-settlement-v1": {
        "v": 1, "observed_by": "payer", "exchange_id": exchange_id,
        "phase": phase, "source": source, "segment": 0, "payment_hash": "aa",
    }}}})
}

/// A citing record as `producer::capsule` seals one: the sender's verified
/// key, no node id.
fn citing(key: &str, half: &str, signature_ok: bool) -> Value {
    json!({
        "references": [{"citation_purpose": "counterparty_half", "digest": half}],
        "model_attestation": {"compute_attestation": {"received_half": {
            "cited_capsule_id": half, "received_from": "some-peer", "via": "record_push",
            "signature_ok": signature_ok, "sender_key_id": key,
        }}},
    })
}

fn verdict(verdict: &str, id: &str, at: &str) -> Value {
    json!({"model_attestation": {"compute_attestation": {"adjudication_issued": {
        "verdict": verdict, "verdict_capsule_id": id, "referee_node_id": REFEREE,
        "halves": [format!("{id}-a"), format!("{id}-b")], "half_node_ids": [PEER, OTHER],
        "issued_at": at,
    }}}})
}

#[test]
fn local_facts_count_settled_exchanges_held_halves_and_adverse_verdicts_in_the_period() {
    let dir = tempfile::tempdir().unwrap();
    let now = DateTime::parse_from_rfc3339("2026-10-29T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    write_ledger(
        dir.path(),
        &[
            exchange(PEER, "ex-paid"),
            exchange(PEER, "ex-unpaid"),
            exchange(OTHER, "ex-other"),
            settlement("ex-paid", "input_invoice_issued"),
            settlement("ex-paid", "input_settlement_observed"),
            settlement("ex-unpaid", "input_invoice_issued"),
            citing(KEY, "half-1", true),
            citing(KEY, "half-1", true),
            citing(KEY, "half-2", false),
            // This node issued both (it is the referee's own judgment, so it
            // counts with no request on file).
            verdict(
                &format!("contradicted:{PEER}"),
                "v-recent",
                "2026-10-20T00:00Z",
            ),
            verdict(
                &format!("contradicted:{PEER}"),
                "v-old",
                "2026-09-01T00:00Z",
            ),
        ],
    );
    let facts = local_facts(dir.path(), now).expect("the chain reads whole");
    assert_eq!(
        facts.by_peer.get(PEER),
        Some(&LocalFacts {
            settled: 1,
            held_halves: 0,
            adverse: 1,
        }),
        "one settled exchange, one adverse verdict in 30 days"
    );
    assert_eq!(
        facts.halves_by_key.get(KEY).map(BTreeSet::len),
        Some(1),
        "one verified half, counted once, under the key it verified under"
    );
    assert_eq!(
        facts.by_peer.get(OTHER).map(|f| f.adverse),
        Some(0),
        "a contradiction naming the other twin corroborates this one"
    );
    assert_eq!(facts.by_peer.get(OTHER).map(|f| f.settled), Some(0));

    // The rows resolve the half to the peer through its announced key.
    let base = Base::new(dir.path().to_path_buf());
    base.refresh(now);
    let at = Instant::now();
    base.record_card(PEER, card(30), at);
    assert_eq!(base.read_keyed(PEER, at, now).rows[4], RowResult::Pass);
    assert_eq!(
        base.read_with_key(PEER, Some(&"ef".repeat(32)), at, now)
            .rows[4],
        RowResult::Fail,
        "a half under another key is not this peer's"
    );
}

#[test]
fn a_chain_that_does_not_read_whole_leaves_the_local_rows_not_read() {
    let dir = tempfile::tempdir().unwrap();
    let now = Utc::now();
    assert!(
        local_facts(dir.path(), now).is_some(),
        "an empty book reads"
    );
    std::fs::write(
        dir.path().join("capsules.jsonl"),
        format!(
            "{}\n{{torn",
            verdict(&format!("contradicted:{PEER}"), "v", "2026-10-29T00:00Z")
        ),
    )
    .unwrap();
    assert!(
        local_facts(dir.path(), now).is_none(),
        "a torn line could hide an adverse verdict"
    );
    let base = Base::new(dir.path().to_path_buf());
    base.refresh(now);
    assert_eq!(
        base.read_keyed(PEER, Instant::now(), now).rows[2..],
        [RowResult::NotRead; 3]
    );
}

#[test]
fn a_card_read_under_another_key_or_failing_later_is_no_longer_read() {
    let (base, _dir) = base();
    let (sender, mut asks) = tokio::sync::mpsc::unbounded_channel();
    base.asks.set(sender).unwrap();
    let at = Instant::now();
    base.record_card(PEER, card(30), at);
    let rotated = "cd".repeat(32);
    let read = base.read_with_key(PEER, Some(&rotated), at, Utc::now());
    assert_eq!(read.card, None, "the old card speaks for the old key only");
    assert_eq!(read.rows[..2], [RowResult::NotRead; 2]);
    assert_eq!(
        asks.try_recv().as_deref(),
        Ok(PEER),
        "and the new key's card is asked for"
    );

    let (base, _dir) = self::base();
    base.record_card(PEER, card(30), at);
    base.record_card(PEER, CardOutcome::Unverifiable, at);
    let read = base.read_keyed(PEER, at, Utc::now());
    assert_eq!(read.card, None);
    assert_eq!(
        read.rows[0],
        RowResult::Fail,
        "the newer answer did not verify"
    );
}

#[test]
fn a_refusal_or_an_answer_with_no_key_is_never_a_card() {
    let sent = serde_json::to_vec(&card_request()).unwrap();
    assert_eq!(
        read_card(
            &sent,
            &json!({"reason": "policy_declined"}),
            None,
            &Default::default()
        ),
        CardOutcome::NotRead
    );
    assert_eq!(
        read_card(&sent, &json!({"artifact": {}}), None, &Default::default()),
        CardOutcome::NotRead,
        "no key known yet is not a failed check"
    );
    let key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes(),
    );
    assert_eq!(
        read_card(
            &sent,
            &json!({"artifact": {}}),
            Some(&key),
            &Default::default()
        ),
        CardOutcome::Unverifiable
    );
}

#[test]
fn minute_granular_times_parse() {
    assert!(parse_minute("2026-10-20T00:00Z").is_some());
    assert!(parse_minute("2026-10-20T00:00:00Z").is_some());
    assert!(parse_minute("yesterday").is_none());
}
