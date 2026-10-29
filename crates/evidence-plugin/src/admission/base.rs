//! The base policy's five rows (`base/1`, #64): what admission reads about
//! any peer an attempt names, listed or not, and seals with its decision.
//!
//! - **identity**: the peer's history card verifies under the record key it
//!   announces now, with that key as its responder. A card read under another
//!   key, or a later answer that fails to verify, is no longer read; with no
//!   key known yet, the row is `not_read`, not `fail`.
//! - **key age**: the card's first checkpoint is at least [`KEY_AGE_DAYS`]
//!   old. A checkpoint's time counts as stated, witnessed or not, so a peer
//!   can backdate it: a `pass` here is not proof of age.
//! - **performed-and-settled**: this node's own book holds at least
//!   [`MIN_SETTLED`] exchange with the peer whose book reads `settled`.
//! - **disputes**: no adverse adjudication about the peer in the last
//!   [`DISPUTE_PERIOD_DAYS`] days, counted exactly as `verdict_counts::fold`
//!   counts verdicts (verified, asked for by this node, once per referee and
//!   pair). Adverse is a `contradicted` verdict naming the peer.
//! - **corroboration**: this node holds the peer's pushed half for at least
//!   [`MIN_HELD_HALVES`] exchange ("no half, no deal above T0").
//!
//! The rows decide nothing (Steven, 10-29): each decision seals them as read,
//! and the verdict stays the operator's config's (the lists and the default).
//! An adverse adjudication is a `fail` in the disputes row and never blocks on
//! its own; the operator makes it a NO in config. A card not read yet is asked
//! for in the background, and its rows read `not_read` until it comes. Every
//! threshold is a placeholder, fixed here and cited by the policy digest.
//!
//! Nothing here is read while a request waits: the card comes from a
//! background ask ([`Base::start`]), and the three local rows from a snapshot
//! a background refresh recomputes from this node's own chain every
//! [`REFRESH`].

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

pub const KEY_AGE_DAYS: i64 = 7;
pub const MIN_SETTLED: usize = 1;
pub const DISPUTE_PERIOD_DAYS: i64 = 30;
pub const MIN_HELD_HALVES: usize = 1;
/// A card is asked for again once it is this old.
const CARD_TTL: Duration = Duration::from_secs(24 * 3600);
/// The least time between two asks of one peer.
const ASK_RETRY: Duration = Duration::from_secs(3600);
pub const REFRESH: Duration = Duration::from_secs(60);

/// The thresholds, as the policy digest covers them.
pub fn thresholds() -> Value {
    json!({
        "key_age_days": KEY_AGE_DAYS,
        "min_settled": MIN_SETTLED,
        "dispute_period_days": DISPUTE_PERIOD_DAYS,
        "min_held_halves": MIN_HELD_HALVES,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowResult {
    Pass,
    Fail,
    NotRead,
}

impl RowResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotRead => "not_read",
        }
    }

    fn of(pass: bool) -> Self {
        if pass {
            Self::Pass
        } else {
            Self::Fail
        }
    }
}

/// The rows in the order a record lists them.
pub const ROWS: [&str; 5] = [
    "identity",
    "key_age",
    "performed_and_settled",
    "disputes",
    "corroboration",
];

/// A verified history card, as the rows read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    /// The answer's `artifact_digest`; a record cites it only by commitment.
    pub artifact_digest: String,
    /// The time its first checkpoint states. `None` when it doesn't parse.
    pub first_checkpoint_at: Option<DateTime<Utc>>,
    /// The record key it verified under. The card speaks for that key only:
    /// once the peer's announced key changes, it is no longer read.
    pub key_id: String,
}

/// What one ask of a peer's card came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardOutcome {
    Read(Card),
    /// The answer did not verify, or there is no key to verify it under.
    Unverifiable,
    /// A refusal, no answer, or bytes that are not an answer.
    NotRead,
}

#[derive(Default)]
struct CardEntry {
    card: Option<(Card, Instant)>,
    last: Option<CardOutcome>,
    asked_at: Option<Instant>,
    in_flight: bool,
}

/// The local rows' inputs for one peer, as [`Base::read`] resolves them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalFacts {
    pub settled: usize,
    pub held_halves: usize,
    pub adverse: usize,
}

/// The local rows' inputs from one read of this node's chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// Per peer node id (lowercase): settled exchanges and adverse verdicts.
    pub by_peer: HashMap<String, LocalFacts>,
    /// The halves held, by the key the receiver verified each under
    /// (`sender_key_id`). A receiver records no transport-attested node id
    /// (`record_push_bridge`), so a half is the peer's when its key is the
    /// peer's announced key.
    pub halves_by_key: HashMap<String, BTreeSet<String>>,
}

/// What the rows read for one attempt.
#[derive(Debug)]
pub struct Read {
    pub rows: [RowResult; 5],
    /// The card cited: `Some(artifact digest)` when one was read.
    pub card: Option<String>,
}

pub struct Base {
    ledger_dir: PathBuf,
    cards: Mutex<HashMap<String, CardEntry>>,
    /// `None` until a refresh read the chain whole: the local rows are then
    /// not read.
    facts: RwLock<Option<Facts>>,
    asks: OnceLock<tokio::sync::mpsc::UnboundedSender<String>>,
}

impl Base {
    pub fn new(ledger_dir: PathBuf) -> Self {
        Self {
            ledger_dir,
            cards: Mutex::default(),
            facts: RwLock::new(None),
            asks: OnceLock::new(),
        }
    }

    /// The rows for `peer` (a lowercase 64-hex node id) at `now`, queueing an
    /// ask of its card when one is due.
    pub fn read(&self, peer: &str, at: Instant, now: DateTime<Utc>) -> Read {
        let registry = crate::peer_keys::registry();
        let key = crate::peer_keys::announced_key_in(registry.as_deref(), peer);
        self.read_with_key(peer, key.as_deref(), at, now)
    }

    /// [`Base::read`] with `key`, the peer's announced record key now.
    fn read_with_key(
        &self,
        peer: &str,
        key: Option<&str>,
        at: Instant,
        now: DateTime<Utc>,
    ) -> Read {
        let key = key.map(str::to_ascii_lowercase);
        let (card, card_rows) = self.card_rows(peer, key.as_deref(), at, now);
        let local = self
            .facts
            .read()
            .expect("the facts lock is never poisoned")
            .as_ref()
            .map(|facts| {
                let mut local = facts.by_peer.get(peer).cloned().unwrap_or_default();
                if let Some(halves) = key.as_ref().and_then(|key| facts.halves_by_key.get(key)) {
                    local.held_halves += halves.len();
                }
                local
            });
        let local_row = |pass: fn(&LocalFacts) -> bool| {
            local
                .as_ref()
                .map_or(RowResult::NotRead, |facts| RowResult::of(pass(facts)))
        };
        let rows = [
            card_rows[0],
            card_rows[1],
            local_row(|f| f.settled >= MIN_SETTLED),
            local_row(|f| f.adverse == 0),
            local_row(|f| f.held_halves >= MIN_HELD_HALVES),
        ];
        Read { rows, card }
    }

    /// The identity and key-age rows, and the card cited. `key` is the
    /// peer's announced record key now; a card read under another key is not
    /// read.
    fn card_rows(
        &self,
        peer: &str,
        key: Option<&str>,
        at: Instant,
        now: DateTime<Utc>,
    ) -> (Option<String>, [RowResult; 2]) {
        let mut cards = self.cards.lock().expect("the card lock is never poisoned");
        let entry = cards.entry(peer.to_string()).or_default();
        if entry
            .card
            .as_ref()
            .is_some_and(|(card, _)| Some(card.key_id.as_str()) != key)
        {
            entry.card = None;
            entry.last = None;
            entry.asked_at = None;
        }
        let stale = entry
            .card
            .as_ref()
            .is_none_or(|(_, read_at)| at.duration_since(*read_at) >= CARD_TTL);
        let retry_due = entry
            .asked_at
            .is_none_or(|asked| at.duration_since(asked) >= ASK_RETRY);
        if stale && retry_due && !entry.in_flight {
            if let Some(asks) = self.asks.get() {
                if asks.send(peer.to_string()).is_ok() {
                    entry.in_flight = true;
                    entry.asked_at = Some(at);
                }
            }
        }
        if let Some((card, _)) = &entry.card {
            let key_age = card
                .first_checkpoint_at
                .map_or(RowResult::NotRead, |first| {
                    RowResult::of(now - first >= chrono::Duration::days(KEY_AGE_DAYS))
                });
            return (
                Some(card.artifact_digest.clone()),
                [RowResult::Pass, key_age],
            );
        }
        match entry.last {
            Some(CardOutcome::Unverifiable) => (None, [RowResult::Fail, RowResult::NotRead]),
            _ => (None, [RowResult::NotRead; 2]),
        }
    }

    /// What an ask of `peer`'s card came to. A card once read is kept until
    /// a newer one is read or one fails to verify: a later refusal or silence
    /// does not unread it.
    pub fn record_card(&self, peer: &str, outcome: CardOutcome, at: Instant) {
        let mut cards = self.cards.lock().expect("the card lock is never poisoned");
        let entry = cards.entry(peer.to_string()).or_default();
        entry.in_flight = false;
        match &outcome {
            CardOutcome::Read(card) => entry.card = Some((card.clone(), at)),
            CardOutcome::Unverifiable => entry.card = None,
            CardOutcome::NotRead => {}
        }
        entry.last = Some(outcome);
    }

    #[cfg(test)]
    pub fn set_facts_for_test(&self, peer: &str, facts: LocalFacts) {
        self.facts
            .write()
            .expect("the facts lock is never poisoned")
            .get_or_insert_with(Facts::default)
            .by_peer
            .insert(peer.to_string(), facts);
    }

    /// Recompute the local rows' inputs from this node's own chain. A chain
    /// that doesn't read whole leaves them not read rather than empty.
    pub fn refresh(&self, now: DateTime<Utc>) {
        let facts = local_facts(&self.ledger_dir, now);
        if facts.is_none() {
            tracing::warn!(
                "admission could not read this node's chain whole; the local rows read not_read"
            );
        }
        *self
            .facts
            .write()
            .expect("the facts lock is never poisoned") = facts;
    }

    /// Start the background ask of peers' cards and the local refresh, for
    /// the life of the process.
    pub fn start(self: &Arc<Self>, context: mesh_llm_plugin::PluginContext<'static>) {
        let (sender, mut asks) = tokio::sync::mpsc::unbounded_channel::<String>();
        if self.asks.set(sender).is_err() {
            return;
        }
        let base = self.clone();
        tokio::spawn(async move {
            let mut context = context;
            while let Some(peer) = asks.recv().await {
                let outcome = ask_card(&mut context, &peer).await;
                let read = match &outcome {
                    CardOutcome::Read(_) => "read",
                    CardOutcome::Unverifiable => "unverifiable",
                    CardOutcome::NotRead => "not_read",
                };
                tracing::info!(%peer, card = read, "admission asked a peer for its history card");
                base.record_card(&peer, outcome, Instant::now());
            }
        });
        let base = self.clone();
        tokio::spawn(async move {
            loop {
                let refreshing = base.clone();
                let _ = tokio::task::spawn_blocking(move || refreshing.refresh(Utc::now())).await;
                tokio::time::sleep(REFRESH).await;
            }
        });
    }
}

/// The Evidence Request the identity and key-age rows read: the peer's
/// history card.
pub fn card_request() -> Value {
    json!({
        "subject": {"full_history": null},
        "coverage": {"min_freshness": 1},
        "derivation": "history_card/1",
    })
}

async fn ask_card(context: &mut mesh_llm_plugin::PluginContext<'_>, peer: &str) -> CardOutcome {
    let Ok((sent, answer)) =
        crate::mesh_evidence_bridge::send_evidence_request(context, peer, &card_request()).await
    else {
        return CardOutcome::NotRead;
    };
    let registry = crate::peer_keys::registry();
    read_card(
        &sent,
        &answer,
        crate::peer_keys::announced_key_in(registry.as_deref(), peer).as_deref(),
        &crate::checkpoint_cadence::active_witness_keys(),
    )
}

/// The card in `answer` to the request `sent`, verified under `key_id` (the
/// peer's announced record key, hex).
pub fn read_card(
    sent: &[u8],
    answer: &Value,
    key_id: Option<&str>,
    witness_keys: &std::collections::BTreeMap<String, String>,
) -> CardOutcome {
    if answer.get("reason").is_some() {
        return CardOutcome::NotRead;
    }
    // No usable key yet (not announced, or announced two ways): nothing can
    // be checked, which is not a card that failed to verify.
    let Some((key_id, key)) = key_id.and_then(|key_id| {
        crate::mesh_evidence_bridge::verifying_key(key_id).map(|key| (key_id, key))
    }) else {
        return CardOutcome::NotRead;
    };
    let Ok(request) = evidence_request::request::parse_json(sent) else {
        return CardOutcome::Unverifiable;
    };
    let witness_key =
        |ts_url: &str| crate::evidence_answer::configured_witness_key(witness_keys, ts_url);
    match crate::evidence_artifact::check(sent, &request, answer, &key, &witness_key) {
        Ok(checked) if checked.checkpoints > 0 => CardOutcome::Read(Card {
            artifact_digest: checked.artifact_digest,
            first_checkpoint_at: checked
                .first_checkpoint_at
                .and_then(|at| DateTime::parse_from_rfc3339(&at).ok())
                .map(|at| at.with_timezone(&Utc)),
            key_id: key_id.to_ascii_lowercase(),
        }),
        _ => CardOutcome::Unverifiable,
    }
}

/// The local rows' inputs from this node's own chain at `ledger_dir`, or
/// `None` when the chain, or the list of adjudications it asked for, is there
/// but doesn't read whole: a torn or unreadable line could hide an adverse
/// verdict, so it is never read as "none".
pub fn local_facts(ledger_dir: &Path, now: DateTime<Utc>) -> Option<Facts> {
    for file in ["capsules.jsonl", crate::verdict_counts::REQUESTED_FILENAME] {
        match std::fs::read_to_string(ledger_dir.join(file)) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    if crate::evidence_panes::unparsable_line_count(ledger_dir) > 0 {
        return None;
    }
    let records = crate::evidence_panes::read_capsule_records(ledger_dir);
    let settled_ids = crate::evidence_panes::settled_exchange_ids(&records);
    let mut settled: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut facts = Facts::default();
    for record in &records {
        if let (Some(peer), Some(exchange)) = (
            crate::evidence_panes::full_counterparty_node_id(record),
            crate::evidence_panes::record_exchange_id(record),
        ) {
            if settled_ids.contains(exchange) {
                settled
                    .entry(peer.to_ascii_lowercase())
                    .or_default()
                    .insert(exchange.to_string());
            }
        }
        if let Some((key, half)) = held_half(record) {
            facts.halves_by_key.entry(key).or_default().insert(half);
        }
    }
    for (peer, exchanges) in settled {
        facts.by_peer.entry(peer).or_default().settled = exchanges.len();
    }
    let period = chrono::Duration::days(DISPUTE_PERIOD_DAYS);
    let verdicts =
        crate::verdict_counts::fold(&records, &crate::verdict_counts::read_requested(ledger_dir));
    for (peer, verdicts) in verdicts {
        // A verdict whose time doesn't read counts as in the period.
        let adverse = verdicts
            .iter()
            .filter(|v| v.bucket == crate::verdict_counts::CONTRADICTED)
            .filter(|v| {
                v.recorded_at
                    .as_deref()
                    .and_then(parse_minute)
                    .is_none_or(|at| now - at <= period)
            })
            .count();
        facts
            .by_peer
            .entry(peer.to_ascii_lowercase())
            .or_default()
            .adverse = adverse;
    }
    Some(facts)
}

/// `(the key the half verified under, the half's capsule id)` from a citing
/// record whose receiver checked the half's signature.
fn held_half(record: &Value) -> Option<(String, String)> {
    let received = record.pointer("/model_attestation/compute_attestation/received_half")?;
    if received.get("signature_ok").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let key = received
        .get("sender_key_id")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())?;
    let half = record
        .get("references")
        .and_then(Value::as_array)?
        .iter()
        .find(|r| r.get("citation_purpose").and_then(Value::as_str) == Some("counterparty_half"))
        .and_then(|r| r.get("digest"))
        .and_then(Value::as_str)?;
    Some((key.to_ascii_lowercase(), half.to_string()))
}

/// A sealed time, RFC 3339 or minute-granular (`2026-10-29T16:30Z`).
fn parse_minute(at: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(at)
        .ok()
        .or_else(|| {
            at.strip_suffix('Z')
                .and_then(|minute| DateTime::parse_from_rfc3339(&format!("{minute}:00Z")).ok())
        })
        .map(|at| at.with_timezone(&Utc))
}

#[cfg(test)]
mod tests;
