//! This node's book of asks (loop step 7, Ask): the record that it asked a
//! peer for evidence, sealed before the request is sent; the record of the
//! answer or refusal that came back; and the record that nothing did, once
//! the waiting window closed.
//!
//! **The rules are evidencebook's** (`evidencebook::ask`, the Go book's
//! `Request`, `RecordResponse` and `RecordAbsence`): the record kinds
//! (`evidence_request`, `evidence_response`, `recorded_absence`), their
//! statements, and [`evidencebook::ask::record_absence`] itself, which
//! refuses an absence while the request is pending and once any outcome is
//! recorded. This module is the [`Book`] the crate seals through: each
//! record is a local record of this node's ledger whose one block,
//! [`BLOCK`], holds the crate's entry and its commit time. The crate sees
//! the book as these records alone, in ledger order.
//!
//! **What the request record holds.** The request exactly as transmitted,
//! signed (`requester_auth`), so its JCS digest is the digest of the bytes
//! on the wire (`mesh_evidence_bridge::send_evidence_request` sends those
//! bytes). It names the peer asked (`audience`, `responder_ref`) in clear,
//! so none of these records ever leaves this node in an answer
//! (`evidence_log`'s `never_leaves`).
//!
//! **The window.** It closes at the later of the request's own `deadline`
//! and the transport's wait or the crate's minimum
//! ([`evidencebook::ask::MINIMUM_ABSENCE_WINDOW_SECONDS`]) after the request
//! was recorded ([`window_closes`]). Until then the request is pending and
//! nothing is recorded for it. A reply read inside the window is recorded
//! as a response; none by the close is recorded as an absence. The stream
//! is closed at the window's end, so a later reply is never read, and the
//! crate refuses a second outcome for a request: an absence is never
//! converted into an answer (ER "The Three-State Discipline").
//!
//! **A node that stopped inside a window** seals the absences it owes when
//! it starts again ([`seal_overdue_absences`]): the request record is all
//! it needs.

use std::time::Duration;

use evidencebook::ask::{AskError, Book, Entry, SealError, Sealed};
use evidencebook::record::{record_types, EpistemicType, Link, LinkType};
use evidencebook::store::{Record, RecordSource};
use serde_json::{json, Map, Value};

use crate::capsule_emit::CapsuleState;

/// The block of a local record that holds one entry of this book.
pub const BLOCK: &str = "evidence_book_entry";

/// Whether a ledger record is one of this book's.
pub fn is_ask_record(record: &Value) -> bool {
    entry_block(record).is_some()
}

fn entry_block(record: &Value) -> Option<&Map<String, Value>> {
    record
        .pointer("/model_attestation/compute_attestation")?
        .get(BLOCK)?
        .as_object()
}

/// The book over this node's ledger, as the crate reads and seals it:
/// every record of this book, in ledger order, as `(record id, header)`.
struct AskBook<'a> {
    capsules: &'a CapsuleState,
    now: String,
    records: Vec<(String, Map<String, Value>)>,
}

impl<'a> AskBook<'a> {
    fn open(capsules: &'a CapsuleState, now: &str) -> Self {
        let records = crate::evidence_panes::read_capsule_records(capsules.ledger_dir())
            .iter()
            .filter_map(|record| {
                let id = record.get("capsule_id")?.as_str()?.to_string();
                Some((id, entry_block(record)?.clone()))
            })
            .collect();
        Self {
            capsules,
            now: now.to_string(),
            records,
        }
    }

    fn record(&self, leaf_index: usize) -> Option<Record> {
        let (id, header) = self.records.get(leaf_index)?;
        Some(Record {
            leaf_index: leaf_index as u64,
            digest: id.clone(),
            body: serde_json::to_vec(header).ok()?,
        })
    }

    fn header(&self, record_id: &str) -> Option<&Map<String, Value>> {
        self.records
            .iter()
            .find(|(id, _)| id == record_id)
            .map(|(_, header)| header)
    }

    /// Whether a response or an absence citing `request_record_id` is
    /// recorded: the crate's own test, which [`record_response`] applies
    /// before it seals as the Go book's `RecordResponse` does.
    fn outcome_recorded(&self, request_record_id: &str) -> bool {
        self.records.iter().any(|(_, header)| {
            matches!(
                header.get("record_type").and_then(Value::as_str),
                Some(record_types::RESPONSE | record_types::RECORDED_ABSENCE)
            ) && header
                .get("links")
                .and_then(Value::as_array)
                .is_some_and(|links| {
                    links.iter().any(|l| {
                        l.get("type").and_then(Value::as_str) == Some(LinkType::Cites.as_str())
                            && l.get("target").and_then(Value::as_str) == Some(request_record_id)
                    })
                })
        })
    }
}

impl RecordSource for AskBook<'_> {
    fn record_by_digest(&self, digest: &str) -> Option<Record> {
        let leaf = self.records.iter().position(|(id, _)| id == digest)?;
        self.record(leaf)
    }
    fn record_at(&self, leaf_index: u64) -> Option<Record> {
        self.record(usize::try_from(leaf_index).ok()?)
    }
    fn correlation(&self, _id: &str) -> Vec<u64> {
        Vec::new()
    }
    fn citing(&self, _half_digest: &str) -> Vec<u64> {
        Vec::new()
    }
    fn header_of(&self, record: &Record) -> Option<Map<String, Value>> {
        serde_json::from_slice(&record.body).ok()
    }
}

impl Book for AskBook<'_> {
    fn len(&self) -> u64 {
        self.records.len() as u64
    }
    fn now(&self) -> String {
        self.now.clone()
    }
    fn seal(&mut self, entry: &Entry) -> Result<Sealed, SealError> {
        let header = header(entry, &self.now);
        let emitted = self
            .capsules
            .emit_ask_record(header.clone())
            .map_err(|e| SealError(e.to_string()))?;
        self.records.push((emitted.capsule_id.clone(), header));
        Ok(Sealed {
            record_id: emitted.capsule_id,
            committed_at: self.now.clone(),
        })
    }
    /// The checkpoint cadence cuts this ledger's checkpoints.
    fn checkpoint(&mut self) -> Result<(), SealError> {
        Ok(())
    }
}

/// The header members the crate reads back (`record_type`, `links`,
/// `statement`, `committed_at`), plus the entry's epistemic type.
fn header(entry: &Entry, committed_at: &str) -> Map<String, Value> {
    let links: Vec<Value> = entry
        .links
        .iter()
        .map(|l| json!({"type": l.link_type.as_str(), "target": l.target}))
        .collect();
    let mut header = Map::new();
    header.insert("record_type".into(), json!(entry.record_type));
    header.insert(
        "epistemic_type".into(),
        json!(entry.epistemic_type.as_str()),
    );
    header.insert("links".into(), Value::Array(links));
    header.insert("statement".into(), entry.statement.clone());
    header.insert("committed_at".into(), json!(committed_at));
    header
}

/// The record of having asked, and when its waiting window closes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    pub record_id: String,
    /// RFC 3339 UTC.
    pub window_closes: String,
}

/// Seal `request`, exactly as it will be transmitted to `responder`, as an
/// `evidence_request` record (the statement `ask::request` seals:
/// `request` and `responder_ref`). `now` is whole-second RFC 3339 UTC;
/// `wait` is how long the transport waits for a reply.
pub fn record_request(
    capsules: &CapsuleState,
    request: &Value,
    responder: &str,
    now: &str,
    wait: Duration,
) -> Result<Asked, AskError> {
    let mut book = AskBook::open(capsules, now);
    let mut statement = Map::new();
    statement.insert("request".into(), request.clone());
    if !responder.is_empty() {
        statement.insert("responder_ref".into(), json!(responder));
    }
    let sealed = book.seal(&Entry {
        record_type: record_types::REQUEST.into(),
        epistemic_type: EpistemicType::ObservedEvent,
        links: Vec::new(),
        statement: Value::Object(statement),
    })?;
    let window_closes = window_closes(
        request.get("deadline").and_then(Value::as_str),
        &sealed.committed_at,
        wait,
    )
    .ok_or_else(|| AskError::Invalid(format!("the request's deadline: {request}")))?;
    Ok(Asked {
        record_id: sealed.record_id,
        window_closes,
    })
}

/// When the waiting window of a request recorded at `committed_at` closes:
/// the later of its `deadline` and `committed_at` plus the longer of `wait`
/// and the crate's minimum. `None` when a time does not parse.
pub fn window_closes(deadline: Option<&str>, committed_at: &str, wait: Duration) -> Option<String> {
    let parse = |t: &str| chrono::DateTime::parse_from_rfc3339(t).ok();
    let minimum = Duration::from_secs(
        evidencebook::ask::MINIMUM_ABSENCE_WINDOW_SECONDS
            .try_into()
            .unwrap_or(60),
    );
    let after =
        parse(committed_at)?.to_utc() + chrono::Duration::from_std(wait.max(minimum)).ok()?;
    // Whole seconds, rounded up, so the close is never before either bound.
    let ceil = |t: chrono::DateTime<chrono::Utc>| {
        let whole = t.timestamp() + i64::from(t.timestamp_subsec_nanos() > 0);
        chrono::DateTime::from_timestamp(whole, 0)
    };
    let mut closes = ceil(after)?;
    if let Some(deadline) = deadline {
        closes = closes.max(ceil(parse(deadline)?.to_utc())?);
    }
    Some(closes.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// The outcome a reply is recorded as: the request draft's `artifact` and
/// `refusal` when it verified (or was not checked, which `verification`
/// says), and the received-and-failed sub-states the Go book names when it
/// failed. Never an absence.
fn outcome(answer: &Value, verification: &Value) -> &'static str {
    let refusal_shaped = answer.get("reason").is_some() && answer.get("artifact").is_none();
    match verification.get("state").and_then(Value::as_str) {
        Some("artifact") => "artifact",
        Some("refusal") => "refusal",
        Some("not_evidence") if refusal_shaped => "refusal_nonconformant",
        Some("not_evidence") => "artifact_verification_failed",
        _ if refusal_shaped => "refusal",
        _ => "artifact",
    }
}

/// Seal the reply that came back inside the window for the request
/// recorded as `request_record_id` as an `evidence_response` record citing
/// it: its outcome, the request's digest and what checking it found. Refused
/// once an outcome is recorded for the request, so a reply never replaces
/// an absence (or another reply).
pub fn record_response(
    capsules: &CapsuleState,
    request_record_id: &str,
    request_digest: &str,
    answer: &Value,
    verification: &Value,
    now: &str,
) -> Result<Sealed, AskError> {
    let mut book = AskBook::open(capsules, now);
    if book
        .header(request_record_id)
        .and_then(|h| h.get("record_type"))
        != Some(&json!(record_types::REQUEST))
    {
        return Err(AskError::NotFound(format!(
            "{request_record_id} is not a request this book recorded"
        )));
    }
    if book.outcome_recorded(request_record_id) {
        return Err(AskError::Invalid(format!(
            "an outcome is already recorded for request {request_digest}"
        )));
    }
    Ok(book.seal(&Entry {
        record_type: record_types::RESPONSE.into(),
        epistemic_type: EpistemicType::ObservedEvent,
        links: vec![Link {
            link_type: LinkType::Cites,
            target: request_record_id.to_string(),
        }],
        statement: json!({
            "outcome": outcome(answer, verification),
            "request_digest": request_digest,
            "verification": verification,
        }),
    })?)
}

/// Seal `recorded_absence` for the request recorded as `request_record_id`,
/// its window having closed at `window_closes`: evidencebook's
/// `record_absence`, which refuses while the request is pending and once an
/// outcome is recorded.
pub fn record_absence(
    capsules: &CapsuleState,
    request_record_id: &str,
    window_closes: &str,
    now: &str,
) -> Result<Sealed, AskError> {
    let mut book = AskBook::open(capsules, now);
    evidencebook::ask::record_absence(&mut book, request_record_id, window_closes, "")
}

/// At start: seal `recorded_absence` for every recorded request with no
/// outcome whose window (as [`window_closes`] computes it with `wait`) has
/// closed by `now`. Returns how many were sealed; one that cannot be is
/// logged and left pending.
pub fn seal_overdue_absences(capsules: &CapsuleState, now: &str, wait: Duration) -> usize {
    let mut book = AskBook::open(capsules, now);
    let Some(now_t) = chrono::DateTime::parse_from_rfc3339(now).ok() else {
        return 0;
    };
    let overdue: Vec<(String, String)> = book
        .records
        .iter()
        .filter(|(_, h)| h.get("record_type") == Some(&json!(record_types::REQUEST)))
        .filter(|(id, _)| !book.outcome_recorded(id))
        .filter_map(|(id, h)| {
            let committed_at = h.get("committed_at")?.as_str()?;
            let deadline = h
                .get("statement")
                .and_then(|s| s.pointer("/request/deadline"))
                .and_then(Value::as_str);
            let closes = window_closes(deadline, committed_at, wait)?;
            (chrono::DateTime::parse_from_rfc3339(&closes).ok()? <= now_t)
                .then(|| (id.clone(), closes))
        })
        .collect();
    let mut sealed = 0;
    for (id, closes) in overdue {
        match evidencebook::ask::record_absence(&mut book, &id, &closes, "") {
            Ok(_) => sealed += 1,
            Err(error) => {
                tracing::warn!(%error, request_record = %id, "an overdue absence could not be sealed");
            }
        }
    }
    sealed
}

#[cfg(test)]
mod tests;
