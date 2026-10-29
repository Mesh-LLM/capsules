//! The Service History (`service_history/1`, PRD-SERVICE-EVIDENCE §2, M2): a
//! Standard History under agent-action-capsule's inference-service history
//! profile (`spec/inference-service-history-profile-v0.md`, cited as ISH, at
//! cfb2462): the `history_card/1` artifact embedded unchanged, and this
//! node's served exchanges counted per closed week.
//!
//! **The derivation.** Unregistered, and named on the wire by the digest of
//! its definition document (`derivations/service-history-1.json`,
//! [`DEFINITION_DIGEST`]), which carries ISH §4.1's frame: `profile`,
//! `level` `standard`, the Standard `coverage_declaration` and the
//! `period_policy` Steven ruled on 2026-10-22 (evidencebook#46): weeks from
//! Monday 2026-01-05 00:00 UTC, a floor of 5 per cell, complementary
//! suppression. The token `service_history/1` is the document's `name`,
//! never a request's `derivation`.
//!
//! **Answered** only for `full_history` under an `expected_pin` naming an
//! anchor whose checkpoint time is a period boundary (ISH §6.1 items 2 and
//! 5, §8.4); anything else is `policy_declined`, the same for every
//! requester. The checkpoint cadence cuts a checkpoint at each boundary
//! (`crate::checkpoint_cadence`). It is Standard History
//! (`share_standard_history`), and when either member cannot be built the
//! whole History is refused, never served with a member dropped.
//!
//! **The artifact** is ISH §8.2's object, as its RFC 8785 octets: `anchor`,
//! `coverage_declaration` (`interval` from the stream's start to the
//! anchor, and the anchor's `live_set`), `declared`, `derivation`,
//! `evidence_stream`, `history_card`, `history_card_digest`,
//! `period_counts` and `subject`. Both members are always declared, so the
//! bytes depend only on (subject, anchor, definition): the same for every
//! requester. The envelope carries no verification material (ISH §8.1); the
//! witness receipts of the card's checkpoints ride beside it in
//! `witness_receipts`, as for a direct card.
//!
//! - `history_card` is the `history_card/1` artifact this node serves for
//!   the same subject and anchor, as a JSON value. RFC 8785 is
//!   compositional, so its canonical octets are the direct artifact's
//!   octets, and `history_card_digest` is their SHA-256.
//! - `period_counts` is `{policy, periods}` in the form of ISH §9's vectors:
//!   `policy` the digest of the definition's `period_policy`, and one entry
//!   per closed period from the one the stream's first checkpoint commits
//!   into to the one ending at the anchor, each `{from, to, cells}`. The cells
//!   count `exchanges_served`, one per model the provider states and one
//!   total (`dimension` null), all `self_reported`. A cell under the floor
//!   is published with no value and `suppressed: "below_floor"`, and
//!   where that leaves a published total beside exactly one suppressed
//!   model, the smallest other model is suppressed `complementary`
//!   (ISH §6.2). Latency is never counted (Steven, 2026-10-22).
//!
//! **Which period a record is in.** The one the first checkpoint covering it
//! commits into: the time this node's stream committed it (ISH §6.1), read
//! from the card itself. A checkpoint commits into the period holding its
//! time, except the first checkpoint at a boundary, which commits into the
//! period it ends: it closes that period, so it commits only records of the
//! periods before it (ISH §6.1 item 2). Checkpoint times are taken as never
//! going back (each is at least the one before it), so no checkpoint after
//! the one that closed a period adds to it, and a period's cells are the
//! same at every later anchor (ISH §6.1 item 4).
//!
//! **Verified** by [`check_artifact`], from `evidence_artifact::check`, which
//! first checks the envelope and the embedded card as a direct
//! `history_card/1` answer's: every checkpoint signed by the responder, the
//! list starting at the stream's first checkpoint and ending at the anchor,
//! and each consistency proof; then the witness receipts. Shown by
//! [`render`] in ISH §8.5's order.

use evidence_request::jcs;
use evidence_request::registry::{Reason, DERIVATION_HISTORY_CARD};
use evidence_request::request::Derivation;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// The definition document, as published beside this crate. Only its
/// digest is used at run time; a test pins one to the other.
#[cfg(test)]
pub const DEFINITION_DOCUMENT: &str = include_str!("../../../derivations/service-history-1.json");

/// SHA-256 over the RFC 8785 bytes of [`DEFINITION_DOCUMENT`]: the
/// derivation's name on the wire, and the artifact's `derivation`.
pub const DEFINITION_DIGEST: &str =
    "eecfeed1ccfdf08b86b55748f91684d2fdaf138e71122912c7a50dc18fb62771";

/// SHA-256 over the RFC 8785 bytes of the definition's `period_policy`.
pub const POLICY_DIGEST: &str = "0d4b28af7ebfca01a49c1ad59e74b7d9bff0e6712dd3478b4ee35b8ff6af5150";

/// The policy's `epoch`, 2026-01-05T00:00:00Z, in Unix seconds.
const EPOCH: i64 = 1_767_571_200;
/// The policy's `length_s`: one week.
pub const LENGTH_S: i64 = 604_800;
/// The policy's `floor`.
pub const FLOOR: u64 = 5;

/// The one counts member and the one unit it counts in.
const COUNTS: &str = "period_counts";
const UNIT: &str = "exchanges_served";
const LABEL: &str = "self_reported";

/// The members every artifact declares, sorted.
const DECLARED: [&str; 2] = ["history_card", COUNTS];

/// The keys of every artifact, sorted.
const KEYS: [&str; 9] = [
    "anchor",
    "coverage_declaration",
    "declared",
    "derivation",
    "evidence_stream",
    "history_card",
    "history_card_digest",
    COUNTS,
    "subject",
];

/// The most periods one answer lists: over 190 years of weeks. A stream
/// whose first checkpoint is older is refused, never answered in part.
const MAX_PERIODS: i64 = 10_000;

/// Whether `derivation` names this one.
pub fn is_derivation(derivation: Option<&Derivation>) -> bool {
    matches!(derivation, Some(Derivation::Digest(d)) if d == DEFINITION_DIGEST)
}

/// The period holding the Unix time `t`.
fn period_of(t: i64) -> i64 {
    (t - EPOCH).div_euclid(LENGTH_S)
}

/// The start of period `k`.
fn start_of(k: i64) -> i64 {
    EPOCH + k * LENGTH_S
}

/// A checkpoint time (`YYYY-MM-DDTHH:MM:SS[.f]Z`) in Unix seconds.
pub fn unix_time(timestamp: &str) -> Option<i64> {
    evidence_request::time::parse_utc(timestamp).map(|t| t.seconds)
}

/// Whether the checkpoint time `timestamp` is a period boundary: a whole
/// second that starts a period (ISH §6.1 item 2).
pub fn is_boundary(timestamp: &str) -> bool {
    evidence_request::time::parse_utc(timestamp)
        .is_some_and(|t| t.nanos == 0 && on_boundary(t.seconds))
}

/// Whether the Unix time `t` is a period boundary.
fn on_boundary(t: i64) -> bool {
    (t - EPOCH).rem_euclid(LENGTH_S) == 0
}

/// The period the stream's first checkpoint, at the Unix time `t`, commits
/// into: the one it ends when `t` is a boundary.
fn first_period(t: i64) -> i64 {
    period_of(t) - i64::from(on_boundary(t))
}

/// The first period boundary strictly after the Unix time `t`.
pub fn next_boundary_after(t: i64) -> i64 {
    start_of(period_of(t) + 1)
}

/// A Unix time in the profile's form, `YYYY-MM-DDTHH:MM:SSZ` (IP §5.2).
fn profile_time(t: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(t, 0).map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

// ---------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------

/// One checkpoint of the chain an answer reads: its time and the records
/// it covers (its leaf count).
pub(crate) struct Cut<'a> {
    pub timestamp: &'a str,
    pub leaves: u64,
}

/// The `period_counts` member at the anchor `chain.last()`. `chain` is the
/// stream's checkpoints from its first to the anchor, and `model(i)` the
/// model the record at leaf `i` states it served, `None` for a record that
/// is not a served exchange. `policy_declined` when the anchor is not at a
/// period boundary, a time does not parse, or the stream is older than
/// [`MAX_PERIODS`] periods.
pub(crate) fn period_counts(
    chain: &[Cut<'_>],
    model: &dyn Fn(u64) -> Option<String>,
) -> Result<Value, Reason> {
    let anchor = chain.last().ok_or(Reason::PolicyDeclined)?;
    if !is_boundary(anchor.timestamp) {
        return Err(Reason::PolicyDeclined);
    }
    let first = unix_time(chain[0].timestamp).ok_or(Reason::PolicyDeclined)?;
    let anchor_period = period_of(unix_time(anchor.timestamp).ok_or(Reason::PolicyDeclined)?);
    // Deliberately broken in one CI build: the period the anchor opens is
    // counted too.
    let last_counted = if cfg!(feature = "mutant-service-history-counts-open-period") {
        anchor_period
    } else {
        anchor_period - 1
    };
    let first_period = first_period(first);
    if last_counted - first_period >= MAX_PERIODS {
        return Err(Reason::PolicyDeclined);
    }
    // Per counted period, the served exchanges per model.
    let periods = (first_period..=last_counted).count();
    let mut counted: Vec<std::collections::BTreeMap<String, u64>> =
        vec![Default::default(); periods];
    let (mut committed_at, mut from_leaf, mut closed) = (i64::MIN, 0u64, i64::MIN);
    for cut in chain {
        // A checkpoint's time is never taken as earlier than the one before.
        committed_at = committed_at.max(unix_time(cut.timestamp).ok_or(Reason::PolicyDeclined)?);
        let mut k = period_of(committed_at);
        // The first checkpoint at a boundary commits into the period it
        // closes; every period before its time is closed from then on.
        if on_boundary(committed_at) && k - 1 > closed {
            k -= 1;
        }
        closed = closed.max(period_of(committed_at) - 1);
        for leaf in from_leaf..cut.leaves {
            if k > last_counted {
                break;
            }
            if let Some(m) = model(leaf) {
                *counted[(k - first_period) as usize].entry(m).or_default() += 1;
            }
        }
        from_leaf = from_leaf.max(cut.leaves);
    }
    let mut list = Vec::with_capacity(periods);
    for (i, by_model) in counted.iter().enumerate() {
        let k = first_period + i as i64;
        let (from, to) = (profile_time(start_of(k)), profile_time(start_of(k + 1)));
        let (Some(from), Some(to)) = (from, to) else {
            return Err(Reason::PolicyDeclined);
        };
        list.push(json!({"from": from, "to": to, "cells": cells(by_model)}));
    }
    Ok(json!({"policy": POLICY_DIGEST, "periods": list}))
}

/// One period's cells: one per model, by name, then the total, each
/// suppressed under ISH §6.2.
fn cells(by_model: &std::collections::BTreeMap<String, u64>) -> Vec<Value> {
    let total: u64 = by_model.values().sum();
    let mut values: Vec<(Option<&str>, u64, Option<&str>)> = by_model
        .iter()
        .map(|(m, &n)| (Some(m.as_str()), n, (n < FLOOR).then_some("below_floor")))
        .collect();
    values.push((None, total, (total < FLOOR).then_some("below_floor")));
    let models = values.len() - 1;
    let suppressed = values[..models].iter().filter(|c| c.2.is_some()).count();
    // A published total beside exactly one suppressed model gives that
    // model away: the smallest other published model goes with it.
    if values[models].2.is_none()
        && suppressed == 1
        && !cfg!(feature = "mutant-service-history-skips-complementary")
    {
        if let Some(smallest) = values[..models]
            .iter_mut()
            .filter(|c| c.2.is_none())
            .min_by_key(|c| c.1)
        {
            smallest.2 = Some("complementary");
        }
    }
    values
        .into_iter()
        .map(|(model, n, why)| {
            let mut cell = json!({
                "dimension": model.map(|m| json!({"model": m})),
                "label": LABEL,
                "unit": UNIT,
                "value": if why.is_some() { Value::Null } else { json!(n) },
            });
            if let Some(why) = why {
                cell["suppressed"] = json!(why);
            }
            cell
        })
        .collect()
}

/// The artifact's octets: `card` is the direct `history_card/1` artifact's
/// octets at `anchor`, `counts` the `period_counts` member, and `log_size`
/// the records the anchor covers. `policy_declined` when the card's octets
/// are not its own canonical form, so the embedded card could not be the
/// direct one.
pub(crate) fn artifact(
    card: &[u8],
    counts: Value,
    anchor: &str,
    stream: &str,
    log_size: u64,
) -> Result<Vec<u8>, Reason> {
    let mut card_value: Value = serde_json::from_slice(card).map_err(|_| Reason::PolicyDeclined)?;
    if jcs::to_string(&card_value)
        .map_err(|_| Reason::PolicyDeclined)?
        .as_bytes()
        != card
    {
        return Err(Reason::PolicyDeclined);
    }
    // Deliberately broken in one CI build: the card is rebuilt from its
    // checkpoint list, without the consistency proofs.
    if cfg!(feature = "mutant-service-history-card-rebuilt") {
        if let Some(history) = card_value.get_mut("history").and_then(Value::as_array_mut) {
            for entry in history {
                entry["consistency_from_previous"] = Value::Null;
            }
        }
    }
    let card_text = jcs::to_string(&card_value).map_err(|_| Reason::PolicyDeclined)?;
    let art = json!({
        "anchor": anchor,
        "coverage_declaration": coverage_declaration(anchor, stream, log_size),
        "declared": DECLARED,
        "derivation": DEFINITION_DIGEST,
        "evidence_stream": stream,
        "history_card": card_value,
        "history_card_digest": hex::encode(Sha256::digest(card_text.as_bytes())),
        COUNTS: counts,
        "subject": {"full_history": null},
    });
    jcs::to_string(&art)
        .map(String::into_bytes)
        .map_err(|_| Reason::PolicyDeclined)
}

/// The anchor-dependent half of the Standard coverage declaration
/// (ISH §4.2).
fn coverage_declaration(anchor: &str, stream: &str, log_size: u64) -> Value {
    json!({
        "interval": {"from": null, "to": anchor},
        "kind": "stream_interval",
        "live_set": [{"checkpoint": anchor, "count": log_size, "start": 0, "stream": stream}],
        "rule": "all_records",
    })
}

// ---------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------

/// One checked cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    /// The model the provider states, `None` for the period's total.
    pub model: Option<String>,
    /// The count, or why it is suppressed.
    pub value: Result<u64, String>,
}

/// One checked period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Period {
    pub from: String,
    pub to: String,
    pub cells: Vec<Cell>,
}

/// What a checked History counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counts {
    pub periods: Vec<Period>,
}

/// Check a Service History artifact `art` (already checked to name this
/// subject and derivation) against its embedded card, already checked: its
/// checkpoint times `times`, the stream's first to the anchor, the anchor
/// digest and stream, and the records the anchor covers. Every rule a
/// verifier can check from one History: the members, the card's digest and
/// subject, the coverage declaration (ISH §4.2), and `period_alignment`,
/// `period_anchor` and `period_floor` (ISH §6.3), with every closed period
/// from the stream's first listed and no cell twice.
pub(crate) fn check_artifact(
    art: &Map<String, Value>,
    times: &[&str],
    anchor: &str,
    stream: &str,
    log_size: u64,
) -> Result<Counts, String> {
    let mut keys: Vec<&str> = art.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != KEYS || art.get("declared") != Some(&json!(DECLARED)) {
        return Err("the artifact's members are not the ones the definition declares".into());
    }
    let card = &art["history_card"];
    let text = jcs::to_string(card).map_err(|_| "the card is malformed".to_string())?;
    if art.get("history_card_digest").and_then(Value::as_str)
        != Some(hex::encode(Sha256::digest(text.as_bytes())).as_str())
    {
        return Err("the card does not match history_card_digest".into());
    }
    if card.get("subject") != art.get("subject")
        || card.get("derivation").and_then(Value::as_str) != Some(DERIVATION_HISTORY_CARD)
        || card.get("anchor") != art.get("anchor")
        || card.get("evidence_stream") != art.get("evidence_stream")
    {
        return Err("the card is not for this History's subject, stream and anchor".into());
    }
    if art.get("coverage_declaration") != Some(&coverage_declaration(anchor, stream, log_size)) {
        return Err("the coverage declaration is not the Standard one at this anchor".into());
    }
    let anchor_time = *times.last().ok_or("the card lists no checkpoint")?;
    if !is_boundary(anchor_time) {
        return Err("period_anchor: the anchor's time is not a period boundary".into());
    }
    check_counts(&art[COUNTS], times)
}

/// `period_alignment` and `period_floor` over the counts member.
fn check_counts(counts: &Value, times: &[&str]) -> Result<Counts, String> {
    let malformed = |why: &str| format!("the period counts are malformed: {why}");
    let counts = counts
        .as_object()
        .ok_or_else(|| malformed("not an object"))?;
    let mut keys: Vec<&str> = counts.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != ["periods", "policy"] {
        return Err(malformed("unexpected members"));
    }
    if counts["policy"] != json!(POLICY_DIGEST) {
        return Err("period_alignment: the counts name another policy".into());
    }
    let listed = counts["periods"]
        .as_array()
        .ok_or_else(|| malformed("periods is not a list"))?;
    // Every closed period, from the one holding the first checkpoint to the
    // one the anchor closes, each once, in order.
    let first = unix_time(times[0]).ok_or_else(|| malformed("a checkpoint time"))?;
    let anchor = unix_time(times[times.len() - 1]).ok_or_else(|| malformed("the anchor time"))?;
    let expected = first_period(first)..period_of(anchor);
    if listed.len() as i64 != expected.end - expected.start {
        return Err("period_alignment: the closed periods are not each listed once".into());
    }
    let mut out = Vec::with_capacity(listed.len());
    for (period, k) in listed.iter().zip(expected) {
        let (from, to) = (profile_time(start_of(k)), profile_time(start_of(k + 1)));
        if period.get("from").and_then(Value::as_str) != from.as_deref()
            || period.get("to").and_then(Value::as_str) != to.as_deref()
            || period.as_object().map(Map::len) != Some(3)
        {
            return Err("period_alignment: a period is not the policy's next closed one".into());
        }
        out.push(Period {
            from: from.unwrap_or_default(),
            to: to.unwrap_or_default(),
            cells: check_cells(&period["cells"])?,
        });
    }
    Ok(Counts { periods: out })
}

/// `period_floor` over one period's cells: each in the counts unit and
/// label, a model at most once and exactly one total, every value at least
/// the floor, every suppressed cell without a value and with a reason, and
/// complementary suppression where it is due.
fn check_cells(cells: &Value) -> Result<Vec<Cell>, String> {
    let bad = |why: &str| format!("period_floor: {why}");
    let cells = cells.as_array().ok_or_else(|| bad("cells is not a list"))?;
    let mut out: Vec<Cell> = Vec::with_capacity(cells.len());
    for cell in cells {
        let c = cell.as_object().ok_or_else(|| bad("a cell is malformed"))?;
        if c.get("unit").and_then(Value::as_str) != Some(UNIT) {
            return Err(format!("units: a cell counts in another unit than {UNIT}"));
        }
        if c.get("label").and_then(Value::as_str) != Some(LABEL) {
            return Err(format!("labels: a count is labelled other than {LABEL}"));
        }
        let model = match c.get("dimension") {
            Some(Value::Null) => None,
            Some(Value::Object(d)) if d.len() == 1 => Some(
                d.get("model")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("a dimension is not a model"))?
                    .to_string(),
            ),
            _ => return Err(bad("a dimension is malformed")),
        };
        if out.iter().any(|o| o.model == model) {
            return Err(bad("a cell is listed twice"));
        }
        let value = match (c.get("value"), c.get("suppressed").and_then(Value::as_str)) {
            (Some(Value::Null), Some(why @ ("below_floor" | "complementary"))) if c.len() == 5 => {
                Err(why.to_string())
            }
            (Some(v), None) if c.len() == 4 => match v.as_u64() {
                Some(n) if n >= FLOOR => Ok(n),
                Some(_) => return Err(bad("a published cell is below the floor")),
                None => return Err(bad("a value is not a count")),
            },
            _ => return Err(bad("a cell is neither published nor suppressed")),
        };
        out.push(Cell { model, value });
    }
    let [total] = out.iter().filter(|c| c.model.is_none()).collect::<Vec<_>>()[..] else {
        return Err(bad("a period has no single total"));
    };
    let models: Vec<&Cell> = out.iter().filter(|c| c.model.is_some()).collect();
    if let Ok(total) = total.value {
        if models.iter().filter(|c| c.value.is_err()).count() == 1 {
            return Err(bad("a suppressed cell can be derived from the total"));
        }
        if models.iter().all(|c| c.value.is_ok())
            && models
                .iter()
                .filter_map(|c| c.value.as_ref().ok())
                .sum::<u64>()
                != total
        {
            return Err(bad("the models do not add up to the total"));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------

/// The words a rendered History never uses: continuity, a signature or a
/// receipt is never execution, and nothing ranks a node (PRD T5, §4).
#[cfg(test)]
pub const DENY_LIST: [&str; 8] = [
    "model executed",
    "verified model",
    "ran on",
    "attested",
    "score",
    "rating",
    "rank",
    "reputation",
];

/// A checked History as lines of text, in ISH §8.5's order: what the counts
/// are, each count in its own row, the checkpoints and receipts, which
/// checks did not run, and the limits.
pub fn render(
    counts: &Counts,
    checkpoints: usize,
    verified: usize,
    receipts: usize,
) -> Vec<String> {
    let mut lines = vec![
        "Every count is this node's own statement (self_reported). Checkpoint continuity, \
         witness receipts and signatures never show what was computed."
            .to_string(),
        "Coverage: every record of this node's stream up to the anchor (stream_interval, \
         all_records); completeness is not established, since the counts were not checked \
         against records."
            .to_string(),
        format!(
            "Periods of {} days; a count under {FLOOR} is withheld.",
            LENGTH_S / 86_400
        ),
    ];
    for period in &counts.periods {
        for cell in &period.cells {
            let what = match &cell.model {
                Some(m) => format!("exchanges served, model {m} (as the provider states it)"),
                None => "exchanges served, all models".to_string(),
            };
            let value = match &cell.value {
                Ok(n) => n.to_string(),
                Err(why) if why == "complementary" => {
                    "withheld (another withheld count could be derived from it)".to_string()
                }
                Err(_) => format!("withheld (under {FLOOR})"),
            };
            lines.push(format!(
                "{} to {}: {what}: {value} (self_reported)",
                period.from, period.to
            ));
        }
    }
    lines.push(format!("{checkpoints} checkpoints of this node's own log"));
    lines.push(if receipts == 0 {
        "witness receipts: no witness named".to_string()
    } else {
        format!(
            "witness receipts counted: {verified} of {receipts} (a later rewrite of this log is \
             detectable); the rest are under no configured witness key"
        )
    });
    lines.push(
        "Not checked: anchor_inclusion, coverage_declaration_population, \
         coverage_declaration_commitment, and period_fixed (one History held)."
            .to_string(),
    );
    lines.push(
        "Limits: the history card shows each checkpoint's exact log size, which the periods \
         do not cover."
            .to_string(),
    );
    lines
}

#[cfg(test)]
mod tests;
