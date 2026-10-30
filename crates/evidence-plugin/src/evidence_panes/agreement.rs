//! Service evidence agreement coverage on the Exchanges rows (design R7, R8,
//! R13).
//!
//! Each row whose own half this node sealed gets `agreement`, computed by
//! this node alone, for its side of the exchange (`side`: `requester` for a
//! requested half, `provider` for a served one). The other side keeps its own
//! figures on its own node; the two can differ (the requester counts its
//! requested halves, which can include exchanges the provider never served).
//!
//! `coverage` is one label, the first that applies in this order:
//!
//! - `set_up_after`: the half cites nothing and the first session with this
//!   counterparty started after it ("not covered: agreement set up after this
//!   exchange").
//! - `outside_window`, `over_count`, `over_cap`: the half cites a session it
//!   is not covered by. Over cap is "not covered", never a failed exchange.
//! - `cap_not_evaluable`: a payment of this or an earlier exchange under the
//!   session has no observation held, so the known sum is only a lower bound
//!   and does not exceed the cap.
//! - `not_cited`: a session with this counterparty holds the half's time, but
//!   the half cites none ("agreement present; exchange does not cite it").
//! - `covered`.
//! - `no_agreement`: no session with this counterparty bears on the half. A
//!   half whose counterparty this node cannot name gets this too: no session
//!   is guessed for it.
//!
//! Count and cap run per session in this node's own log order. The count is
//! the half's position among this side's halves citing the session. The cap
//! sums, over every payment of every exchange citing the session, this
//! side's own observation: the payer's `payer_observed.amount` (routing fee
//! excluded) or the provider's `payee_observed.received`. An exchange's
//! payments are the invoices this node's own lifecycle records name under the
//! exchange's id, joined to a leg by `payment_ref`, so a leg that cites
//! nothing still counts (R12). The spend cap is the requester's own
//! assertion (`agent_origin_assertion`, §11.1.6).
//!
//! `finding` is the interop profile's §11.1.8 finding over the provider's
//! served half, read as the acceptor's execution record (R3), with the
//! session's proposal, accepted record and receipt. `requirements` maps it
//! and the served half to the contract's requirement results (R8).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use evidence_request::acceptance::{self, ExecutionRecord, Finding, Inputs, TrustPolicy};
use evidence_request::time::parse_rfc3339;
use serde_json::{json, Value};

use super::settlement::SettlementIndex;
use super::{label_role, poc_block, record_exchange_id};
use crate::agreement;
use crate::agreement_bridge::SessionView;

/// How the reader names the citation it reads from a half (R3).
const READER_METHOD: &str = "x-mesh-poc-v1/acceptance_digest";

/// What reading coverage needs beyond the rows and records.
pub(super) struct Context<'a> {
    /// The complete sessions this node keeps.
    pub sessions: &'a [SessionView],
    /// The peer key registry (`crate::peer_keys::registry`): node id to key.
    pub registry: Option<&'a str>,
    /// The settlement legs this node sealed, in log order.
    pub legs: &'a [Value],
    pub settlements: &'a SettlementIndex,
    /// When trust is decided (Unix seconds).
    pub now: i64,
}

/// A settlement leg: a record carrying the -00 `settlement` member.
pub(super) fn is_settlement_leg(record: &Value) -> bool {
    record.get("settlement").is_some_and(Value::is_object)
}

/// Attach `agreement` to every row of `pane` whose own half is in `records`.
pub(super) fn attach_rows(pane: &mut Value, records: &[Value], ctx: &Context<'_>) {
    let Some(rows) = pane.get_mut("rows").and_then(Value::as_array_mut) else {
        return;
    };
    let by_id: HashMap<&str, &Value> = records
        .iter()
        .filter(|r| !is_settlement_leg(r))
        .filter_map(|r| Some((r.get("capsule_id")?.as_str()?, r)))
        .collect();
    let cell_id = |row: &Value, cell: &str| {
        row.get(cell)
            .and_then(|c| c.get("capsule_id"))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let own: BTreeSet<String> = rows.iter().filter_map(|row| cell_id(row, "mine")).collect();
    let tally = Tally::new(records, &own, ctx);
    for row in rows.iter_mut() {
        let Some(half) = cell_id(row, "mine").and_then(|id| by_id.get(id.as_str()).copied()) else {
            continue;
        };
        let theirs = cell_id(row, "theirs").and_then(|id| by_id.get(id.as_str()).copied());
        if let Some(value) = coverage(half, theirs, &tally, ctx) {
            row["agreement"] = value;
        }
    }
}

/// Which side of the exchange a half is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Requester,
    Provider,
}

impl Side {
    fn of(half: &Value) -> Option<Side> {
        match label_role(half) {
            "requested" => Some(Side::Requester),
            "served" => Some(Side::Provider),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Side::Requester => "requester",
            Side::Provider => "provider",
        }
    }

    /// The session's key for this side and for the counterparty.
    fn keys(self, s: &SessionView) -> (&str, &str) {
        match self {
            Side::Requester => (&s.proposer, &s.acceptor),
            Side::Provider => (&s.acceptor, &s.proposer),
        }
    }
}

/// The digest a half cites in its `acceptance` member, if any.
fn cited(half: &Value) -> Option<&str> {
    let link = poc_block(half)?.get("acceptance")?;
    (link.get("type").and_then(Value::as_str) == Some("cites"))
        .then(|| link.get("target").and_then(Value::as_str))
        .flatten()
}

fn half_time(half: &Value) -> Option<i64> {
    let t = half.get("timestamp")?.as_str()?;
    parse_rfc3339(t).map(|t| t.seconds)
}

fn provenance_text<'a>(half: &'a Value, key: &str) -> Option<&'a str> {
    poc_block(half)?
        .get("serving_provenance")?
        .get(key)?
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "unknown")
}

/// The counterparty's node id as the half names it: the provider a requested
/// half was served by, the requester a served half was asked by.
fn counterparty_node(half: &Value, side: Side) -> Option<&str> {
    match side {
        Side::Requester => provenance_text(half, "served_by_node_id"),
        Side::Provider => provenance_text(half, "requesting_party"),
    }
}

/// Per session, the running count and spend of this side's citing halves, in
/// this node's log order.
struct Tally {
    by_half: HashMap<String, Position>,
}

#[derive(Clone, Copy)]
struct Position {
    ordinal: u64,
    known_msat: u64,
    /// Some payment of this or an earlier exchange has no observation held.
    lower_bound: bool,
}

impl Tally {
    fn new(records: &[Value], own: &BTreeSet<String>, ctx: &Context<'_>) -> Tally {
        let observed = observations(ctx.legs);
        let mut running: HashMap<&str, Position> = HashMap::new();
        let mut by_half = HashMap::new();
        for half in records.iter().filter(|r| !is_settlement_leg(r)) {
            let Some(id) = half.get("capsule_id").and_then(Value::as_str) else {
                continue;
            };
            let (Some(side), Some(digest)) = (Side::of(half), cited(half)) else {
                continue;
            };
            if !own.contains(id) {
                continue;
            }
            let at = running.entry(digest).or_insert(Position {
                ordinal: 0,
                known_msat: 0,
                lower_bound: false,
            });
            at.ordinal += 1;
            let hashes = ctx
                .settlements
                .invoice_hashes(record_exchange_id(half), side == Side::Provider);
            for hash in hashes {
                match observed.get(&(side.leg(), hash)) {
                    Some(msat) => at.known_msat = at.known_msat.saturating_add(*msat),
                    None => at.lower_bound = true,
                }
            }
            by_half.insert(id.to_string(), *at);
        }
        Tally { by_half }
    }
}

impl Side {
    /// The leg holding this side's own observation of a payment.
    fn leg(self) -> &'static str {
        match self {
            Side::Requester => "payer_observed",
            Side::Provider => "payee_observed",
        }
    }
}

/// `(leg, payment hash)` to the observed amount: `amount` on a payer leg,
/// `received` on a payee leg. One per payment: a later leg for the same
/// payment replaces an earlier one.
fn observations(legs: &[Value]) -> HashMap<(&'static str, String), u64> {
    let mut out = HashMap::new();
    for leg in legs {
        let s = &leg["settlement"];
        let (kind, field) = match s.get("leg").and_then(Value::as_str) {
            Some("payer_observed") => ("payer_observed", "amount"),
            Some("payee_observed") => ("payee_observed", "received"),
            _ => continue,
        };
        let hash = s
            .pointer("/payment_ref/value")
            .and_then(Value::as_str)
            .filter(|_| {
                s.pointer("/payment_ref/type").and_then(Value::as_str) == Some("ln.payment_hash")
            });
        let msat = s
            .get(field)
            .filter(|v| v.get("unit").and_then(Value::as_str) == Some("msat"))
            .and_then(|v| v.get("value"))
            .and_then(Value::as_str)
            .and_then(|v| v.parse::<u64>().ok());
        if let (Some(hash), Some(msat)) = (hash, msat) {
            out.insert((kind, hash.to_string()), msat);
        }
    }
    out
}

fn coverage(
    half: &Value,
    theirs: Option<&Value>,
    tally: &Tally,
    ctx: &Context<'_>,
) -> Option<Value> {
    let side = Side::of(half)?;
    let id = half.get("capsule_id")?.as_str()?;
    let own_key = half
        .get("key_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let t = half_time(half);
    let peer_key = counterparty_node(half, side)
        .and_then(|node| crate::peer_keys::announced_key_in(ctx.registry, node));
    let with_peer: Vec<&SessionView> = ctx
        .sessions
        .iter()
        .filter(|s| {
            let (mine, theirs) = side.keys(s);
            mine == own_key && Some(theirs) == peer_key.as_deref()
        })
        .collect();
    let in_window = |s: &SessionView| t.is_some_and(|t| s.start <= t && t <= s.end);

    let mut out = json!({ "side": side.as_str() });
    let session = match cited(half) {
        Some(digest) => {
            // A half cites only a session its own side kept; one this node
            // does not keep is not evaluated here.
            let session = ctx
                .sessions
                .iter()
                .find(|s| s.acceptance_digest == digest && side.keys(s).0 == own_key)?;
            let position = tally.by_half.get(id).copied();
            out["acceptance_digest"] = json!(digest);
            out["coverage"] = json!(cited_label(session, in_window(session), position));
            if let Some(p) = position {
                out["count"] = json!({
                    "position": p.ordinal,
                    "max_exchanges": session.terms.max_exchanges,
                });
                out["spend"] = json!({
                    "observed_msat": p.known_msat,
                    "lower_bound": p.lower_bound,
                    "spend_cap_msat": session.terms.spend_cap_msat,
                    "basis": "agent_origin_assertion",
                    "observed_by": side.leg(),
                });
            }
            session
        }
        None => {
            if let Some(s) = with_peer.iter().copied().find(|s| in_window(s)) {
                out["acceptance_digest"] = json!(s.acceptance_digest);
                out["coverage"] = json!("not_cited");
                s
            } else {
                let first = with_peer.iter().map(|s| s.start).min();
                let after = matches!((first, t), (Some(f), Some(t)) if f > t);
                out["coverage"] = json!(if after {
                    "set_up_after"
                } else {
                    "no_agreement"
                });
                return Some(out);
            }
        }
    };
    let served = match side {
        Side::Provider => Some(half),
        Side::Requester => theirs.filter(|h| Side::of(h) == Some(Side::Provider)),
    };
    let (finding, evidence) = finding(session, served, ctx);
    out["finding"] = json!(finding.map(Finding::as_str));
    out["requirements"] = requirements(session, served, finding, &evidence);
    Some(out)
}

/// The label for a half citing `session`, by the precedence in the module
/// doc.
fn cited_label(session: &SessionView, in_window: bool, position: Option<Position>) -> &'static str {
    let Some(p) = position else {
        return "cap_not_evaluable";
    };
    if !in_window {
        "outside_window"
    } else if session
        .terms
        .max_exchanges
        .is_some_and(|max| p.ordinal > max)
    {
        "over_count"
    } else if p.known_msat > session.terms.spend_cap_msat {
        "over_cap"
    } else if p.lower_bound {
        "cap_not_evaluable"
    } else {
        "covered"
    }
}

/// The §11.1.8 finding for `session` over the served half, when held, and
/// the digests each claim lists as evidence.
fn finding(
    session: &SessionView,
    served: Option<&Value>,
    ctx: &Context<'_>,
) -> (Option<Finding>, Vec<String>) {
    let Some(accepted) = acceptance::parse(&session.accepted) else {
        return (None, Vec::new());
    };
    let transaction = accepted.get("transaction").cloned().unwrap_or(Value::Null);
    let served_octets = served.and_then(|h| serde_json::to_vec(h).ok());
    let execution: Vec<&[u8]> = served_octets.as_deref().into_iter().collect();
    let trust = TrustPolicy {
        parties: party_map(ctx.registry, &session.proposer, &session.acceptor),
        ..TrustPolicy::default()
    };
    let result = acceptance::evaluate(
        &Inputs {
            contract: &agreement::contract(),
            transaction: &transaction,
            proposer: &session.proposer,
            acceptor: &session.acceptor,
            records: &[&session.proposed, &session.accepted],
            execution_records: &execution,
            receipts: &[&session.receipt],
            trust: &trust,
            evaluation_time: &agreement::profile_time(ctx.now),
            session: true,
            form_ii_objects: 0,
            profiles_implemented: &[acceptance::PROFILE_ID],
        },
        read_served_half,
    );
    match result {
        Ok(r) => (Some(r.finding), r.evidence),
        Err(error) => {
            tracing::warn!(%error, "service evidence agreement not evaluated");
            (None, Vec::new())
        }
    }
}

/// The relying party's key-to-party map (R4): every key the peer key
/// registry announces, mapped to its node, so a node that announces another
/// key is still one party. A session party no announcement names (this
/// node's own key) is its own party.
fn party_map(registry: Option<&str>, proposer: &str, acceptor: &str) -> BTreeMap<String, String> {
    let mut parties: BTreeMap<String, String> = registry
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
        .and_then(|v| v.as_object().cloned())
        .into_iter()
        .flatten()
        .filter_map(|(node, key)| Some((key.as_str()?.to_string(), node)))
        .filter(|(key, _)| !key.is_empty())
        .collect();
    for key in [proposer, acceptor] {
        parties
            .entry(key.to_string())
            .or_insert_with(|| format!("key:{key}"));
    }
    parties
}

/// The Mesh reader (R3): a half Capsule as an execution record. Its issuer is
/// the key its producer envelope verifies under, once its Class 1 checks
/// pass; its action time is its own `timestamp`; it cites what its
/// `acceptance` member cites. A session names no transaction per record.
fn read_served_half(octets: &[u8]) -> Option<ExecutionRecord> {
    let half: Value = serde_json::from_slice(octets).ok()?;
    let issuer = verified_issuer(&half);
    Some(ExecutionRecord {
        issuer,
        action_at: half
            .get("timestamp")
            .and_then(Value::as_str)
            .map(String::from),
        cites: cited(&half).map(String::from).into_iter().collect(),
        transaction: None,
        method: READER_METHOD.into(),
    })
}

/// The key `half` verifies under, when it passes its Class 1 checks and its
/// producer envelope verifies.
fn verified_issuer(half: &Value) -> Option<String> {
    if !capsule_emit_lib::structure::check_structure(half).ok() {
        return None;
    }
    capsule_emit_lib::cose::verify_producer_envelope(half).ok()
}

/// The contract's requirement results (R8). `R-prior` follows the finding;
/// `R-served` needs the served half held and verifying; `R-model-stated`
/// needs the model that half states to be one the session's policy names,
/// as stated, never verified. Each result names what it relies on.
fn requirements(
    session: &SessionView,
    served: Option<&Value>,
    finding: Option<Finding>,
    evidence: &[String],
) -> Value {
    let prior = match finding {
        Some(Finding::AcceptedBeforeAction) => "met",
        Some(Finding::AcceptedAfterAction) => "not_met",
        _ => "not_evaluable",
    };
    let served_ok = served.map(|h| verified_issuer(h).is_some());
    let served_result = match served_ok {
        Some(true) => "met",
        Some(false) => "not_met",
        None => "not_evaluable",
    };
    let model = served.filter(|_| served_ok == Some(true)).and_then(|h| {
        poc_block(h)?
            .pointer("/serving_provenance/model/canonical_ref")?
            .as_str()
    });
    let model_result = match (served_ok, model) {
        (Some(true), Some(m)) if session.models.iter().any(|x| x == m) => "met",
        (Some(true), _) => "not_met",
        _ => "not_evaluable",
    };
    let served_id = served.and_then(|h| h.get("capsule_id")).cloned();
    json!([
        {
            "id": "R-prior",
            "result": prior,
            "contract_ref": agreement::CONTRACT_REF,
            "evidence": evidence,
        },
        {"id": "R-served", "result": served_result, "evidence": served_id},
        {
            "id": "R-model-stated",
            "result": model_result,
            "stated_model": model,
            "basis": "stated",
            "evidence": served_id,
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "aa";
    const PEER_KEY: &str = "bb";
    const PEER_NODE: &str = "node-b";
    const T0: i64 = 1_793_000_000;

    fn session(digest: &str, start: i64, max: Option<u64>, cap: u64) -> SessionView {
        SessionView {
            acceptance_digest: digest.into(),
            proposer: PEER_KEY.into(),
            acceptor: ME.into(),
            start,
            end: start + 3_600,
            models: vec!["m".into()],
            terms: agreement::Terms {
                spend_cap_msat: cap,
                max_exchanges: max,
            },
            proposed: Vec::new(),
            accepted: Vec::new(),
            receipt: Vec::new(),
        }
    }

    /// A served half sealed by this node at `at`, for host exchange `ex`,
    /// citing `digest` when given.
    fn served(id: &str, at: i64, ex: &str, digest: Option<&str>) -> Value {
        let mut poc = json!({
            "role": "served",
            "serving_provenance": {"exchange_id": ex, "requesting_party": PEER_NODE},
        });
        if let Some(d) = digest {
            poc["acceptance"] = crate::producer::capsule::acceptance_link(d);
        }
        json!({
            "capsule_id": id,
            "key_id": ME,
            "timestamp": agreement::committed_time(at),
            "model_attestation": {"compute_attestation": {"x-mesh-poc-v1": poc}},
        })
    }

    fn invoice(ex: &str, hash: &str) -> Value {
        json!({"model_attestation": {"compute_attestation": {"x-mesh-settlement-v1": {
            "observed_by": "provider", "exchange_id": ex,
            "phase": "input_invoice_issued", "segment": 0, "payment_hash": hash,
        }}}})
    }

    fn payee_leg(hash: &str, received: u64, cites: Option<&str>) -> Value {
        let mut leg = json!({"settlement": {
            "leg": "payee_observed",
            "received": {"value": received.to_string(), "unit": "msat"},
            "payment_ref": {"type": "ln.payment_hash", "value": hash},
        }});
        if let Some(d) = cites {
            leg["model_attestation"] = json!({"compute_attestation": {"x-mesh-poc-v1": {
                "acceptance": crate::producer::capsule::acceptance_link(d),
            }}});
        }
        leg
    }

    fn pane(halves: &[&Value]) -> Value {
        let rows: Vec<Value> = halves
            .iter()
            .map(|h| json!({"mine": {"capsule_id": h["capsule_id"]}}))
            .collect();
        json!({ "rows": rows })
    }

    /// `agreement` on each row, after attaching with these inputs.
    fn attached(
        halves: &[Value],
        sessions: &[SessionView],
        invoices: &[Value],
        legs: &[Value],
    ) -> Vec<Value> {
        let mut index = SettlementIndex::default();
        for record in invoices {
            index.push(record.clone());
        }
        let registry = json!({ PEER_NODE: PEER_KEY }).to_string();
        let ctx = Context {
            sessions,
            registry: Some(&registry),
            legs,
            settlements: &index,
            now: T0 + 7_200,
        };
        let mut p = pane(&halves.iter().collect::<Vec<_>>());
        attach_rows(&mut p, halves, &ctx);
        p["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["agreement"].clone())
            .collect()
    }

    fn coverage_of(rows: &[Value]) -> Vec<&str> {
        rows.iter()
            .map(|r| r["coverage"].as_str().unwrap())
            .collect()
    }

    /// Count and cap run in log order: the third citing exchange is over a
    /// count of two, and the one whose payment takes the sum past the cap is
    /// over cap; a window miss outranks both.
    #[test]
    fn count_cap_and_window_follow_log_order_and_precedence() {
        let s = session("d1", T0, Some(3), 1_500);
        let halves = [
            served("h1", T0 + 60, "e1", Some("d1")),
            served("h2", T0 + 120, "e2", Some("d1")),
            served("h3", T0 + 180, "e3", Some("d1")),
            served("h4", T0 + 240, "e4", Some("d1")),
            served("h5", T0 + 4_000, "e5", Some("d1")),
        ];
        let invoices: Vec<Value> = (1..=5)
            .map(|n| invoice(&format!("e{n}"), &format!("p{n}")))
            .collect();
        let legs: Vec<Value> = (1..=5)
            .map(|n| payee_leg(&format!("p{n}"), 500, None))
            .collect();
        let rows = attached(&halves, &[s], &invoices, &legs);
        assert_eq!(
            coverage_of(&rows),
            [
                "covered",
                "covered",
                "covered",
                "over_count",
                "outside_window"
            ]
        );
        assert_eq!(rows[2]["spend"]["observed_msat"], json!(1_500));
        assert_eq!(rows[2]["spend"]["basis"], json!("agent_origin_assertion"));
        assert_eq!(rows[3]["count"], json!({"position": 4, "max_exchanges": 3}));

        let tight = session("d1", T0, None, 900);
        let rows = attached(&halves[..3], &[tight], &invoices, &legs);
        assert_eq!(coverage_of(&rows), ["covered", "over_cap", "over_cap"]);
    }

    /// R12's condition: a payee leg that cites nothing (two sessions were
    /// open at once) still counts toward the cap through the exchange
    /// binding, so the sum is the same as with every leg cited.
    #[test]
    fn an_uncited_payee_leg_still_counts_toward_the_cap() {
        let sessions = [
            session("d1", T0, None, 10_000),
            session("d2", T0, None, 10_000),
        ];
        let halves = [
            served("h1", T0 + 60, "e1", Some("d1")),
            served("h2", T0 + 120, "e2", Some("d2")),
            served("h3", T0 + 180, "e3", Some("d1")),
        ];
        let invoices = [
            invoice("e1", "p1"),
            invoice("e2", "p2"),
            invoice("e3", "p3"),
        ];
        let sum =
            |legs: &[Value]| attached(&halves, &sessions, &invoices, legs)[2]["spend"].clone();
        let uncited = sum(&[
            payee_leg("p1", 700, None),
            payee_leg("p2", 50, None),
            payee_leg("p3", 300, None),
        ]);
        let cited = sum(&[
            payee_leg("p1", 700, Some("d1")),
            payee_leg("p2", 50, Some("d2")),
            payee_leg("p3", 300, Some("d1")),
        ]);
        assert_eq!(
            uncited["observed_msat"],
            json!(1_000),
            "d1's two payments only"
        );
        assert_eq!(uncited, cited);
    }

    /// A payment with no observation held makes this and every later
    /// exchange a lower bound: over cap only once the known sum exceeds it,
    /// otherwise no cap conclusion. When the observation arrives, the
    /// figures are recomputed.
    #[test]
    fn a_missing_observation_is_a_lower_bound_until_it_arrives() {
        let s = session("d1", T0, None, 1_000);
        let halves = [
            served("h1", T0 + 60, "e1", Some("d1")),
            served("h2", T0 + 120, "e2", Some("d1")),
            served("h3", T0 + 180, "e3", Some("d1")),
        ];
        let invoices = [
            invoice("e1", "p1"),
            invoice("e2", "p2"),
            invoice("e3", "p3"),
        ];
        let gap = [payee_leg("p2", 400, None), payee_leg("p3", 700, None)];
        let rows = attached(&halves, std::slice::from_ref(&s), &invoices, &gap);
        assert_eq!(
            coverage_of(&rows),
            ["cap_not_evaluable", "cap_not_evaluable", "over_cap"]
        );
        assert_eq!(rows[1]["spend"]["lower_bound"], json!(true));

        let filled = [payee_leg("p1", 100, None), gap[0].clone(), gap[1].clone()];
        let rows = attached(&halves, &[s], &invoices, &filled);
        assert_eq!(coverage_of(&rows), ["covered", "covered", "over_cap"]);
    }

    /// A half that cites nothing: "agreement present" when a session with
    /// its counterparty holds its time, "set up after" when the first such
    /// session started later, and "no agreement" when no session bears on
    /// it or its counterparty is not known. None of them reads as covered.
    #[test]
    fn an_uncited_half_is_labelled_by_the_sessions_around_it() {
        let s = session("d1", T0, None, 1_000);
        let mut unknown_peer = served("h4", T0 + 60, "e4", None);
        unknown_peer["model_attestation"]["compute_attestation"]["x-mesh-poc-v1"]
            ["serving_provenance"]["requesting_party"] = json!("unknown");
        let halves = [
            served("h1", T0 - 600, "e1", None),
            served("h2", T0 + 60, "e2", None),
            served("h3", T0 + 7_200, "e3", None),
            unknown_peer,
        ];
        let rows = attached(&halves, &[s], &[], &[]);
        assert_eq!(
            coverage_of(&rows),
            ["set_up_after", "not_cited", "no_agreement", "no_agreement"]
        );
        assert_eq!(rows[1]["acceptance_digest"], json!("d1"));
        assert!(rows[0].get("finding").is_none());
    }

    /// A settlement leg citing a session is never counted as an exchange.
    #[test]
    fn a_settlement_leg_is_never_a_citing_exchange() {
        let s = session("d1", T0, Some(1), 10_000);
        let mut leg = payee_leg("p0", 1, Some("d1"));
        leg["capsule_id"] = json!("leg");
        leg["key_id"] = json!(ME);
        let halves = [leg, served("h1", T0 + 60, "e1", Some("d1"))];
        let mut index = SettlementIndex::default();
        index.push(invoice("e1", "p1"));
        let ctx = Context {
            sessions: &[s],
            registry: None,
            legs: &[],
            settlements: &index,
            now: T0,
        };
        let mut p = pane(&[&halves[1]]);
        attach_rows(&mut p, &halves, &ctx);
        assert_eq!(p["rows"][0]["agreement"]["count"]["position"], json!(1));
    }

    /// The requirement results follow the finding and the served half: with
    /// no served half held, nothing is met or failed.
    #[test]
    fn requirements_without_a_served_half_are_not_evaluable() {
        let s = session("d1", T0, None, 1);
        let results = requirements(&s, None, Some(Finding::AcceptedExecutionCites), &[]);
        let all: Vec<&str> = results
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["result"].as_str().unwrap())
            .collect();
        assert_eq!(all, ["not_evaluable", "not_evaluable", "not_evaluable"]);
        let after = requirements(&s, None, Some(Finding::AcceptedAfterAction), &[]);
        assert_eq!(after[0]["result"], json!("not_met"));
    }

    /// As the plugin seals them: a session agreed `before` seconds before
    /// this minute's start, a served half that cites it, and the provider's
    /// own Exchanges row for it. The session's digest and the row's
    /// `agreement`.
    fn sealed_under_session(before: i64) -> (String, Value) {
        use crate::agreement::{Proposal, SessionTerms, Store};
        use crate::agreement_bridge::{conclude, respond, Outcome};
        use crate::capsule_emit::{CapsuleState, HostProvenance, ObservedHostExchange};
        use crate::lifecycle_channel::DispatchPath;

        const MODEL: &str = "hf:example/agreement-pane@main";
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let requester = CapsuleState::open(a.path(), "requester").unwrap();
        let provider = CapsuleState::open(b.path(), "provider").unwrap();
        // One node id per call: tests share the announced key registry.
        let requester_node = format!("{:064x}", 0xa9e_e0a1_0000u64 + before as u64);
        crate::peer_keys::announced::announce_for_test(
            &requester_node,
            &hex::encode(requester.public_key()),
        );
        // Seal in the same minute the test starts in: away from its end, so
        // the clock does not cross into the next minute while sealing.
        let mut now = chrono::Utc::now().timestamp();
        if now % 60 >= 50 {
            std::thread::sleep(std::time::Duration::from_secs((61 - now % 60) as u64));
            now = chrono::Utc::now().timestamp();
        }
        let agreed = now - now % 60 - before;
        let (rstore, pstore) = (
            Store::open(requester.ledger_dir()),
            Store::open(provider.ledger_dir()),
        );
        let proposal = Proposal::new(
            requester.signing_key(),
            &hex::encode(provider.public_key()),
            &agreement::new_session_id(),
            &SessionTerms {
                spend_cap_msat: 3_000,
                max_exchanges: Some(5),
                window_seconds: 3_600,
            },
            &[MODEL.to_string()],
            agreed,
        );
        let reply = respond(
            &provider,
            &pstore,
            &proposal.to_message(),
            &|_| true,
            agreed,
        );
        let Outcome::Accepted { session, receipt } = conclude(
            &requester,
            &rstore,
            &proposal,
            &serde_json::to_vec(&reply).unwrap(),
            agreed,
        ) else {
            panic!("accepted: {reply}")
        };
        let frame = serde_json::to_vec(&json!({ "receipt": receipt })).unwrap();
        assert_eq!(
            respond(&provider, &pstore, &frame, &|_| true, agreed),
            json!({"ok": true})
        );

        provider
            .settlement_legs()
            .decide_served_citation("p-ex", || {
                crate::agreement_bridge::served_citation(&provider, &requester_node, MODEL, now)
            });
        let observed = ObservedHostExchange {
            model: MODEL,
            exchange_id: Some("p-ex"),
            request_digest: Some("a".repeat(64).leak()),
            response_digest: None,
            tool_calls_digest: None,
            reasoning_digest: None,
            usage: None,
            host_provenance: HostProvenance {
                requested_by_node_id: Some(requester_node.clone()),
                model_canonical_ref: Some(MODEL.to_string()),
                ..HostProvenance::default()
            },
            dispatch_path: DispatchPath::RawProxy,
            nonce: None,
            peer_capsule_id: None,
            peer_capsule_id_provenance: None,
            twin_bracket_id: None,
            response_text_digest: None,
        };
        provider.emit_for_observed_host_exchange(&observed).unwrap();

        let pane = super::super::build_pane_json("pane-c", provider.ledger_dir(), None).unwrap();
        let rows = pane["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1, "{pane:#}");
        (session.acceptance_digest, rows[0]["agreement"].clone())
    }

    fn results(agreement: &Value) -> Vec<&str> {
        agreement["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["result"].as_str().unwrap())
            .collect()
    }

    /// A session agreed ten minutes before a served half that cites it
    /// reads, on the provider's own row, as covered, accepted before the
    /// exchange, with every requirement met and the accepted record and the
    /// receipt as the evidence `R-prior` relies on.
    #[test]
    fn a_sealed_served_half_under_a_session_reads_accepted_before() {
        let (digest, agreement) = sealed_under_session(600);
        assert_eq!(agreement["side"], json!("provider"));
        assert_eq!(agreement["acceptance_digest"], json!(digest));
        assert_eq!(agreement["coverage"], json!("covered"), "{agreement:#}");
        assert_eq!(
            agreement["finding"],
            json!("accepted_before_action"),
            "{agreement:#}"
        );
        assert_eq!(results(&agreement), ["met", "met", "met"], "{agreement:#}");
        let evidence = agreement["requirements"][0]["evidence"].as_array().unwrap();
        assert!(evidence.contains(&json!(digest)), "{evidence:?}");
        assert_eq!(
            evidence.len(),
            2,
            "the accepted record and the receipt: {evidence:?}"
        );
    }

    /// Every committed time is to the minute, so a served half in the
    /// receipt's own minute cannot be ordered after it: the finding is
    /// "accepted, the execution cites it" and `R-prior` is not evaluable,
    /// never "accepted after" (interop profile §11.1.5 rule 2, AAC #461).
    #[test]
    fn a_served_half_in_the_receipts_minute_reads_ordering_not_established() {
        let (_, agreement) = sealed_under_session(0);
        assert_eq!(agreement["coverage"], json!("covered"), "{agreement:#}");
        assert_eq!(
            agreement["finding"],
            json!("accepted_execution_cites"),
            "{agreement:#}"
        );
        assert_eq!(
            results(&agreement),
            ["not_evaluable", "met", "met"],
            "{agreement:#}"
        );
    }
}
