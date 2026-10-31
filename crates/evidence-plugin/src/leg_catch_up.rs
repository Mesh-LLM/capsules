//! A payer's catch-up of its earlier `mesh/settlement/terms` legs that went
//! to the provider uncovered (Mesh-LLM/capsules-plugin#187): each is pushed
//! again, once, as a bundle under a checkpoint covering it, so the provider
//! holds its checkpoint and inclusion proof (loop step 05
//! `pushed_under_checkpoint`). It moves no money and seals nothing on this
//! node: it only re-sends records already sealed.
//!
//! **Which legs.** The sender of a push seals nothing when it succeeds (the
//! citing records are the receiver's), so this node's ledger cannot tell a
//! covered push from a bare one. What tells is the receiver's reply: it names
//! the verified inclusion only for a bundle. Each such reply for a terms leg
//! is noted in [`COVERED_FILE`] ([`note_reply`]), both here and when a new leg
//! is pushed. Every own terms leg not noted there is due: one pushed bare by
//! a release before the fix, or one whose push failed and expired from the
//! in-memory retry queue ([`crate::settlement_legs`]).
//!
//! **Which peer.** A terms leg names no peer, so it is read from what this
//! node sealed: the leg's payment hash, the payer settlement record of that
//! invoice (its host exchange id), and this node's requested exchange record
//! for that id (the peer that served it). A leg for which that join does not
//! give exactly one peer is skipped and logged, never guessed.
//!
//! **Bounded.** At most [`MAX_PER_RUN`] legs per run, oldest first; one run
//! per process. A leg whose push fails, or whose receiver predates bundles,
//! is not noted, so the next run tries it again.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::producer::capsule::SETTLEMENT_BLOCK_POINTER;

/// One line per own terms leg whose push a provider acknowledged with the
/// inclusion it verified: `{capsule_id, peer, checkpoint_digest, covered_at}`.
pub const COVERED_FILE: &str = "covered-terms-legs.jsonl";

/// How many legs one run pushes again.
pub const MAX_PER_RUN: usize = 64;

/// A terms leg to push again to `peer`, under a checkpoint covering it.
#[derive(Debug, Clone, PartialEq)]
pub struct Due {
    pub peer: String,
    pub capsule: Value,
}

/// What a run pushes, and how many due legs it left for want of a peer.
#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    pub due: Vec<Due>,
    pub unknown_peer: Vec<String>,
}

/// One writer of [`COVERED_FILE`] at a time: the catch-up and new pushes both
/// append.
static COVERED_WRITER: Mutex<()> = Mutex::new(());

/// Whether this process's run has started.
static STARTED: AtomicBool = AtomicBool::new(false);

/// True exactly once per process: the caller then runs the catch-up.
pub fn claim_run() -> bool {
    !STARTED.swap(true, Ordering::SeqCst)
}

/// The legs due in the ledger at `ledger_dir`, oldest first, at most `limit`.
pub fn plan(ledger_dir: &Path, limit: usize) -> Plan {
    let records = crate::evidence_panes::read_capsule_records(ledger_dir);
    plan_from(&records, &covered(ledger_dir), limit)
}

/// [`plan`] over `records` (this node's own, in ledger order) and the legs
/// already noted as covered.
pub fn plan_from(records: &[Value], covered: &HashSet<String>, limit: usize) -> Plan {
    // The payer's invoices: payment hash -> the host exchange ids its
    // settlement records name for it.
    let mut invoices: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    // This node's requested exchanges: host exchange id -> the serving peers.
    let mut served_by: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for record in records {
        if let Some(observed) = record.pointer(SETTLEMENT_BLOCK_POINTER) {
            let text = |key: &str| observed.get(key).and_then(Value::as_str);
            if let (Some("payer"), Some(phase), Some(hash), Some(exchange)) = (
                text("observed_by"),
                text("phase"),
                text("payment_hash"),
                text("exchange_id"),
            ) {
                if phase.ends_with("_invoice_issued") {
                    invoices.entry(hash).or_default().insert(exchange);
                }
            }
        }
        if crate::evidence_panes::label_role(record) == "requested" {
            let provenance = record
                .pointer("/model_attestation/compute_attestation/x-mesh-poc-v1/serving_provenance");
            let text = |key: &str| {
                provenance
                    .and_then(|p| p.get(key))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty() && *s != "unknown")
            };
            if let (Some(exchange), Some(peer)) = (text("exchange_id"), text("served_by_node_id")) {
                served_by.entry(exchange).or_default().insert(peer);
            }
        }
    }
    let only = |set: Option<&BTreeSet<&str>>| {
        set.filter(|s| s.len() == 1)
            .and_then(BTreeSet::first)
            .map(|one| one.to_string())
    };
    let mut plan = Plan::default();
    for record in records {
        if plan.due.len() >= limit {
            break;
        }
        let Some((capsule_id, hash)) = own_terms_leg(record) else {
            continue;
        };
        if covered.contains(capsule_id) {
            continue;
        }
        let peer =
            only(invoices.get(hash)).and_then(|exchange| only(served_by.get(exchange.as_str())));
        match peer {
            Some(peer) => plan.due.push(Due {
                peer,
                capsule: record.clone(),
            }),
            None => plan.unknown_peer.push(capsule_id.to_string()),
        }
    }
    plan
}

/// A payer's terms leg: its capsule id and payment hash.
fn own_terms_leg(record: &Value) -> Option<(&str, &str)> {
    let member = record.get("settlement")?;
    let text = |pointer: &str| member.pointer(pointer).and_then(Value::as_str);
    if text("/leg") != Some("terms")
        || text("/sealer_role") != Some("payer")
        || text("/payment_ref/type") != Some("ln.payment_hash")
    {
        return None;
    }
    Some((
        record.get("capsule_id")?.as_str()?,
        text("/payment_ref/value")?,
    ))
}

/// The terms legs noted as covered. A torn line is skipped.
fn covered(ledger_dir: &Path) -> HashSet<String> {
    std::fs::read_to_string(ledger_dir.join(COVERED_FILE))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|line| line.get("capsule_id")?.as_str().map(str::to_string))
        .collect()
}

/// Note `capsule` (an own terms leg pushed to `peer`) as covered when
/// `reply` is the receiver's acknowledgement of a bundle naming it: the
/// inclusion it verified and holds. Returns whether it was noted. A reply
/// with no inclusion (a bare push, or a receiver predating bundles) notes
/// nothing, so the leg stays due.
pub fn note_reply(
    ledger_dir: &Path,
    capsule: &Value,
    peer: &str,
    reply: &Value,
) -> std::io::Result<bool> {
    let Some((capsule_id, _)) = own_terms_leg(capsule) else {
        return Ok(false);
    };
    let Some(inclusion) = reply
        .get("inclusion")
        .filter(|i| i.get("half_capsule_id").and_then(Value::as_str) == Some(capsule_id))
    else {
        return Ok(false);
    };
    let _one = COVERED_WRITER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if covered(ledger_dir).contains(capsule_id) {
        return Ok(true);
    }
    let mut line = serde_json::to_vec(&json!({
        "capsule_id": capsule_id,
        "peer": peer,
        "checkpoint_digest": inclusion.get("checkpoint_digest"),
        "covered_at": crate::producer::timestamp::utc_now_minute(),
    }))?;
    line.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_dir.join(COVERED_FILE))?;
    file.write_all(&line)?;
    file.sync_all()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule_emit::{CapsuleState, HostProvenance, ObservedHostExchange};
    use crate::lifecycle_channel::DispatchPath;
    use crate::settlement_channel::Phase;
    use crate::settlement_legs::tests::{event, PROVIDER_PEER};
    use std::sync::Arc;

    const HASH: &str = "8437d5a5e0c5aa3304c0e0d17288cd504593ca7e560e3691a30739f1725ee7c5";

    /// A payer that sealed what a live paid exchange seals before its terms
    /// leg is pushed: the invoice's settlement record, the terms leg, and
    /// (when `served_by` is given) its requested exchange record naming the
    /// serving peer.
    fn payer(dir: &Path, exchange_id: &str, served_by: Option<&str>) -> CapsuleState {
        let payer = CapsuleState::open(dir, "payer-node").unwrap();
        let invoice = event(
            "payer",
            exchange_id,
            Phase::InputInvoiceIssued,
            0,
            HASH,
            1000,
            &[],
        );
        payer
            .emit_settlement_record(&invoice.observation())
            .unwrap();
        assert!(payer
            .settlement_legs()
            .on_lifecycle(&payer, &invoice)
            .is_empty());
        if let Some(peer) = served_by {
            payer
                .emit_for_observed_host_exchange(&ObservedHostExchange {
                    model: "m",
                    exchange_id: Some(exchange_id),
                    request_digest: Some(&"c".repeat(64)),
                    response_digest: Some(&"d".repeat(64)),
                    tool_calls_digest: None,
                    reasoning_digest: None,
                    usage: None,
                    host_provenance: HostProvenance {
                        served_by_node_id: Some(peer.to_string()),
                        ..Default::default()
                    },
                    dispatch_path: DispatchPath::RemoteMesh,
                    nonce: Some("catch-up-nonce"),
                    peer_capsule_id: None,
                    peer_capsule_id_provenance: None,
                    twin_bracket_id: None,
                    response_text_digest: None,
                })
                .unwrap();
        }
        payer
    }

    fn lines(dir: &Path, name: &str) -> Vec<Value> {
        std::fs::read_to_string(dir.join(name))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// A terms leg the provider holds from a bare push is pushed again under
    /// a checkpoint covering it: the provider then holds its inclusion and
    /// seals its `counterparty_inclusion` citing record, without holding or
    /// citing the half a second time. The payer notes the leg covered, so a
    /// second run pushes nothing.
    #[tokio::test]
    async fn a_leg_pushed_bare_is_covered_once_by_the_catch_up() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let payer = payer(a.path(), "ex-bare", Some(PROVIDER_PEER));
        let provider = Arc::new(CapsuleState::open(b.path(), "provider-node").unwrap());
        let payer_peer = "payer-peer-catch-up";
        crate::peer_keys::announced::announce_for_test(
            payer_peer,
            &crate::commitment::key_id(payer.signing_key()),
        );
        let ledger = payer.ledger_dir().to_path_buf();
        let plan = plan(&ledger, MAX_PER_RUN);
        assert!(plan.unknown_peer.is_empty(), "{plan:?}");
        let [due] = plan.due.as_slice() else {
            panic!("one leg due: {plan:?}");
        };
        assert_eq!(due.peer, PROVIDER_PEER);
        let leg_id = due.capsule["capsule_id"].as_str().unwrap().to_string();

        // What a release before the fix did: the bare leg, held.
        let bare = crate::record_push_bridge::tests::answer_push(
            &provider,
            payer_peer,
            &serde_json::to_vec(&due.capsule).unwrap(),
        )
        .await;
        assert_eq!(bare["status"], "received", "{bare}");
        assert!(bare.get("inclusion").is_none());
        let held = provider.ledger_dir().to_path_buf();
        let inclusion = crate::record_push_receive::RECEIVED_INCLUSION_FILENAME;
        assert!(lines(&held, inclusion).is_empty());
        assert!(!note_reply(&ledger, &due.capsule, &due.peer, &bare).unwrap());

        // The catch-up: the same leg, under a checkpoint of the payer's log.
        let (state, _) = crate::producer::checkpoint::CheckpointState::load(
            &ledger,
            "payer-log",
            crate::producer::checkpoint::CheckpointCadenceConfig::default(),
        )
        .unwrap();
        let handle =
            crate::checkpoint_cadence::CheckpointHandle::new(state, payer.signing_key().clone());
        let coverage = handle.coverage_for(&leg_id).await.unwrap();
        let body = crate::record_push_bridge::bundle_body(&due.capsule, &coverage);
        let reply = crate::record_push_bridge::tests::answer_push(
            &provider,
            payer_peer,
            &serde_json::to_vec(&body).unwrap(),
        )
        .await;
        assert_eq!(reply["inclusion"]["half_capsule_id"], leg_id, "{reply}");
        assert!(note_reply(&ledger, &due.capsule, &due.peer, &reply).unwrap());

        let inclusions = lines(&held, inclusion);
        assert_eq!(inclusions.len(), 1, "{inclusions:?}");
        assert_eq!(inclusions[0]["half_capsule_id"], leg_id);
        for store in [
            crate::record_push_receive::RECEIVED_CAPSULES_FILENAME,
            crate::record_push_receive::RECEIVED_PROVENANCE_FILENAME,
        ] {
            assert_eq!(lines(&held, store).len(), 1, "held once: {store}");
        }
        let provider_chain = lines(&held, "capsules.jsonl");
        let cited = |block: &str| {
            provider_chain
                .iter()
                .filter(|r| {
                    r.pointer(&format!("/model_attestation/compute_attestation/{block}"))
                        .is_some()
                })
                .count()
        };
        assert_eq!(cited("received_half"), 1, "the half cited once");
        assert_eq!(cited("counterparty_inclusion"), 1, "its inclusion cited");

        // A second run: nothing due, nothing sent.
        assert_eq!(super::plan(&ledger, MAX_PER_RUN), Plan::default());
        assert_eq!(lines(&ledger, COVERED_FILE).len(), 1);
    }

    /// A leg whose serving peer this node never sealed (no requested record
    /// for its exchange) is skipped, never sent to a guessed peer.
    #[test]
    fn a_leg_whose_peer_is_unknown_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let payer = payer(dir.path(), "ex-unknown", None);
        let plan = plan(payer.ledger_dir(), MAX_PER_RUN);
        assert!(plan.due.is_empty(), "{plan:?}");
        assert_eq!(plan.unknown_peer.len(), 1);
    }

    /// Two requested records naming different peers for one exchange leave
    /// the peer unknown; a run takes at most its bound, oldest first.
    #[test]
    fn an_ambiguous_peer_is_skipped_and_a_run_is_bounded() {
        let leg = |id: &str, hash: &str| {
            json!({"capsule_id": id, "settlement": {
                "leg": "terms", "sealer_role": "payer",
                "payment_ref": {"type": "ln.payment_hash", "value": hash}}})
        };
        let invoice = |hash: &str, exchange: &str| {
            json!({"model_attestation": {"compute_attestation": {"x-mesh-settlement-v1": {
                "observed_by": "payer", "phase": "input_invoice_issued",
                "payment_hash": hash, "exchange_id": exchange}}}})
        };
        let requested = |exchange: &str, peer: &str| {
            json!({"model_attestation": {"compute_attestation": {"x-mesh-poc-v1": {
                "role": "requested",
                "serving_provenance": {"exchange_id": exchange, "served_by_node_id": peer}}}}})
        };
        let records = vec![
            invoice("h1", "e1"),
            requested("e1", "p1"),
            requested("e1", "p2"),
            leg("l1", "h1"),
            invoice("h2", "e2"),
            requested("e2", "p1"),
            leg("l2", "h2"),
            leg("l3", "h2"),
        ];
        let plan = plan_from(&records, &HashSet::new(), 1);
        assert_eq!(plan.unknown_peer, ["l1"]);
        assert_eq!(plan.due.len(), 1);
        assert_eq!(plan.due[0].capsule["capsule_id"], "l2");
        let covered: HashSet<String> = ["l2".to_string()].into();
        let rest = plan_from(&records, &covered, MAX_PER_RUN);
        assert_eq!(rest.due.len(), 1);
        assert_eq!(rest.due[0].capsule["capsule_id"], "l3");
    }
}
