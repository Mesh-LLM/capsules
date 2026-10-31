//! The counterparty cross-check of the Lightning denominator
//! (Mesh-LLM/capsules-plugin#83): Lightning has no public ledger, so the
//! count of settlements a node discloses is checked against the other side's
//! book instead.
//!
//! **The other side's half.** `GET settlement-bundle` gives this node's own
//! terminal settlement records (`payment.lifecycle.v1`, either side) as an
//! Evidence Bundle proven against one signed checkpoint, built by the same
//! producer-selected builder as the receipt bundles
//! ([`crate::deal_receipt::selected_bundle`]). Only terminal settlements are
//! carried: no invoice, terms, accounting or exchange record. The route is
//! the owner's; the owner hands the file to the counterparty.
//!
//! **The check.** `settlement_check` given that bundle as
//! `counterparty_bundle` verifies it (every record and the checkpoint signed
//! by one key, accepted for a peer through [`crate::peer_keys::accepted_via`]
//! and not this node's own; every record proven under the checkpoint), then
//! pairs payment hashes across the two books with loop#183's rule
//! (`steps/06-settle`, `crosscheck`): a hash pairs when all its payer
//! observations are in one book with one `amount_msat`, all its provider
//! observations are in the other with one `credited_msat + fee_msat`, and the
//! two amounts are equal. Every other hash is unpaired, with its reason.
//!
//! A hash held in one book only is not a failure: either node may have paid
//! a third party. Both books holding a hash and disagreeing about it is.
//! `public_ledger_count` stays `NOT_CHECKED`; this result never stands in
//! for it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use mesh_llm_plugin::{http, DeclarativePluginBuilder, PluginError};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::checkpoint_cadence::CheckpointHandle;
use crate::deal_receipt::{selected_bundle, Error, Selection};
use crate::evidence_log::{self, LedgerIndex};
use crate::producer::capsule::SETTLEMENT_BLOCK_POINTER;
use crate::settlement_adapter::{Kind, Observation, Side, Status};

/// The method a `counterparty_count` result names.
pub const METHOD: &str = "payment_hash pairs across the two books by role and amount (loop#183)";

/// Whether `record` is a terminal settlement the bundle carries.
fn is_terminal_settlement(record: &Value) -> bool {
    Observation::from_lifecycle_record(record)
        .is_some_and(|o| o.kind == Kind::Settlement && o.terminal)
}

/// The capsule ids of this node's terminal settlement records, in log order.
fn settlement_ids(index: &LedgerIndex) -> std::io::Result<Vec<String>> {
    let view = index.view()?;
    let mut ids = Vec::new();
    for (i, leaf) in index.leaves.iter().enumerate() {
        if leaf.padding {
            continue;
        }
        let Some(record) = view.record_at(i as u64) else {
            continue;
        };
        let Ok(capsule) = serde_json::from_slice::<Value>(&record.body) else {
            continue;
        };
        if capsule.pointer(SETTLEMENT_BLOCK_POINTER).is_some() && is_terminal_settlement(&capsule) {
            ids.push(record.digest);
        }
    }
    Ok(ids)
}

/// Why no bundle is given.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    NoSettlement,
    NotCheckpointed,
}

impl Refusal {
    fn why(&self) -> &'static str {
        match self {
            Refusal::NoSettlement => "this node holds no terminal settlement record",
            Refusal::NotCheckpointed => "no signed checkpoint covers the records yet",
        }
    }
}

#[derive(Debug)]
pub enum Failure {
    Refused(Refusal),
    Failed(String),
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        match e {
            Error::Refused(_) => Failure::Refused(Refusal::NotCheckpointed),
            Error::Failed(why) => Failure::Failed(why),
        }
    }
}

/// This node's terminal settlement records as a producer-selected bundle.
pub fn bundle(ledger_dir: &Path, node_key_id: &str) -> Result<Value, Failure> {
    let unreadable =
        |e: std::io::Error| Failure::Failed(format!("the ledger is not readable: {e}"));
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        let ids = settlement_ids(index).map_err(unreadable)?;
        let Some(root) = ids.last().cloned() else {
            return Err(Failure::Refused(Refusal::NoSettlement));
        };
        Ok(selected_bundle(
            index,
            node_key_id,
            Selection {
                root: &root,
                ids: &ids,
                disclosures: BTreeMap::new(),
                extensions: Map::new(),
            },
        )?)
    })
    .map_err(unreadable)?
}

pub fn answer(ledger_dir: &Path, node_key_id: &str) -> Result<Value, String> {
    match bundle(ledger_dir, node_key_id) {
        Ok(bundle) => Ok(json!({"state": "bundle", "bundle": bundle})),
        Err(Failure::Refused(r)) => Ok(json!({"state": "refused", "why": r.why()})),
        Err(Failure::Failed(why)) => Err(why),
    }
}

/// The last terminal settlement this node sealed, which a covering
/// checkpoint must reach.
fn last_settlement(ledger_dir: &Path, node_key_id: &str) -> Option<String> {
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        settlement_ids(index).ok()?.pop()
    })
    .ok()
    .flatten()
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SettlementBundleArgs {}

pub fn with_route(
    builder: DeclarativePluginBuilder,
    capsules: Arc<crate::capsule_emit::CapsuleState>,
    checkpoints: Option<CheckpointHandle>,
) -> DeclarativePluginBuilder {
    builder.http_item(
        http::get("/settlement-bundle")
            .binding_id("evidence_settlement_bundle")
            .description(
                "This node's own terminal Lightning settlement records, proven against a signed \
                 checkpoint, for a counterparty's settlement_check to cross-check its count \
                 against. Cuts a signed checkpoint when none covers the records yet.",
            )
            .input::<SettlementBundleArgs>()
            .handle(move |_args, _context| {
                let capsules = capsules.clone();
                let checkpoints = checkpoints.clone();
                Box::pin(async move {
                    let ledger_dir = capsules.ledger_dir().to_path_buf();
                    let node_key_id = crate::commitment::key_id(capsules.signing_key());
                    let last = {
                        let (dir, key) = (ledger_dir.clone(), node_key_id.clone());
                        tokio::task::spawn_blocking(move || last_settlement(&dir, &key))
                            .await
                            .ok()
                            .flatten()
                    };
                    if let (Some(handle), Some(last)) = (checkpoints.as_ref(), last) {
                        let _ = handle.coverage_for(&last).await;
                    }
                    tokio::task::spawn_blocking(move || answer(&ledger_dir, &node_key_id))
                        .await
                        .map_err(|error| {
                            PluginError::internal(format!(
                                "settlement bundle task did not complete: {error}"
                            ))
                        })?
                        .map_err(PluginError::internal)
                })
            }),
    )
}

/// The counterparty's settlement observations, once its bundle verified, and
/// the peers its key is accepted for.
pub struct Verified {
    pub key_id: String,
    pub peers: Vec<String>,
    pub observations: Vec<Observation>,
}

/// Verify a counterparty's `settlement-bundle`. `accept` returns the peers a
/// key is accepted for (`None`: not accepted, or this node's own).
pub fn verify(
    bundle: &Value,
    accept: impl Fn(&str) -> Option<Vec<String>>,
) -> Result<Verified, String> {
    use agent_action_capsule::bundle::{verify_bundle_strict, StrictOptions};
    let result = verify_bundle_strict(
        bundle,
        &StrictOptions {
            require_signature: true,
            witness_directory: None,
        },
    );
    if !result.ok() {
        return Err(format!("the bundle is {}", result.verdict()));
    }
    // Producer-selected, so interval coverage is withheld; each record must
    // still be signed and proven under the signed checkpoint.
    for claim in ["signatures", "checkpoint", "per_record_membership"] {
        let status = result.claim(claim).map(|c| c.status.as_str());
        if status != Some("pass") {
            return Err(format!(
                "the bundle's {claim} claim is {status:?}, not pass"
            ));
        }
    }
    let key_id = result
        .signed_checkpoint
        .as_ref()
        .map(|c| c.key_id.clone())
        .ok_or("the bundle's checkpoint is not authenticated")?;
    if result.signer_matches_checkpoint != Some(true) {
        return Err("a record is signed by a key other than the checkpoint's".into());
    }
    let records = bundle
        .get("records")
        .and_then(Value::as_array)
        .ok_or("the bundle carries no records")?;
    let observations = records
        .iter()
        .filter_map(Observation::from_lifecycle_record)
        .filter(|o| o.kind == Kind::Settlement && o.terminal)
        .collect();
    let peers = accept(&key_id).ok_or("the bundle's key is not accepted for any peer")?;
    Ok(Verified {
        key_id,
        peers,
        observations,
    })
}

/// Which book an observation is from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Book {
    Own,
    Counterparty,
}

impl Book {
    fn wire(self) -> &'static str {
        match self {
            Book::Own => "this node",
            Book::Counterparty => "the counterparty",
        }
    }
}

/// Pair payment hashes across the two books (loop#183's rule).
pub fn cross_check(own: &[&Observation], counterparty: &Verified) -> Value {
    let mut by_hash: BTreeMap<&str, Vec<(Book, &Observation)>> = BTreeMap::new();
    for o in own
        .iter()
        .copied()
        .filter(|o| o.kind == Kind::Settlement && o.terminal)
    {
        if let Some(h) = o.payment_hash.as_deref() {
            by_hash.entry(h).or_default().push((Book::Own, o));
        }
    }
    for o in counterparty.observations.iter() {
        if let Some(h) = o.payment_hash.as_deref() {
            by_hash.entry(h).or_default().push((Book::Counterparty, o));
        }
    }
    let mut paired = 0u64;
    let mut unpaired = Vec::new();
    let mut conflicting = false;
    for (hash, seen) in &by_hash {
        let books: BTreeSet<Book> = seen.iter().map(|(b, _)| *b).collect();
        let mut payers: BTreeSet<(Book, u64)> = BTreeSet::new();
        let mut payees: BTreeSet<(Book, u64)> = BTreeSet::new();
        let mut malformed: BTreeSet<Book> = BTreeSet::new();
        for (book, o) in seen {
            match (o.side, o.credited_msat, o.fee_msat) {
                (Side::Payer, ..) => {
                    payers.insert((*book, o.amount_msat));
                }
                (Side::Provider, Some(credited), Some(fee)) => match credited.checked_add(fee) {
                    Some(sum) => {
                        payees.insert((*book, sum));
                    }
                    None => {
                        malformed.insert(*book);
                    }
                },
                (Side::Provider, ..) => {
                    malformed.insert(*book);
                }
            }
        }
        let payer_books: BTreeSet<Book> = payers.iter().map(|(b, _)| *b).collect();
        let payee_books: BTreeSet<Book> = payees.iter().map(|(b, _)| *b).collect();
        let payer_amounts: BTreeSet<u64> = payers.iter().map(|(_, a)| *a).collect();
        let payee_amounts: BTreeSet<u64> = payees.iter().map(|(_, a)| *a).collect();
        let (reason, conflict) = if books.len() < 2 {
            let only = books.iter().next().map_or("", |b| b.wire());
            (Some(format!("recorded by {only} only")), false)
        } else if !malformed.is_empty() {
            (
                Some(
                    "a provider observation has no wallet-reported credited_msat and fee_msat"
                        .to_string(),
                ),
                false,
            )
        } else if payers.is_empty() || payees.is_empty() {
            (
                Some("no payer observation or no provider observation, with amounts".to_string()),
                true,
            )
        } else if payer_books.len() > 1 || payee_books.len() > 1 || payer_books == payee_books {
            (
                Some("both books observed the same role: one book of each role is needed".into()),
                true,
            )
        } else if payer_amounts.len() > 1
            || payee_amounts.len() > 1
            || payer_amounts != payee_amounts
        {
            (
                Some(format!(
                    "conflicting amounts: payer {payer_amounts:?}, provider credited plus fee {payee_amounts:?}"
                )),
                true,
            )
        } else {
            (None, false)
        };
        match reason {
            None => paired += 1,
            Some(reason) => {
                conflicting |= conflict;
                unpaired.push(json!({"payment_hash": hash, "reason": reason}));
            }
        }
    }
    let status = if conflicting {
        Status::Fail
    } else if unpaired.is_empty() && paired > 0 {
        Status::Pass
    } else {
        Status::Inconclusive
    };
    json!({
        "status": status.wire(),
        "method": METHOD,
        "counterparty_key": counterparty.key_id,
        "counterparty_peers": counterparty.peers,
        "paired": paired,
        "unpaired": unpaired,
    })
}

/// The result when no counterparty bundle was given (`NOT_PRESENT`), or it
/// did not verify (`NOT_CHECKED`: the input is there, the pairing not run).
pub fn not_run(status: Status, reason: &str) -> Value {
    json!({"status": status.wire(), "reason": reason})
}

#[cfg(test)]
mod tests;
