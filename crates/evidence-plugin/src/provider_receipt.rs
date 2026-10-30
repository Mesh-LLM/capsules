//! `GET provider-receipt-bundle`: the provider's own receipt for one paid
//! exchange it served, as an Evidence Bundle that capsule-viewer renders
//! (Mesh-LLM/capsules-plugin#134; Steven's ruling on #146: each side keeps its
//! half, and the counterparty's receipt is what its half says: the model and
//! what was paid, never the inference content).
//!
//! It is not a deal. The provider's half is the records it already seals: the
//! exchange record it served (`x-mesh-poc-v1`, role `served`: the model, the
//! digests) and its `payee_observed` settlement legs (what it received). The
//! typed seller deal the profile asks of a seller needs an offer, an
//! acceptance and an authority this node does not make, so none is sealed.
//!
//! Which legs belong to which exchange is the node's own note
//! ([`PROVIDER_LINKS_FILE`], written when a leg is sealed): a leg names no
//! exchange itself. The bundle is owner-only and producer-selected, like the
//! payer's ([`crate::deal_receipt`]); it carries those records and no
//! payload, so the digests stay and no inference content or payer identity
//! beyond what the records name is in it.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use mesh_llm_plugin::{http, DeclarativePluginBuilder, PluginError};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::checkpoint_cadence::CheckpointHandle;
use crate::deal_receipt::{selected_bundle, Error, Selection};
use crate::evidence_log::{self, LedgerIndex};

/// One `{"exchange_id", "capsule_id"}` line per `payee_observed` leg this node
/// sealed: the host's exchange id the leg was for.
pub const PROVIDER_LINKS_FILE: &str = "provider-links.jsonl";

/// Why no bundle is given.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No payment this node received is noted for that exchange.
    NoPayment,
    /// The exchange record this node served is not in its ledger (or not
    /// the only one).
    NoExchange,
    /// No signed checkpoint covers the records yet.
    NotCheckpointed,
}

impl Refusal {
    fn why(&self) -> &'static str {
        match self {
            Refusal::NoPayment => "this node noted no payment received for that exchange",
            Refusal::NoExchange => "this node holds no single served record for that exchange",
            Refusal::NotCheckpointed => "no signed checkpoint covers the records yet",
        }
    }
}

/// What building the bundle ran into.
#[derive(Debug)]
pub enum Failure {
    Refused(Refusal),
    Failed(String),
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        match e {
            // The shared builder refuses for one reason only: no checkpoint.
            Error::Refused(_) => Failure::Refused(Refusal::NotCheckpointed),
            Error::Failed(why) => Failure::Failed(why),
        }
    }
}

impl From<Refusal> for Failure {
    fn from(r: Refusal) -> Self {
        Failure::Refused(r)
    }
}

/// Note that `leg_capsule_id` is a leg this node sealed for `exchange_id`.
pub fn link_leg(ledger_dir: &Path, exchange_id: &str, leg_capsule_id: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut line = serde_json::to_vec(&json!({
        "exchange_id": exchange_id, "capsule_id": leg_capsule_id,
    }))
    .map_err(std::io::Error::other)?;
    line.push(b'\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_dir.join(PROVIDER_LINKS_FILE))?
        .write_all(&line)
}

/// The legs noted for `exchange_id`, in the order noted. By bytes: a torn
/// last line is skipped.
fn legs_of(ledger_dir: &Path, exchange_id: &str) -> std::io::Result<Vec<String>> {
    let bytes = match std::fs::read(ledger_dir.join(PROVIDER_LINKS_FILE)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut legs: Vec<String> = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        let Ok(v) = serde_json::from_slice::<Value>(line) else {
            continue;
        };
        if v.get("exchange_id").and_then(Value::as_str) != Some(exchange_id) {
            continue;
        }
        if let Some(id) = v.get("capsule_id").and_then(Value::as_str) {
            if !legs.iter().any(|l| l == id) {
                legs.push(id.to_string());
            }
        }
    }
    Ok(legs)
}

/// The single record this node served for `exchange_id`.
fn served_record(index: &LedgerIndex, exchange_id: &str) -> Option<String> {
    let view = index.view().ok()?;
    let mut served = index.correlated(exchange_id).iter().filter_map(|&i| {
        let record = view.record_at(i)?;
        let capsule: Value = serde_json::from_slice(&record.body).ok()?;
        (crate::evidence_panes::label_role(&capsule) == "served").then_some(record.digest)
    });
    let first = served.next()?;
    served.next().is_none().then_some(first)
}

/// The provider's receipt bundle for the host's `exchange_id`.
pub fn bundle(ledger_dir: &Path, node_key_id: &str, exchange_id: &str) -> Result<Value, Failure> {
    let unreadable =
        |e: std::io::Error| Failure::Failed(format!("the ledger is not readable: {e}"));
    let noted = legs_of(ledger_dir, exchange_id).map_err(unreadable)?;
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        let legs: Vec<String> = noted
            .into_iter()
            .filter(|id| index.leaf_index_of(id).is_some())
            .collect();
        if legs.is_empty() {
            return Err(Refusal::NoPayment.into());
        }
        let exchange = served_record(index, exchange_id).ok_or(Refusal::NoExchange)?;
        let mut ids = vec![exchange.clone()];
        ids.extend(legs);
        Ok(selected_bundle(
            index,
            node_key_id,
            Selection {
                root: &exchange,
                ids: &ids,
                disclosures: BTreeMap::new(),
                extensions: Map::new(),
            },
        )?)
    })
    .map_err(unreadable)?
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProviderReceiptArgs {
    /// The host's exchange id (the Logs request's).
    pub exchange_id: Value,
}

/// `{"state": "bundle", "bundle": ...}`, or `{"state": "refused", "why": ...}`.
pub fn answer(ledger_dir: &Path, node_key_id: &str, exchange_id: &Value) -> Result<Value, String> {
    let Some(id) = exchange_id
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256)
    else {
        return Err("exchange_id must be a non-empty string".into());
    };
    match bundle(ledger_dir, node_key_id, id) {
        Ok(bundle) => Ok(json!({"state": "bundle", "bundle": bundle})),
        Err(Failure::Refused(r)) => Ok(json!({"state": "refused", "why": r.why()})),
        Err(Failure::Failed(why)) => Err(why),
    }
}

/// `builder` with the `provider-receipt-bundle` route declared. A checkpoint
/// is cut first when none covers the records yet (this may write to the log
/// and contact witnesses).
pub fn with_route(
    builder: DeclarativePluginBuilder,
    capsules: Arc<crate::capsule_emit::CapsuleState>,
    checkpoints: Option<CheckpointHandle>,
) -> DeclarativePluginBuilder {
    builder.http_item(
        http::get("/provider-receipt-bundle")
            .binding_id("evidence_provider_receipt_bundle")
            .description(
                "The provider's own receipt for one paid exchange it served: the model and what \
                 it received, for the viewer to render. Cuts a signed checkpoint when none \
                 covers the records yet.",
            )
            .input::<ProviderReceiptArgs>()
            .handle(move |args, _context| {
                let capsules = capsules.clone();
                let checkpoints = checkpoints.clone();
                Box::pin(async move {
                    let ledger_dir = capsules.ledger_dir().to_path_buf();
                    let node_key_id = crate::commitment::key_id(capsules.signing_key());
                    let exchange = args.exchange_id;
                    if let (Some(handle), Some(last)) = (
                        checkpoints.as_ref(),
                        last_record(&ledger_dir, &node_key_id, &exchange),
                    ) {
                        let _ = handle.coverage_for(&last).await;
                    }
                    tokio::task::spawn_blocking(move || {
                        answer(&ledger_dir, &node_key_id, &exchange)
                    })
                    .await
                    .map_err(|error| {
                        PluginError::internal(format!(
                            "provider receipt task did not complete: {error}"
                        ))
                    })?
                    .map_err(PluginError::internal)
                })
            }),
    )
}

/// The last-sealed of the records the bundle would carry, which a covering
/// checkpoint must reach.
fn last_record(ledger_dir: &Path, node_key_id: &str, exchange: &Value) -> Option<String> {
    let exchange_id = exchange.as_str()?;
    let noted = legs_of(ledger_dir, exchange_id).ok()?;
    evidence_log::with_index(ledger_dir, node_key_id, |index| {
        let mut ids = noted;
        ids.extend(served_record(index, exchange_id));
        ids.into_iter()
            .filter_map(|id| Some((index.leaf_index_of(&id)?, id)))
            .max()
            .map(|(_, id)| id)
    })
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule_emit::CapsuleState;
    use crate::deal_receipt::tests::cut;
    use crate::settlement_legs::tests::{dirs, two_nodes, WALLET};

    const HOST_EXCHANGE: &str = "p-ex";

    /// A provider that served an exchange for the host id `p-ex` and received
    /// its two payments (the legs `two_nodes` seals on node b).
    fn provider(dir: &Path) -> (CapsuleState, String) {
        let (a, _) = (tempfile::tempdir().unwrap(), ());
        two_nodes(a.path(), dir, WALLET);
        let state = CapsuleState::open(dir, "provider-node").unwrap();
        let mut served = crate::capsule_emit::tests::sample_exchange("payer-node");
        served.exchange_id = Some(HOST_EXCHANGE);
        let exchange = state.emit_for_exchange(&served).unwrap().capsule_id;
        (state, exchange)
    }

    fn key(state: &CapsuleState) -> String {
        crate::commitment::key_id(state.signing_key())
    }

    #[test]
    fn the_provider_gets_its_served_record_and_the_legs_it_noted_and_nothing_else() {
        let (_a, dir) = dirs();
        let (state, exchange) = provider(dir.path());
        // A later, unrelated record is not carried.
        state
            .emit_for_exchange(&crate::capsule_emit::tests::sample_exchange("someone-else"))
            .unwrap();
        cut(&state);
        let bundle = bundle(state.ledger_dir(), &key(&state), HOST_EXCHANGE)
            .unwrap_or_else(|e| panic!("{e:?}"));
        let records = bundle["records"].as_array().unwrap();
        assert_eq!(records.len(), 3, "the served record and two legs");
        assert_eq!(bundle["root"], json!(exchange));
        let legs: Vec<&Value> = records
            .iter()
            .filter(|r| r.get("settlement").is_some())
            .collect();
        assert_eq!(legs.len(), 2);
        // What the provider received is in the legs, with its unit.
        assert!(legs
            .iter()
            .any(|l| l["settlement"]["received"]["value"] == json!("995")));
        // 1 msat is 1e-11 BTC: the unit is in the amount (assetCode, assetScale).
        assert!(legs.iter().all(|l| {
            l["settlement"]["received"]["assetCode"] == json!("BTC")
                && l["settlement"]["received"]["assetScale"] == json!(11)
        }));
        // No payload is disclosed: the digests stay, no inference content.
        assert!(bundle["disclosures"]
            .as_object()
            .is_none_or(|d| d.is_empty()));
        let text = serde_json::to_string(&bundle).unwrap();
        assert!(!text.contains("hello"), "no response text");
        assert!(!text.contains("\"content\":\"hi\""), "no prompt text");
        let checked = agent_action_capsule::bundle::verify_bundle_strict(
            &bundle,
            &agent_action_capsule::bundle::StrictOptions {
                require_signature: true,
                witness_directory: None,
            },
        );
        let statuses: Vec<_> = checked
            .claims
            .iter()
            .map(|(name, c)| (*name, c.status.as_str()))
            .collect();
        assert!(statuses
            .iter()
            .all(|(n, s)| *s == "pass" || (*n == "interval_coverage" && *s == "withheld")));
        if let Some(out) = std::env::var_os("PROVIDER_RECEIPT_BUNDLE_OUT") {
            std::fs::write(out, serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();
        }
    }

    #[test]
    fn no_payment_no_served_record_and_no_checkpoint_are_refusals() {
        let (_a, dir) = dirs();
        let (state, _) = provider(dir.path());
        let ask = |id: &str| bundle(state.ledger_dir(), &key(&state), id);
        // Not yet checkpointed.
        assert!(matches!(
            ask(HOST_EXCHANGE),
            Err(Failure::Refused(Refusal::NotCheckpointed))
        ));
        cut(&state);
        assert!(ask(HOST_EXCHANGE).is_ok());
        assert!(matches!(
            ask("unknown"),
            Err(Failure::Refused(Refusal::NoPayment))
        ));
        // A payment noted for an exchange this node holds no served record for.
        link_leg(state.ledger_dir(), "orphan", &"a".repeat(64)).unwrap();
        assert!(matches!(
            ask("orphan"),
            Err(Failure::Refused(Refusal::NoPayment))
        ));
    }

    #[test]
    fn the_route_answer_names_a_refusal_and_rejects_an_empty_id() {
        let (_a, dir) = dirs();
        let (state, _) = provider(dir.path());
        let answered = answer(state.ledger_dir(), &key(&state), &json!("unknown")).unwrap();
        assert_eq!(answered["state"], "refused");
        assert!(answer(state.ledger_dir(), &key(&state), &json!("")).is_err());
        assert!(answer(state.ledger_dir(), &key(&state), &json!(7)).is_err());
    }
}
