//! The Lightning settlement adapter (`adapters/lightning-v0.md`): checks the
//! settlement objects this node holds for a paid exchange and derives each
//! settled payment's value band. Read-only: it seals nothing and contacts
//! nobody.
//!
//! **The settlement object.** Today it is the host's `payment.lifecycle.v1`
//! event, which this node seals verbatim as a settlement record
//! ([`crate::settlement_channel`], `seal_settlement_record`). The adapter
//! reads those records through one reader per source ([`Observation::from_lifecycle_record`])
//! into a rail-neutral [`Observation`], so a host whose settlement objects
//! arrive on another channel needs a new reader, not a new adapter.
//!
//! **What each property means** (the declaration's item (e)):
//! - `object_held`: the record's `event_ref` recomputes over the event the
//!   host emitted, rebuilt from the record. `INCONCLUSIVE` when no host shape
//!   this plugin knows recomputes (a host may add fields the record does not
//!   keep), never `FAIL`.
//! - `invoice_join`: the settlement's `payment_hash` is the hash of an
//!   invoice the provider issued for the same exchange and segment.
//! - `amount`: the settled amount equals that invoice's amount.
//! - `finality`: the wallet reported the payment terminal (`wallet_reported`,
//!   `settlement: "terminal"`). That is the wallet's statement; the host
//!   passes no proof of it.
//! - `preimage`: the native Lightning check, `sha256(preimage) ==
//!   payment_hash`. Always `NOT_CHECKED` today: the host's event never
//!   carries the preimage.
//! - `payee_credit`: provider side only, what the receiving wallet credited
//!   plus its fee equals the amount.
//!
//! An invoice with no terminal settlement is reported, never read as
//! "unpaid": the host emits nothing for a payment whose outcome it does not
//! know.
//!
//! **Band** (`(currency, decade)`): derived from the settled amount with no
//! conversion. The decade is that of the amount in [`BAND_CURRENCY`], so
//! 250 sats is `sat:e+2` and 1 msat is `sat:e-3`.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::producer::jcs;

/// The MCP operation name.
pub const SETTLEMENT_CHECK_OPERATION: &str = "settlement_check";

/// The adapter declaration these results are produced under.
pub const LIGHTNING_ADAPTER: &str = "lightning-v0";

/// The band's currency label. The decade is of the amount in this unit
/// (1 sat = 1000 msat).
pub const BAND_CURRENCY: &str = "sat";

/// Where the plugin records the observed event.
const SETTLEMENT_BLOCK: &str = "/model_attestation/compute_attestation/x-mesh-settlement-v1";

/// A per-property result (profile §7.1 vocabulary). Never a score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    Inconclusive,
    NotChecked,
}

impl Outcome {
    pub fn wire(self) -> &'static str {
        match self {
            Outcome::Pass => "PASS",
            Outcome::Fail => "FAIL",
            Outcome::Inconclusive => "INCONCLUSIVE",
            Outcome::NotChecked => "NOT_CHECKED",
        }
    }
}

/// One property's result and the method (or reason) behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Property {
    pub outcome: Outcome,
    pub method: &'static str,
}

fn prop(outcome: Outcome, method: &'static str) -> Property {
    Property { outcome, method }
}

impl Property {
    fn to_value(&self) -> Value {
        json!({"result": self.outcome.wire(), "method": self.method})
    }
}

/// Which side of the exchange sealed an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Side {
    Payer,
    Provider,
}

impl Side {
    fn wire(self) -> &'static str {
        match self {
            Side::Payer => "payer",
            Side::Provider => "provider",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Invoice,
    Settlement,
    /// Terms, final accounting, delivered: held, not a settlement object.
    Other,
}

/// One settlement-relevant observation, whatever rail message carried it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub exchange_id: String,
    pub side: Side,
    pub kind: Kind,
    pub segment: Option<u32>,
    pub payment_hash: Option<String>,
    pub amount_msat: u64,
    pub credited_msat: Option<u64>,
    pub fee_msat: Option<u64>,
    /// The rail reported this payment terminal.
    pub terminal: bool,
    pub held: Property,
}

impl Observation {
    /// The `payment.lifecycle.v1` reader: one sealed settlement record.
    /// `None` for a record that is not a settlement record or lacks the
    /// fields every such record carries.
    pub fn from_lifecycle_record(record: &Value) -> Option<Self> {
        let block = record.pointer(SETTLEMENT_BLOCK)?.as_object()?;
        let s = |k: &str| block.get(k).and_then(Value::as_str);
        let u = |k: &str| block.get(k).and_then(Value::as_u64);
        let exchange_id = s("exchange_id").filter(|x| !x.is_empty())?.to_string();
        let side = match s("observed_by")? {
            "payer" => Side::Payer,
            "provider" => Side::Provider,
            _ => return None,
        };
        let phase = s("phase")?;
        let kind = match phase {
            "input_invoice_issued" | "output_invoice_issued" => Kind::Invoice,
            "input_settlement_observed" | "output_settlement_observed" => Kind::Settlement,
            _ => Kind::Other,
        };
        Some(Self {
            exchange_id,
            side,
            kind,
            segment: u("segment").and_then(|v| u32::try_from(v).ok()),
            payment_hash: s("payment_hash").map(str::to_string),
            amount_msat: u("amount_msat")?,
            credited_msat: u("credited_msat"),
            fee_msat: u("fee_msat"),
            terminal: s("source") == Some("wallet_reported") && s("settlement") == Some("terminal"),
            held: lifecycle_event_ref(block),
        })
    }
}

/// Rebuild the host's event from a sealed record's block and recompute its
/// `event_ref`. The record drops `null`s and renames `role` to
/// `observed_by`; the host serializes `null`s and, since `role` and `tokens`
/// were added, both members. A host from before then sent neither, so both
/// shapes are tried.
fn lifecycle_event_ref(block: &Map<String, Value>) -> Property {
    let Some(claimed) = block.get("event_ref").and_then(Value::as_str) else {
        return prop(Outcome::Fail, "the record carries no event_ref");
    };
    let mut base = Map::new();
    for key in [
        "exchange_id",
        "terms_digest",
        "phase",
        "source",
        "amount_msat",
        "credited_msat",
        "fee_msat",
    ] {
        if let Some(v) = block.get(key) {
            base.insert(key.into(), v.clone());
        }
    }
    for key in ["settlement", "segment", "payment_hash"] {
        base.insert(key.into(), block.get(key).cloned().unwrap_or(Value::Null));
    }
    base.insert("event_ref".into(), json!(""));
    let mut current = base.clone();
    current.insert(
        "role".into(),
        block.get("observed_by").cloned().unwrap_or(Value::Null),
    );
    current.insert(
        "tokens".into(),
        block.get("tokens").cloned().unwrap_or(Value::Null),
    );
    for shape in [current, base] {
        if jcs::json_digest(&Value::Object(shape)).ok().as_deref() == Some(claimed) {
            return prop(Outcome::Pass, "event_ref recomputed over the host's event");
        }
    }
    prop(
        Outcome::Inconclusive,
        "event_ref does not recompute over any host event shape this plugin knows",
    )
}

/// The `(currency, decade)` band of an amount, as `sat:e<sign><n>`. `None`
/// for zero, which has no decade.
pub fn band(amount_msat: u64) -> Option<String> {
    if amount_msat == 0 {
        return None;
    }
    let digits = amount_msat.ilog10() as i64;
    let decade = digits - 3;
    let sign = if decade > 0 { "+" } else { "" };
    Some(format!("{BAND_CURRENCY}:e{sign}{decade}"))
}

/// One terminal settlement's per-property results.
fn check_settlement(settlement: &Observation, invoices: &[&Observation]) -> Value {
    let invoice = invoices
        .iter()
        .find(|i| i.side == settlement.side && i.segment == settlement.segment);
    let invoice_join = match (&settlement.payment_hash, invoice) {
        (None, _) => prop(
            Outcome::NotChecked,
            "the wallet reported no payment_hash for this settlement",
        ),
        (Some(_), None) => prop(
            Outcome::Inconclusive,
            "no invoice for this segment is held on this side",
        ),
        (Some(hash), Some(i)) if i.payment_hash.as_ref() == Some(hash) => prop(
            Outcome::Pass,
            "payment_hash equals the invoice's for the same exchange and segment",
        ),
        (Some(_), Some(_)) => prop(
            Outcome::Fail,
            "payment_hash differs from the invoice's for the same exchange and segment",
        ),
    };
    let amount = match invoice {
        None => prop(
            Outcome::Inconclusive,
            "no invoice to compare the amount with",
        ),
        Some(i) if i.amount_msat == 0 => prop(Outcome::NotChecked, "the invoice names no amount"),
        Some(i) if i.amount_msat == settlement.amount_msat => {
            prop(Outcome::Pass, "settled amount equals the invoice amount")
        }
        Some(_) => prop(
            Outcome::Fail,
            "settled amount differs from the invoice amount",
        ),
    };
    let finality = if settlement.terminal {
        prop(
            Outcome::Pass,
            "wallet_report: the wallet reported the payment terminal",
        )
    } else {
        prop(Outcome::Fail, "the settlement is not reported terminal")
    };
    let payee_credit = match (
        settlement.side,
        settlement.credited_msat,
        settlement.fee_msat,
    ) {
        (Side::Payer, ..) => prop(
            Outcome::NotChecked,
            "the payer's wallet does not see the credit",
        ),
        (Side::Provider, Some(credited), Some(fee)) => {
            if credited.checked_add(fee) == Some(settlement.amount_msat) {
                prop(
                    Outcome::Pass,
                    "credited_msat plus fee_msat equals the amount",
                )
            } else {
                prop(
                    Outcome::Fail,
                    "credited_msat plus fee_msat differs from the amount",
                )
            }
        }
        (Side::Provider, ..) => prop(
            Outcome::NotChecked,
            "the receiving wallet did not report what it credited and deducted",
        ),
    };
    json!({
        "side": settlement.side.wire(),
        "segment": settlement.segment,
        "payment_hash": settlement.payment_hash,
        "amount_msat": settlement.amount_msat,
        "band": band(settlement.amount_msat),
        "properties": {
            "object_held": settlement.held.to_value(),
            "invoice_join": invoice_join.to_value(),
            "amount": amount.to_value(),
            "finality": finality.to_value(),
            "preimage": prop(Outcome::NotChecked, "the settlement object carries no preimage").to_value(),
            "payee_credit": payee_credit.to_value(),
        },
    })
}

/// The adapter's result for one exchange's observations.
///
/// `result` is `PASS` when at least one settlement is held and every
/// property of every settlement is `PASS` or `NOT_CHECKED`; `FAIL` when any
/// property is `FAIL` (an invoice or other record whose `event_ref` fails
/// counts); otherwise `INCONCLUSIVE`, which includes an exchange whose
/// invoices have no terminal settlement held.
pub fn check_exchange(exchange_id: &str, observations: &[&Observation]) -> Value {
    let invoices: Vec<&Observation> = observations
        .iter()
        .copied()
        .filter(|o| o.kind == Kind::Invoice)
        .collect();
    let settlements: Vec<Value> = observations
        .iter()
        .filter(|o| o.kind == Kind::Settlement)
        .map(|s| check_settlement(s, &invoices))
        .collect();
    let unsettled: Vec<Value> = invoices
        .iter()
        .filter(|i| {
            !observations.iter().any(|o| {
                o.kind == Kind::Settlement
                    && o.side == i.side
                    && o.segment == i.segment
            })
        })
        .map(|i| json!({"side": i.side.wire(), "segment": i.segment, "payment_hash": i.payment_hash}))
        .collect();
    let outcomes: Vec<&str> = settlements
        .iter()
        .flat_map(|s| {
            s["properties"]
                .as_object()
                .into_iter()
                .flat_map(|p| p.values().filter_map(|v| v["result"].as_str()))
        })
        .chain(
            observations
                .iter()
                .filter(|o| o.kind != Kind::Settlement)
                .map(|o| o.held.outcome.wire()),
        )
        .collect();
    let result = if outcomes.contains(&Outcome::Fail.wire()) {
        Outcome::Fail
    } else if settlements.is_empty()
        || !unsettled.is_empty()
        || outcomes.contains(&Outcome::Inconclusive.wire())
    {
        Outcome::Inconclusive
    } else {
        Outcome::Pass
    };
    json!({
        "exchange_id": exchange_id,
        "adapter": LIGHTNING_ADAPTER,
        "result": result.wire(),
        "settlements": settlements,
        "invoices_without_settlement": unsettled,
    })
}

/// The whole report over the settlement records a book holds, in ledger
/// order. `settlement_records` counts every settlement record the book
/// holds, read or not: the denominator for any count of settled exchanges.
pub fn report(records: impl IntoIterator<Item = Value>, exchange_id: Option<&str>) -> Value {
    let mut settlement_records = 0u64;
    let mut unread = 0u64;
    let mut by_exchange: BTreeMap<String, Vec<Observation>> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for record in records {
        if record.pointer(SETTLEMENT_BLOCK).is_none() {
            continue;
        }
        settlement_records += 1;
        let Some(obs) = Observation::from_lifecycle_record(&record) else {
            unread += 1;
            continue;
        };
        if !by_exchange.contains_key(&obs.exchange_id) {
            order.push(obs.exchange_id.clone());
        }
        by_exchange
            .entry(obs.exchange_id.clone())
            .or_default()
            .push(obs);
    }
    let exchanges: Vec<Value> = order
        .iter()
        .filter(|id| exchange_id.is_none_or(|want| want == id.as_str()))
        .map(|id| {
            let held: Vec<&Observation> = by_exchange[id].iter().collect();
            check_exchange(id, &held)
        })
        .collect();
    json!({
        "adapter": LIGHTNING_ADAPTER,
        "settlement_records": settlement_records,
        "settlement_records_unread": unread,
        "exchanges_with_settlement_records": order.len(),
        "exchanges": exchanges,
    })
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SettlementCheckArgs {
    /// Check only this exchange id. Without it, every exchange the book
    /// holds settlement records for.
    #[serde(default)]
    pub exchange_id: Option<String>,
}

/// `settlement_check`: [`report`] over this node's book.
pub async fn handle(
    args: SettlementCheckArgs,
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
) -> mesh_llm_plugin::PluginResult<Value> {
    tokio::task::spawn_blocking(move || -> Result<Value, String> {
        let mut records = Vec::new();
        for id in capsules.capsule_ids_in_order() {
            match capsules.lookup(&id) {
                Ok(Some(entry)) => records.push(entry.capsule),
                Ok(None) => {}
                Err(e) => return Err(format!("the ledger could not be read: {e}")),
            }
        }
        Ok(report(records, args.exchange_id.as_deref()))
    })
    .await
    .map_err(|e| {
        mesh_llm_plugin::PluginError::internal(format!("settlement_check did not complete: {e}"))
    })?
    .map_err(mesh_llm_plugin::PluginError::internal)
}

#[cfg(test)]
mod tests;
