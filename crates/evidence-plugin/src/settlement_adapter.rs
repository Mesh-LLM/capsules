//! The Lightning settlement adapter (`adapters/lightning-v0.md`): checks the
//! settlement objects this node holds for a paid exchange, evaluates the
//! declared predicate `settled`, and derives each exchange's value band.
//! Read-only: it seals nothing and contacts nobody.
//!
//! **The settlement object.** Today it is the host's `payment.lifecycle.v1`
//! event, which this node seals verbatim as a settlement record
//! ([`crate::settlement_channel`], `seal_settlement_record`). The adapter
//! reads those records through one reader per source
//! ([`Observation::from_lifecycle_record`]) into a rail-neutral
//! [`Observation`], so a host whose settlement objects arrive on another
//! channel needs a new reader, not a new adapter.
//!
//! **Results** use the five statuses of the interop profile (§7.1), each
//! reported as a `native_check` with the check's name in `detail.check`, as
//! the x402 declaration reports its checks. `NOT_PRESENT` means the input is
//! absent; `NOT_CHECKED` means it is present and the check was not run. Every
//! result names its method. A `finality` PASS names `preimage_verified` when
//! the settlement's preimage hashes to its `payment_hash`, and otherwise
//! `wallet_reported`: the wallet's own statement, never a proof.
//!
//! **Joining.** A settlement joins an invoice of the same side and segment
//! by `payment_hash`. A settlement with no hash joins nothing (`NOT_PRESENT`);
//! for its amount it is compared with its segment's invoice only when that
//! segment has exactly one. Payer and provider records are never joined.
//!
//! **Band** (`(currency, decade)`): per exchange and side, from the sum of
//! that side's distinct terminal settlements (deposit and final together,
//! never per payment), with no conversion: `currency` is the amount's
//! `assetCode` (`BTC`) and `decade` the signed power of ten of the amount in
//! that currency, so 250 sats is `BTC` decade -6. The currency is part of the
//! band, and a band is never compared with another currency's.
//!
//! **Counts.** The disclosed count is this node's distinct terminal
//! settlements, by `payment_hash`. Lightning has no public ledger to check it
//! against, so `public_ledger_count` is always `NOT_CHECKED`; the
//! counterparty's book is the outside count instead (`counterparty_count`,
//! [`crate::settlement_counterparty`]).

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::producer::capsule::{SETTLEMENT_BLOCK_POINTER, SETTLEMENT_CHANNEL};
use crate::producer::jcs;

/// The MCP operation name.
pub const SETTLEMENT_CHECK_OPERATION: &str = "settlement_check";

/// The adapter declaration these results are produced under.
pub const LIGHTNING_ADAPTER: &str = "lightning-v0";

/// The band's currency: the settlement-records `assetCode` a Lightning
/// amount is written in.
pub const BAND_CURRENCY: &str = "BTC";

/// The settlement-records `assetScale` of a Lightning amount: the value is
/// in msat, 1e-11 BTC.
pub const BAND_ASSET_SCALE: i64 = 11;

/// The finality method: the wallet's report, which the declaration names.
pub const FINALITY_METHOD: &str = "wallet_reported";

/// The finality method when the settlement carries a preimage that hashes to
/// its `payment_hash`: the payee released it, so the payment completed.
pub const PREIMAGE_FINALITY_METHOD: &str = "preimage_verified";

/// A property status (interop profile §7.1). Never a score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    NotPresent,
    NotChecked,
    Inconclusive,
}

impl Status {
    pub fn wire(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::NotPresent => "NOT_PRESENT",
            Status::NotChecked => "NOT_CHECKED",
            Status::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// One check's status and the method (or reason) behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub status: Status,
    pub method: &'static str,
}

fn check(status: Status, method: &'static str) -> Check {
    Check { status, method }
}

impl Check {
    /// A `native_check` report (interop profile §7.2), the shape the x402
    /// declaration (§7) uses.
    fn report(&self, name: &str) -> Value {
        json!({
            "property": "native_check",
            "status": self.status.wire(),
            "method": self.method,
            "detail": {"check": name, "object": SETTLEMENT_CHANNEL},
        })
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
    /// The payment's preimage, when the settlement object carries one.
    pub preimage: Option<String>,
    /// The rail reported this payment terminal.
    pub terminal: bool,
    pub held: Check,
}

impl Observation {
    /// The `payment.lifecycle.v1` reader: one sealed settlement record.
    /// `None` for a record that is not a settlement record or lacks the
    /// fields every such record carries.
    pub fn from_lifecycle_record(record: &Value) -> Option<Self> {
        let block = record.pointer(SETTLEMENT_BLOCK_POINTER)?.as_object()?;
        let s = |k: &str| block.get(k).and_then(Value::as_str);
        let u = |k: &str| block.get(k).and_then(Value::as_u64);
        let exchange_id = s("exchange_id").filter(|x| !x.is_empty())?.to_string();
        let side = match s("observed_by")? {
            "payer" => Side::Payer,
            "provider" => Side::Provider,
            _ => return None,
        };
        let kind = match s("phase")? {
            "input_invoice_issued" | "output_invoice_issued" => Kind::Invoice,
            "input_settlement_observed" | "output_settlement_observed" => Kind::Settlement,
            _ => Kind::Other,
        };
        Some(Self {
            exchange_id,
            side,
            kind,
            segment: u("segment").and_then(|v| u32::try_from(v).ok()),
            payment_hash: s("payment_hash")
                .filter(|h| !h.is_empty())
                .map(str::to_string),
            amount_msat: u("amount_msat")?,
            credited_msat: u("credited_msat"),
            fee_msat: u("fee_msat"),
            preimage: s("preimage").map(str::to_string),
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
fn lifecycle_event_ref(block: &Map<String, Value>) -> Check {
    let Some(claimed) = block.get("event_ref").and_then(Value::as_str) else {
        return check(Status::NotPresent, "the record carries no event_ref");
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
        "preimage",
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
            return check(Status::Pass, "event_ref recomputed over the host's event");
        }
    }
    check(
        Status::Inconclusive,
        "event_ref does not recompute over any host event shape this plugin knows",
    )
}

/// The `(currency, decade)` band of an amount (the signed decade the
/// standard history card is to adopt, AAC #440): `currency` is the
/// `assetCode`, and `decade` is
/// `floor(log10(value / 10^assetScale))`, signed, which in exact integer
/// arithmetic is the digits of `value` minus `assetScale` minus one. So
/// 250 sats is `BTC` decade -6 and 1 msat is decade -11. Zero has no
/// decade: its band is `"decade": null`, still in its currency, so every
/// amount has a band.
pub fn band(amount_msat: u64) -> Value {
    let decade = amount_msat
        .checked_ilog10()
        .map(|digits| digits as i64 - BAND_ASSET_SCALE);
    json!({"currency": BAND_CURRENCY, "decade": decade})
}

/// The invoice a settlement is compared with: the one of the same side and
/// segment under its hash; with no hash, the segment's only invoice.
fn invoice_for<'a>(
    settlement: &Observation,
    invoices: &[&'a Observation],
) -> (Check, Option<&'a Observation>) {
    let on_segment: Vec<&Observation> = invoices
        .iter()
        .copied()
        .filter(|i| i.side == settlement.side && i.segment == settlement.segment)
        .collect();
    match &settlement.payment_hash {
        None => (
            check(
                Status::NotPresent,
                "the wallet reported no payment_hash for this settlement",
            ),
            match on_segment.as_slice() {
                [only] => Some(*only),
                _ => None,
            },
        ),
        Some(hash) => match on_segment
            .iter()
            .find(|i| i.payment_hash.as_ref() == Some(hash))
        {
            Some(invoice) => (
                check(
                    Status::Pass,
                    "payment_hash equals an invoice's for the same exchange, side and segment",
                ),
                Some(*invoice),
            ),
            None if on_segment.is_empty() => (
                check(
                    Status::NotPresent,
                    "no invoice for this segment is held on this side",
                ),
                None,
            ),
            None => (
                check(
                    Status::Fail,
                    "payment_hash is not the hash of any invoice for the same exchange, side and segment",
                ),
                None,
            ),
        },
    }
}

/// `sha256(preimage) == payment_hash`, the hash the invoice commits to.
fn preimage_check(settlement: &Observation) -> Check {
    use sha2::{Digest, Sha256};
    let Some(preimage) = &settlement.preimage else {
        return check(
            Status::NotPresent,
            "the settlement object carries no preimage",
        );
    };
    let Some(hash) = &settlement.payment_hash else {
        return check(
            Status::NotPresent,
            "the settlement names no payment_hash to check the preimage against",
        );
    };
    let bytes = match hex::decode(preimage) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return check(Status::Fail, "the preimage is not 32 bytes of hex"),
    };
    if hex::encode(Sha256::digest(&bytes)).eq_ignore_ascii_case(hash) {
        check(Status::Pass, "sha256(preimage) equals payment_hash")
    } else {
        check(Status::Fail, "sha256(preimage) differs from payment_hash")
    }
}

/// One terminal settlement's checks, in declaration order.
fn settlement_checks(
    settlement: &Observation,
    invoices: &[&Observation],
) -> Vec<(&'static str, Check)> {
    let (invoice_join, invoice) = invoice_for(settlement, invoices);
    let amount = match invoice {
        None => check(Status::NotPresent, "no invoice to compare the amount with"),
        Some(i) if i.amount_msat == 0 => check(Status::NotPresent, "the invoice names no amount"),
        Some(i) if i.amount_msat == settlement.amount_msat => {
            check(Status::Pass, "settled amount equals the invoice amount")
        }
        Some(_) => check(
            Status::Fail,
            "settled amount differs from the invoice amount",
        ),
    };
    let preimage = preimage_check(settlement);
    // A preimage that hashes to the payment hash is the rail's own proof of
    // completion and outranks the wallet's word; one that does not is a
    // failed finality whatever the wallet said.
    let finality = match preimage.status {
        Status::Pass => check(Status::Pass, PREIMAGE_FINALITY_METHOD),
        Status::Fail => check(
            Status::Fail,
            "the preimage does not hash to the payment_hash",
        ),
        _ if settlement.terminal => check(Status::Pass, FINALITY_METHOD),
        _ => check(Status::Fail, "the settlement is not reported terminal"),
    };
    let payee_credit = match (
        settlement.side,
        settlement.credited_msat,
        settlement.fee_msat,
    ) {
        (Side::Payer, ..) => check(
            Status::NotChecked,
            "the payer's wallet does not see what the payee credited",
        ),
        (Side::Provider, Some(credited), Some(fee)) => {
            if credited.checked_add(fee) == Some(settlement.amount_msat) {
                check(
                    Status::Pass,
                    "credited_msat plus fee_msat equals the amount",
                )
            } else {
                check(
                    Status::Fail,
                    "credited_msat plus fee_msat differs from the amount",
                )
            }
        }
        (Side::Provider, ..) => check(
            Status::NotPresent,
            "the receiving wallet did not report what it credited and deducted",
        ),
    };
    vec![
        ("object_held", settlement.held.clone()),
        ("invoice_join", invoice_join),
        ("amount", amount),
        ("finality", finality),
        ("preimage", preimage),
        ("payee_credit", payee_credit),
    ]
}

/// One side's book of one exchange: every check, the `settled` predicate
/// and the band.
fn side_book(side: Side, observations: &[&Observation]) -> Value {
    let invoices: Vec<&Observation> = observations
        .iter()
        .copied()
        .filter(|o| o.kind == Kind::Invoice)
        .collect();
    let settled_objects: Vec<&Observation> = observations
        .iter()
        .copied()
        .filter(|o| o.kind == Kind::Settlement)
        .collect();
    let rows: Vec<Vec<(&'static str, Check)>> = settled_objects
        .iter()
        .map(|s| settlement_checks(s, &invoices))
        .collect();
    let settlements: Vec<Value> = settled_objects
        .iter()
        .zip(&rows)
        .map(|(s, checks)| {
            json!({
                "segment": s.segment,
                "payment_hash": s.payment_hash,
                "amount_msat": s.amount_msat,
                "checks": checks.iter().map(|(name, c)| c.report(name)).collect::<Vec<_>>(),
            })
        })
        .collect();
    // An invoice is answered only by a settlement joined under its hash.
    let unsettled: Vec<Value> = invoices
        .iter()
        .filter(|i| {
            !settled_objects.iter().any(|s| {
                s.segment == i.segment
                    && s.payment_hash.is_some()
                    && s.payment_hash == i.payment_hash
            })
        })
        .map(|i| json!({"segment": i.segment, "payment_hash": i.payment_hash}))
        .collect();
    let invoice_records: Vec<Value> = invoices
        .iter()
        .map(|i| {
            json!({
                "segment": i.segment,
                "payment_hash": i.payment_hash,
                "amount_msat": i.amount_msat,
                "checks": [i.held.report("object_held")],
            })
        })
        .collect();
    // Distinct settlements (by hash; a hashless one counts once per record)
    // summed for the band: a job split into several payments is one band.
    // A side with no terminal settlement has no amount, so no band.
    let mut seen: BTreeSet<Option<&str>> = BTreeSet::new();
    let counted: Vec<&Observation> = settled_objects
        .iter()
        .copied()
        .filter(|s| {
            s.terminal && (s.payment_hash.is_none() || seen.insert(s.payment_hash.as_deref()))
        })
        .collect();
    let total_band = (!counted.is_empty()).then(|| {
        band(
            counted
                .iter()
                .fold(0u64, |sum, s| sum.saturating_add(s.amount_msat)),
        )
    });
    let settled = settled_predicate(&rows, &invoices, unsettled.is_empty());
    json!({
        "side": side.wire(),
        "settled": settled.report_predicate(),
        "band": total_band,
        "settlements": settlements,
        "invoices": invoice_records,
        "invoices_without_settlement": unsettled,
    })
}

/// The declared predicate `settled` (declaration item (d)): every invoice
/// this side holds is answered by a terminal settlement joined under its
/// hash, every record recomputes, and no check fails. A missing preimage and
/// a payer's unseen credit are expected absences; so is an amount when the
/// joined invoice names none (with the join PASS, an invoice is held, so an
/// amount `NOT_PRESENT` can only mean that).
fn settled_predicate(
    rows: &[Vec<(&'static str, Check)>],
    invoices: &[&Observation],
    every_invoice_answered: bool,
) -> Check {
    const METHOD: &str = "lightning-v0 settled: every invoice held on this side has a terminal settlement joined by payment_hash";
    let status = |row: &[(&'static str, Check)], name: &str| {
        row.iter()
            .find(|(n, _)| *n == name)
            .map_or(Status::NotPresent, |(_, c)| c.status)
    };
    if rows.iter().flatten().any(|(_, c)| c.status == Status::Fail) {
        return check(Status::Fail, METHOD);
    }
    let every_settlement_passes = rows.iter().all(|row| {
        status(row, "object_held") == Status::Pass
            && status(row, "invoice_join") == Status::Pass
            && matches!(status(row, "amount"), Status::Pass | Status::NotPresent)
            && status(row, "finality") == Status::Pass
    });
    let invoices_held = invoices.iter().all(|i| i.held.status == Status::Pass);
    if !rows.is_empty() && every_settlement_passes && invoices_held && every_invoice_answered {
        check(Status::Pass, METHOD)
    } else {
        check(Status::Inconclusive, METHOD)
    }
}

impl Check {
    fn report_predicate(&self) -> Value {
        json!({"status": self.status.wire(), "method": self.method})
    }
}

/// One exchange: each side's book that holds records for it.
pub fn check_exchange(exchange_id: &str, observations: &[&Observation]) -> Value {
    let mut sides: BTreeMap<Side, Vec<&Observation>> = BTreeMap::new();
    for o in observations {
        sides.entry(o.side).or_default().push(o);
    }
    json!({
        "exchange_id": exchange_id,
        "books": sides
            .iter()
            .map(|(side, held)| side_book(*side, held))
            .collect::<Vec<_>>(),
    })
}

/// The whole report over the settlement records a book holds, in ledger
/// order.
///
/// - `disclosed_count`: this node's distinct terminal settlements, by
///   payment hash, whichever side observed it (a hashless one counts once
///   per record).
/// - `public_ledger_count`: always `NOT_CHECKED`; Lightning has no public
///   ledger, so the node's count is never checked against itself.
/// - `settlement_records`: every settlement record the book holds, and
///   `settlement_records_unread` those the reader could not read.
///
/// `counterparty`: the other side's verified book
/// ([`crate::settlement_counterparty`]), or why there is none; it fills
/// `counterparty_count`.
pub fn report(
    records: impl IntoIterator<Item = Value>,
    exchange_id: Option<&str>,
    counterparty: Option<Result<crate::settlement_counterparty::Books, String>>,
) -> Value {
    let mut settlement_records = 0u64;
    let mut unread = 0u64;
    let mut by_exchange: BTreeMap<String, Vec<Observation>> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for record in records {
        if record.pointer(SETTLEMENT_BLOCK_POINTER).is_none() {
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
    let mut hashed: BTreeSet<&str> = BTreeSet::new();
    let mut hashless = 0u64;
    for obs in by_exchange.values().flatten() {
        if obs.kind != Kind::Settlement || !obs.terminal {
            continue;
        }
        // One payment is one settlement, whichever side (or both) observed it.
        if let Some(hash) = obs.payment_hash.as_deref() {
            hashed.insert(hash);
        } else {
            hashless += 1;
        }
    }
    let exchanges: Vec<Value> = order
        .iter()
        .filter(|id| exchange_id.is_none_or(|want| want == id.as_str()))
        .map(|id| {
            let held: Vec<&Observation> = by_exchange[id].iter().collect();
            check_exchange(id, &held)
        })
        .collect();
    let counterparty_count = match counterparty {
        None => crate::settlement_counterparty::not_run(
            Status::NotPresent,
            "no counterparty settlement bundle was given",
        ),
        Some(Err(why)) => crate::settlement_counterparty::not_run(Status::NotChecked, &why),
        Some(Ok(books)) => crate::settlement_counterparty::cross_check(&books),
    };
    json!({
        "adapter": LIGHTNING_ADAPTER,
        "disclosed_count": {
            "settlements": hashed.len() as u64 + hashless,
            "settlements_without_payment_hash": hashless,
            "method": "distinct terminal settlements in this node's book, by payment_hash",
        },
        "public_ledger_count": {"status": Status::NotChecked.wire(), "reason": "no_public_ledger"},
        "counterparty_count": counterparty_count,
        "settlement_records": settlement_records,
        "settlement_records_unread": unread,
        "exchanges": exchanges,
    })
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SettlementCheckArgs {
    /// Check only this exchange id. Without it, every exchange the book
    /// holds settlement records for.
    #[serde(default)]
    pub exchange_id: Option<String>,
    /// The counterparty's `settlement-bundle`, to cross-check this node's
    /// count against its book (`counterparty_count`).
    #[serde(default)]
    pub counterparty_bundle: Option<Value>,
}

/// `settlement_check`: [`report`] over this node's book. Only settlement
/// records are kept in memory.
pub async fn handle(
    args: SettlementCheckArgs,
    capsules: std::sync::Arc<crate::capsule_emit::CapsuleState>,
) -> mesh_llm_plugin::PluginResult<Value> {
    let configured = crate::settings::var(crate::peer_keys::ENV_PEER_KEYS).ok();
    let announced = crate::peer_keys::announced::snapshot();
    tokio::task::spawn_blocking(move || -> Result<Value, String> {
        let counterparty = args.counterparty_bundle.as_ref().map(|bundle| {
            crate::settlement_counterparty::books(
                &capsules,
                configured.as_deref(),
                &announced,
                bundle,
            )
        });
        let mut records = Vec::new();
        for id in capsules.capsule_ids_in_order() {
            match capsules.lookup(&id) {
                Ok(Some(entry)) if entry.capsule.pointer(SETTLEMENT_BLOCK_POINTER).is_some() => {
                    records.push(entry.capsule)
                }
                Ok(_) => {}
                Err(e) => return Err(format!("the ledger could not be read: {e}")),
            }
        }
        Ok(report(records, args.exchange_id.as_deref(), counterparty))
    })
    .await
    .map_err(|e| {
        mesh_llm_plugin::PluginError::internal(format!("settlement_check did not complete: {e}"))
    })?
    .map_err(mesh_llm_plugin::PluginError::internal)
}

#[cfg(test)]
mod tests;
