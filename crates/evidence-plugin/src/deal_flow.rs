//! When a paid exchange's `x-deal-v0` deal is sealed, and what survives a
//! restart (Mesh-LLM/capsules-plugin#96, the payer's side).
//!
//! A deal exists only for an exchange with at least one invoice issued: a
//! free exchange keeps its `x-mesh-poc-v1` record and gets none. One deal per
//! exchange, `deal_id` random, never derived from an id of the exchange.
//!
//! - **baseline** once the exchange's record is sealed and an invoice was
//!   issued for it. It asks for the exchange by its request digest and model,
//!   committed under a nonce this node keeps, and names the serving peer by
//!   fingerprint only.
//! - **outcome** then **close** once the payer's legs show the deal is done
//!   (every invoice paid and the response received: `completed`), or when no
//!   settlement came within [`OPEN_AFTER`] of the first invoice or the node
//!   restarted first (`open`: the record is not final, never "pending").
//! - **report**, an in-log `deal_report` for the counterparty, after the
//!   close, citing the Mesh records each of its lines is about.
//!
//! **The share gate.** Every deal capsule is linked to the exchange record it
//! is of in `deal-links.jsonl` ([`crate::evidence_log`]) *before* it is
//! sealed, so it goes to that exchange's counterparty and to nobody else.
//!
//! **What survives a restart.** The deal's state is `deals.json`; the
//! payload each Capsule commits is journaled in `deal-payloads.jsonl` before
//! the Capsule is appended. A step counts as sealed only if its Capsule is in
//! the ledger, so a crash between the journal and the append reseals the same
//! step, and one between the append and the state file is found again from
//! the journal.
//!
//! Best-effort like the settlement legs: a deal that cannot be sealed is
//! missing evidence, never a failed exchange.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use capsule_emit_lib::produce::BuiltPayload;
use evidencebook::deal;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::deal_records::{self as records, After, Deal, Encoded};

/// How long after its first invoice a deal waits for settlement before its
/// record is closed `open`. The settlement legs are held no longer
/// ([`crate::settlement_legs::MAX_AGE`]).
pub const OPEN_AFTER: i64 = 15 * 60;
/// How many deals the state keeps; the oldest are dropped first.
const MAX_DEALS: usize = 1024;

const STATE_FILE: &str = "deals.json";
const SECRET_FILE: &str = "deal-store-secret";
/// One line per sealed Capsule: the payload it commits, in the order sealed.
pub const PAYLOADS_FILE: &str = "deal-payloads.jsonl";

/// What seals a deal's Capsules: the node's ledger.
pub trait Sealer {
    /// Seal the Capsule `build` makes on the ledger's head. `before` runs with
    /// the Capsule's id after it is built and before it is appended, under the
    /// ledger's one writer lock; if it fails nothing is appended.
    fn seal(
        &self,
        build: &dyn Fn(Option<&str>) -> Result<BuiltPayload, records::Error>,
        before: &dyn Fn(&str) -> std::io::Result<()>,
    ) -> anyhow::Result<String>;

    /// Whether the ledger holds `capsule_id`.
    fn holds(&self, capsule_id: &str) -> bool;
}

/// A deal capsule sealed, as the deal keeps it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Sealed {
    record_type: String,
    seq: i64,
    digest: String,
    capsule_id: String,
    at: String,
    /// On an outcome: it says `completed`.
    #[serde(default)]
    completed: bool,
}

/// One paid exchange's deal.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Entry {
    deal_id: String,
    /// The intent's nonce (64 hex), kept so the committed ask can be opened.
    nonce: String,
    /// When the first invoice was seen, seconds since the Unix epoch.
    started: i64,
    peer: Option<String>,
    exchange_capsule_id: Option<String>,
    request_digest: Option<String>,
    model: Option<String>,
    /// Capsule ids of this node's settlement legs for the exchange.
    terms_legs: Vec<String>,
    paid_legs: Vec<String>,
    delivered_leg: Option<String>,
    billed_msat: u64,
    paid_msat: u64,
    steps: Vec<Sealed>,
    report: Option<String>,
}

impl Entry {
    fn step(&self, record_type: &str) -> Option<&Sealed> {
        self.steps.iter().find(|s| s.record_type == record_type)
    }

    /// Every invoice seen is paid and the response is in.
    fn settled(&self) -> bool {
        self.delivered_leg.is_some()
            && !self.terms_legs.is_empty()
            && self.paid_legs.len() >= self.terms_legs.len()
    }
}

#[derive(Default)]
struct Inner {
    loaded: bool,
    secret: Option<[u8; 32]>,
    /// By the host's exchange id.
    entries: BTreeMap<String, Entry>,
}

/// This node's deals (held by `CapsuleState`).
pub struct Deals {
    dir: PathBuf,
    /// Where the store secret lives, beside the keys and away from the ledger.
    data_dir: PathBuf,
    inner: Mutex<Inner>,
}

impl Deals {
    pub fn new(ledger_dir: &Path, data_dir: &Path) -> Self {
        Self {
            dir: ledger_dir.to_path_buf(),
            data_dir: data_dir.to_path_buf(),
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The first invoice for `exchange_id` was issued and this node sealed its
    /// terms leg `leg`, for `amount_msat`.
    pub fn on_invoice(
        &self,
        sealer: &dyn Sealer,
        exchange_id: &str,
        leg: &str,
        amount_msat: u64,
        now: i64,
    ) {
        self.update(sealer, exchange_id, now, true, |e| {
            if !e.terms_legs.iter().any(|l| l == leg) {
                e.terms_legs.push(leg.to_string());
                e.billed_msat = e.billed_msat.saturating_add(amount_msat);
            }
        });
    }

    /// The exchange's own record is sealed: its id, the serving `peer`, and
    /// what was asked (the request digest) of which model.
    pub fn on_exchange(
        &self,
        sealer: &dyn Sealer,
        exchange_id: &str,
        exchange_capsule_id: &str,
        peer: &str,
        request_digest: &str,
        model: &str,
        now: i64,
    ) {
        self.update(sealer, exchange_id, now, false, |e| {
            e.exchange_capsule_id = Some(exchange_capsule_id.to_string());
            e.peer = Some(peer.to_string());
            e.request_digest = Some(request_digest.to_string());
            e.model = Some(model.to_string());
        });
    }

    /// This node sealed the payer's `payer_observed` leg `leg` (`amount_msat`
    /// paid) for the exchange.
    pub fn on_paid(&self, sealer: &dyn Sealer, exchange_id: &str, leg: &str, amount_msat: u64, now: i64) {
        self.update(sealer, exchange_id, now, false, |e| {
            if !e.paid_legs.iter().any(|l| l == leg) {
                e.paid_legs.push(leg.to_string());
                e.paid_msat = e.paid_msat.saturating_add(amount_msat);
            }
        });
    }

    /// This node sealed the payer's `delivered` leg `leg`.
    pub fn on_delivered(&self, sealer: &dyn Sealer, exchange_id: &str, leg: &str, now: i64) {
        self.update(sealer, exchange_id, now, false, |e| {
            e.delivered_leg.get_or_insert_with(|| leg.to_string());
        });
    }

    /// Time passed: close deals whose settlement did not come.
    pub fn tick(&self, sealer: &dyn Sealer, now: i64) {
        let mut inner = self.lock();
        self.load(&mut inner, sealer);
        let ids: Vec<String> = inner.entries.keys().cloned().collect();
        for id in ids {
            self.advance(&mut inner, sealer, &id, now, false);
        }
        self.save(&inner);
    }

    /// At start: a deal with a baseline and no close is closed `open` (its
    /// legs were held in memory, which a restart lost), and a deal that never
    /// got a baseline within [`OPEN_AFTER`] is dropped.
    pub fn recover(&self, sealer: &dyn Sealer, now: i64) {
        let mut inner = self.lock();
        self.load(&mut inner, sealer);
        inner
            .entries
            .retain(|_, e| e.step(deal::TYPE_BASELINE).is_some() || now - e.started < OPEN_AFTER);
        let ids: Vec<String> = inner.entries.keys().cloned().collect();
        for id in ids {
            self.advance(&mut inner, sealer, &id, now, true);
        }
        self.save(&inner);
    }

    /// The sealed steps of the deal of `exchange_id`, and its report, when
    /// there are any.
    pub fn capsules_of(&self, sealer: &dyn Sealer, exchange_id: &str) -> Vec<String> {
        let mut inner = self.lock();
        self.load(&mut inner, sealer);
        inner
            .entries
            .get(exchange_id)
            .map(|e| {
                e.steps
                    .iter()
                    .map(|s| s.capsule_id.clone())
                    .chain(e.report.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn update(
        &self,
        sealer: &dyn Sealer,
        exchange_id: &str,
        now: i64,
        creates: bool,
        change: impl FnOnce(&mut Entry),
    ) {
        let mut inner = self.lock();
        self.load(&mut inner, sealer);
        if !inner.entries.contains_key(exchange_id) {
            if !creates {
                return;
            }
            let Some(entry) = new_entry(now) else {
                return;
            };
            inner.entries.insert(exchange_id.to_string(), entry);
            while inner.entries.len() > MAX_DEALS {
                let oldest = inner
                    .entries
                    .iter()
                    .min_by_key(|(_, e)| e.started)
                    .map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => inner.entries.remove(&k),
                    None => break,
                };
            }
        }
        if let Some(entry) = inner.entries.get_mut(exchange_id) {
            change(entry);
        }
        self.advance(&mut inner, sealer, exchange_id, now, false);
        self.save(&inner);
    }

    /// Seal what is due for `exchange_id`, in order, stopping at the first
    /// step that cannot be sealed (tried again at the next event).
    fn advance(&self, inner: &mut Inner, sealer: &dyn Sealer, exchange_id: &str, now: i64, restarted: bool) {
        let Some(secret) = inner.secret else {
            return;
        };
        let Some(entry) = inner.entries.get_mut(exchange_id) else {
            return;
        };
        let deal_id = entry.deal_id.clone();
        let (Some(peer), Some(exchange), Some(digest), Some(model)) = (
            entry.peer.clone(),
            entry.exchange_capsule_id.clone(),
            entry.request_digest.clone(),
            entry.model.clone(),
        ) else {
            return;
        };
        let asked = format!("inference request {digest} for {model}");
        let d = Deal {
            key: deal::deal_key(&secret, &deal_id),
            local_values: vec![peer.clone(), asked.clone()],
            deal_id: deal_id.clone(),
        };
        let mut seal = |entry: &mut Entry, enc: Encoded, seq: i64, completed: bool| -> bool {
            match self.seal_step(sealer, &deal_id, &exchange, seq, &enc, now) {
                Some(capsule_id) => {
                    entry.steps.push(Sealed {
                        record_type: enc.record_type.to_string(),
                        seq,
                        digest: enc.digest,
                        capsule_id,
                        at: enc.at,
                        completed,
                    });
                    true
                }
                None => false,
            }
        };
        if entry.step(deal::TYPE_BASELINE).is_none() {
            if entry.terms_legs.is_empty() {
                return;
            }
            let Ok(enc) = d.baseline(&records::at(now), &peer, &entry.nonce, &asked, &model)
                .inspect_err(|error| tracing::warn!(%error, "deal baseline not built"))
            else {
                return;
            };
            if !seal(entry, enc, 1, false) {
                return;
            }
        }
        let baseline = entry.step(deal::TYPE_BASELINE).map(|s| s.digest.clone());
        let Some(baseline) = baseline else { return };
        let settled = entry.settled();
        if entry.step(deal::TYPE_OUTCOME).is_none() {
            let due = settled || restarted || now - entry.started >= OPEN_AFTER;
            if !due {
                return;
            }
            let after = After {
                seq: 2,
                prev: baseline.clone(),
                baseline: baseline.clone(),
            };
            let Ok(enc) = d.outcome(&records::at(now), &after, settled)
                .inspect_err(|error| tracing::warn!(%error, "deal outcome not built"))
            else {
                return;
            };
            if !seal(entry, enc, 2, settled) {
                return;
            }
        }
        if entry.step(deal::TYPE_CLOSE).is_none() {
            let Some(outcome) = entry.step(deal::TYPE_OUTCOME).cloned() else {
                return;
            };
            // The close says what the outcome said, whatever the legs say now.
            let closes_settled = outcome.completed;
            let after = After {
                seq: 3,
                prev: outcome.digest.clone(),
                baseline,
            };
            let Ok(enc) = d.close(&records::at(now), &after, closes_settled)
                .inspect_err(|error| tracing::warn!(%error, "deal close not built"))
            else {
                return;
            };
            if !seal(entry, enc, 3, false) {
                return;
            }
        }
        if entry.report.is_none() {
            let closed_settled = entry.step(deal::TYPE_OUTCOME).is_some_and(|o| o.completed);
            entry.report = self.seal_report(sealer, entry, &exchange, closed_settled, now);
        }
    }

    /// Link, journal, then seal one step.
    fn seal_step(
        &self,
        sealer: &dyn Sealer,
        deal_id: &str,
        exchange_capsule_id: &str,
        seq: i64,
        enc: &Encoded,
        now: i64,
    ) -> Option<String> {
        let record: Value = serde_json::from_slice(&enc.payload).ok()?;
        let result = sealer.seal(
            &|head| {
                records::step_capsule(
                    deal_id,
                    seq,
                    enc,
                    head,
                    crate::producer::capsule::LOCAL_RECORD_OPERATOR,
                    crate::producer::capsule::LOCAL_RECORD_DEVELOPER,
                    now,
                )
            },
            &|capsule_id| {
                self.link(capsule_id, exchange_capsule_id)?;
                self.journal(&json!({
                    "capsule_id": capsule_id, "deal_id": deal_id, "record_type": enc.record_type,
                    "seq": seq, "digest": enc.digest, "at": enc.at, "payload": record,
                }))
            },
        );
        match result {
            Ok(capsule_id) => Some(capsule_id),
            Err(error) => {
                tracing::warn!(%error, record_type = enc.record_type, "deal step not sealed");
                None
            }
        }
    }

    fn seal_report(
        &self,
        sealer: &dyn Sealer,
        entry: &Entry,
        exchange_capsule_id: &str,
        settled: bool,
        now: i64,
    ) -> Option<String> {
        let nonce = random_hex()?;
        let body = report_body(entry, exchange_capsule_id, settled, now);
        let payload = deal::report_payload(&deal::Report {
            deal_id: entry.deal_id.clone(),
            audience: deal::AUDIENCE_COUNTERPARTY.into(),
            nonce,
            body,
            checkpoint: None,
        })
        .map_err(|error| tracing::warn!(%error, "deal report not built"))
        .ok()?;
        let record: Value = serde_json::from_slice(&payload).ok()?;
        let result = sealer.seal(
            &|head| {
                records::report_capsule(
                    &payload,
                    head,
                    crate::producer::capsule::LOCAL_RECORD_OPERATOR,
                    crate::producer::capsule::LOCAL_RECORD_DEVELOPER,
                    now,
                )
            },
            &|capsule_id| {
                self.link(capsule_id, exchange_capsule_id)?;
                self.journal(&json!({
                    "capsule_id": capsule_id, "deal_id": entry.deal_id,
                    "record_type": deal::REPORT_TYPE, "payload": record,
                }))
            },
        );
        match result {
            Ok(capsule_id) => Some(capsule_id),
            Err(error) => {
                tracing::warn!(%error, "deal report not sealed");
                None
            }
        }
    }

    fn link(&self, capsule_id: &str, exchange_capsule_id: &str) -> std::io::Result<()> {
        append_line(
            &self.dir.join(crate::evidence_log::DEAL_LINKS_FILE),
            &json!({"capsule_id": capsule_id, "exchange_capsule_id": exchange_capsule_id}),
        )
    }

    fn journal(&self, line: &Value) -> std::io::Result<()> {
        append_line(&self.dir.join(PAYLOADS_FILE), line)
    }

    /// Read the state and the store secret once; fold in the steps the journal
    /// holds that the ledger holds too but the state does not.
    fn load(&self, inner: &mut Inner, sealer: &dyn Sealer) {
        if inner.loaded {
            return;
        }
        inner.loaded = true;
        inner.secret = read_or_make_secret(&self.data_dir.join(SECRET_FILE));
        if let Ok(text) = std::fs::read_to_string(self.dir.join(STATE_FILE)) {
            match serde_json::from_str(&text) {
                Ok(entries) => inner.entries = entries,
                Err(error) => tracing::warn!(%error, "deal state unreadable; starting empty"),
            }
        }
        let Ok(journal) = std::fs::read_to_string(self.dir.join(PAYLOADS_FILE)) else {
            return;
        };
        for line in journal.lines() {
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
            let (Some(capsule_id), Some(deal_id)) = (text("capsule_id"), text("deal_id")) else {
                continue;
            };
            if !sealer.holds(&capsule_id) {
                continue;
            }
            let Some(entry) = inner.entries.values_mut().find(|e| e.deal_id == deal_id) else {
                continue;
            };
            if v.get("record_type").and_then(Value::as_str) == Some(deal::REPORT_TYPE) {
                entry.report.get_or_insert(capsule_id);
                continue;
            }
            let (Some(record_type), Some(digest), Some(at), Some(seq)) = (
                text("record_type"),
                text("digest"),
                text("at"),
                v.get("seq").and_then(Value::as_i64),
            ) else {
                continue;
            };
            let completed = v.pointer("/payload/body/outcome").and_then(Value::as_str)
                == Some("completed");
            if entry.step(&record_type).is_none() {
                entry.steps.push(Sealed {
                    record_type,
                    seq,
                    digest,
                    capsule_id,
                    at,
                    completed,
                });
                entry.steps.sort_by_key(|s| s.seq);
            }
        }
    }

    fn save(&self, inner: &Inner) {
        let path = self.dir.join(STATE_FILE);
        let tmp = self.dir.join("deals.json.tmp");
        let write = || -> std::io::Result<()> {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(&serde_json::to_vec(&inner.entries).map_err(std::io::Error::other)?)?;
            file.sync_all()?;
            std::fs::rename(&tmp, &path)
        };
        if let Err(error) = write() {
            tracing::warn!(%error, "deal state not saved");
        }
    }
}

fn new_entry(now: i64) -> Option<Entry> {
    Some(Entry {
        deal_id: format!("deal-{}", &random_hex()?[..32]),
        nonce: random_hex()?,
        started: now,
        ..Entry::default()
    })
}

/// 256 random bits as 64 lowercase hex.
fn random_hex() -> Option<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| tracing::warn!(%error, "no randomness for a deal"))
        .ok()?;
    Some(hex::encode(bytes))
}

/// The node's `store_secret`: 32 random bytes in a file only the owner reads,
/// made on first use. The deal keys derive from it, so a leaked record
/// reveals no raw identifier.
fn read_or_make_secret(path: &Path) -> Option<[u8; 32]> {
    if let Ok(text) = std::fs::read_to_string(path) {
        if let Some(secret) = hex::decode(text.trim()).ok().and_then(|b| b.try_into().ok()) {
            return Some(secret);
        }
        tracing::warn!("deal store secret unreadable; the deal is not sealed");
        return None;
    }
    let secret = hex::decode(random_hex()?).ok()?.try_into().ok()?;
    let write = || -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(hex::encode(secret).as_bytes())?;
        file.sync_all()
    };
    match write() {
        Ok(()) => Some(secret),
        // Lost a race to another writer: read theirs.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_or_make_secret(path),
        Err(error) => {
            tracing::warn!(%error, "deal store secret not written; the deal is not sealed");
            None
        }
    }
}

fn append_line(path: &Path, line: &Value) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")?;
    file.sync_all()
}

/// The report's lines. `audience`, `did`, `money`, `lifecycle`, `steps`,
/// `told` and `scope` are the members the receipt reads
/// (capsule-viewer `receipt/model.py`). Money lines are msat text. A close
/// `open` says what this node saw: payment seen with no delivery, or no
/// payment seen, never "not delivered".
fn report_body(entry: &Entry, exchange_capsule_id: &str, settled: bool, now: i64) -> serde_json::Map<String, Value> {
    let model = entry.model.as_deref().unwrap_or("a model");
    let mut did = vec![json!({
        "text": format!("Asked a mesh node for {model}."),
        "steps": [exchange_capsule_id],
    })];
    if !entry.terms_legs.is_empty() {
        did.push(json!({
            "text": format!("Invoiced {} msat.", entry.billed_msat),
            "steps": entry.terms_legs,
        }));
    }
    if !entry.paid_legs.is_empty() {
        did.push(json!({
            "text": format!("Paid {} msat.", entry.paid_msat),
            "steps": entry.paid_legs,
        }));
    }
    if let Some(leg) = &entry.delivered_leg {
        did.push(json!({"text": "Received the response.", "steps": [leg]}));
    }
    let (state, text) = if settled {
        ("closed", "Every invoice was paid and the response was received.")
    } else if entry.paid_legs.is_empty() {
        ("open", "Payment not seen.")
    } else if entry.delivered_leg.is_none() {
        ("open", "Payment seen; delivery not recorded.")
    } else {
        ("open", "Not every invoice was seen paid.")
    };
    let steps: Vec<Value> = entry
        .steps
        .iter()
        .map(|s| json!({"capsule_id": s.capsule_id}))
        .collect();
    let mut body = serde_json::Map::new();
    body.insert("audience".into(), json!(deal::AUDIENCE_COUNTERPARTY));
    body.insert("scope".into(), json!("This node's own record of the exchange."));
    body.insert("did".into(), Value::Array(did));
    body.insert("told".into(), json!([]));
    body.insert(
        "lifecycle".into(),
        json!({"state": state, "text": text, "as_of": records::at(now), "later": []}),
    );
    body.insert("steps".into(), Value::Array(steps));
    body
}
