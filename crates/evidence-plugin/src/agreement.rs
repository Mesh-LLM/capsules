//! Service evidence agreements (PRD R-18 to R-21): one session-scoped
//! acceptance record of the interop profile (`evidence-interop/0` §11.1) per
//! bounded paid session with a provider.
//!
//! The requester proposes: a `proposed` record naming the session's Evidence
//! Contract, its model policy and its terms (spend cap, unit, payment
//! reference type, and optionally a count), each a JCS-digested document
//! carried beside the record. The provider checks the documents against
//! their digests and their shape, then answers with an `accepted` (or
//! `declined`) record. The requester checks the answer and signs the §11.1.4
//! receipt before its next request; that receipt is the session's ordering
//! evidence (P-28). Records and receipts are kept byte-exact as received
//! ([`Store`]), and their digests are computed over the parsed record
//! ([`evidence_request::acceptance::record_digest`]), never over the octets.
//!
//! Spend terms are an agent-origin assertion (§11.1.6): the payer's spend
//! control is local wallet configuration, not a signed authorization, so no
//! record carries `authority` and acceptance never authorizes spend.
//!
//! This module builds and checks the messages; carrying them is
//! [`agreement_bridge`](crate::agreement_bridge)'s job, and deciding when to
//! propose is the caller's (design rule R11).

use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use evidence_request::acceptance;
use serde_json::{json, Map, Value};

/// The private mesh channel agreement messages travel on.
pub const CHANNEL: &str = "x-capsules-agreement/1";
/// The `transaction.scheme` of a session the requester names.
pub const TRANSACTION_SCHEME: &str = "x-capsules/session";
/// The payment reference type the terms name: the one the settlement legs
/// carry (`settlement_legs`, capsule-emit `PAYMENT_REF_TYPES`).
pub const PAYMENT_REF_TYPE: &str = "ln.payment_hash";
/// The spend unit the terms name.
pub const UNIT: &str = "msat";

const PROFILE: &str = acceptance::PROFILE_ID;
const MAX_INTEGER: u64 = (1 << 53) - 1;

/// What the requester proposes for a session, from the operator's settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionTerms {
    /// The cumulative settled amount the session covers, in msat.
    pub spend_cap_msat: u64,
    /// How many exchanges the session covers; `None` for no count bound.
    pub max_exchanges: Option<u64>,
    /// How long the session lasts from its proposal, in seconds.
    pub window_seconds: u64,
}

/// The settings that set session terms.
pub const SPEND_CAP_SETTING: &str = "CAPSULES_AGREEMENT_SPEND_CAP_MSAT";
pub const MAX_EXCHANGES_SETTING: &str = "CAPSULES_AGREEMENT_MAX_EXCHANGES";
pub const WINDOW_SETTING: &str = "CAPSULES_AGREEMENT_WINDOW_SECONDS";
const DEFAULT_WINDOW_SECONDS: u64 = 3_600;

impl SessionTerms {
    /// The operator's session terms, or `None` when no spend cap is set:
    /// then no session is proposed and nothing changes (R11).
    pub fn from_settings() -> Option<SessionTerms> {
        Self::from_values(
            crate::settings::var(SPEND_CAP_SETTING).ok().as_deref(),
            crate::settings::var(MAX_EXCHANGES_SETTING).ok().as_deref(),
            crate::settings::var(WINDOW_SETTING).ok().as_deref(),
        )
    }

    fn from_values(
        cap: Option<&str>,
        count: Option<&str>,
        window: Option<&str>,
    ) -> Option<SessionTerms> {
        let uint = |s: &str| s.trim().parse::<u64>().ok().filter(|n| *n <= MAX_INTEGER);
        let spend_cap_msat = uint(cap?)?;
        let max_exchanges = match count {
            Some(c) if !c.trim().is_empty() => Some(uint(c).filter(|n| *n > 0)?),
            _ => None,
        };
        let window_seconds = match window {
            Some(w) if !w.trim().is_empty() => uint(w).filter(|n| *n > 0)?,
            _ => DEFAULT_WINDOW_SECONDS,
        };
        Some(SessionTerms {
            spend_cap_msat,
            max_exchanges,
            window_seconds,
        })
    }

    /// The terms document (DESIGN §1): JCS-digested, named by `session.terms`.
    pub fn document(&self) -> Value {
        let mut doc = json!({
            "spend_cap": self.spend_cap_msat,
            "unit": UNIT,
            "payment_ref_type": PAYMENT_REF_TYPE,
        });
        if let Some(n) = self.max_exchanges {
            doc["max_exchanges"] = json!(n);
        }
        doc
    }
}

/// The terms a provider read from a proposal's terms document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    pub spend_cap_msat: u64,
    pub max_exchanges: Option<u64>,
}

/// Read a terms document by the shape R2 fixes, or `None`.
pub fn read_terms(doc: &Value) -> Option<Terms> {
    let doc = doc.as_object()?;
    if !doc.keys().all(|k| {
        matches!(
            k.as_str(),
            "spend_cap" | "unit" | "payment_ref_type" | "max_exchanges"
        )
    }) {
        return None;
    }
    let uint = |v: &Value| v.as_u64().filter(|n| *n <= MAX_INTEGER);
    if doc.get("unit")?.as_str()? != UNIT
        || doc.get("payment_ref_type")?.as_str()? != PAYMENT_REF_TYPE
    {
        return None;
    }
    Some(Terms {
        spend_cap_msat: uint(doc.get("spend_cap")?)?,
        max_exchanges: match doc.get("max_exchanges") {
            None => None,
            Some(v) => Some(uint(v).filter(|n| *n > 0)?),
        },
    })
}

/// The digest of [`contract`], published so a reader can check a record's
/// `contract_digest`. Changing the contract's content makes it `@2`; `@1`
/// never changes.
pub const CONTRACT_DIGEST: &str =
    "5f54aa7816d9ca9f469b8c4a8c79a0a67eadf475a0de4734368aa61f74efcc01";

/// The Evidence Contract every session names: what the provider undertakes
/// to produce evidence for. Payment is not a requirement: cap and count are
/// coverage labels, and over cap is "not covered", never a failure.
pub fn contract() -> Value {
    json!({
        "id": "x-capsules/paid-session",
        "version": "1",
        "requirements": [
            {"id": "R-prior", "statement": "the agreement was accepted before the exchange"},
            {"id": "R-served", "statement": "the provider's served half is present and verifies"},
            {"id": "R-model-stated", "statement": "the model the served half states is one the session's model policy names (stated, not verified)"},
        ],
    })
}

/// The model policy document (DESIGN §1): the models a provider states it
/// serves, by canonical reference. "States", never "ran" (R-6).
pub fn model_policy(models: &[String]) -> Value {
    json!({"models": models.iter().map(|m| json!({"model_canonical_ref": m})).collect::<Vec<_>>()})
}

fn digest(v: &Value) -> String {
    acceptance::record_digest(v).expect("documents built here are JCS-representable")
}

/// The profile's time form (§5.2), whole seconds, UTC.
pub fn profile_time(unix_seconds: i64) -> String {
    chrono::DateTime::from_timestamp(unix_seconds, 0)
        .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

fn hex_key(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

/// A proposal as sent: the signed `proposed` record (and its octets) and
/// its documents.
#[derive(Clone, Debug, PartialEq)]
pub struct Proposal {
    pub record: Value,
    /// The record's octets as sent: a message carries each record as JSON
    /// text, so both sides keep the same octets.
    pub record_text: String,
    pub contract: Value,
    pub policy: Value,
    pub terms: Value,
}

impl Proposal {
    /// Build and sign a proposal from `requester` to `provider_key` for a new
    /// session `session_id` (≥128 random bits, text), starting `now`.
    pub fn new(
        requester: &SigningKey,
        provider_key: &str,
        session_id: &str,
        terms: &SessionTerms,
        models: &[String],
        now: i64,
    ) -> Proposal {
        let contract = contract();
        let policy = model_policy(models);
        let terms_doc = terms.document();
        let unsigned = json!({
            "profile": PROFILE,
            "state": "proposed",
            "contract_ref": "x-capsules/paid-session@1",
            "contract_digest": digest(&contract),
            "transaction": {"scheme": TRANSACTION_SCHEME, "id": session_id},
            "proposer": hex_key(requester),
            "acceptor": provider_key,
            "issued_at": profile_time(now),
            "session": {
                "not_before": profile_time(now),
                "not_after": profile_time(now + terms.window_seconds as i64),
                "policy": digest(&policy),
                "terms": digest(&terms_doc),
            },
        });
        let record = sign(unsigned, requester);
        Proposal {
            record_text: record.to_string(),
            record,
            contract,
            policy,
            terms: terms_doc,
        }
    }

    /// The message octets: `{"proposed": <record text>, "documents":
    /// {contract, policy, terms}}`.
    pub fn to_message(&self) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "proposed": self.record_text,
            "documents": {"contract": self.contract, "policy": self.policy, "terms": self.terms},
        }))
        .expect("JSON values serialize")
    }

    /// The contract, model policy and terms documents.
    pub fn documents(&self) -> [&Value; 3] {
        [&self.contract, &self.policy, &self.terms]
    }

    /// The record digest of the `proposed` record.
    pub fn digest(&self) -> String {
        digest(&self.record)
    }
}

fn sign(unsigned: Value, key: &SigningKey) -> Value {
    let Value::Object(map) = unsigned else {
        unreachable!("records are objects")
    };
    Value::Object(acceptance::sign(map, key).expect("records built here are JCS-representable"))
}

/// Why a provider declines a proposal, or a requester refuses an answer.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the message is not JSON in the profile's data model")]
    Malformed,
    #[error("the record is not a valid {0} record")]
    Record(&'static str),
    #[error("the record's signature does not verify")]
    Signature,
    #[error("a document is missing or does not match its digest: {0}")]
    Document(&'static str),
    #[error("the terms document is not the shape this plugin reads")]
    Terms,
    #[error("the record names another party")]
    Party,
    #[error("the session window does not hold the present time")]
    Window,
    #[error("the answer does not answer this proposal")]
    NotThisProposal,
}

/// A proposal the provider checked: its record, octets and terms.
#[derive(Clone, Debug, PartialEq)]
pub struct CheckedProposal {
    pub record: Map<String, Value>,
    pub record_text: String,
    pub digest: String,
    pub terms: Terms,
    /// The contract, model policy and terms documents, checked.
    pub documents: Vec<Value>,
}

/// The provider's check of a proposal message: it is addressed to
/// `own_key`, signed by its proposer, names this plugin's contract, and
/// carries the three documents its digests name, the terms in the shape R2
/// fixes, and a window that holds `now`.
pub fn check_proposal(message: &[u8], own_key: &str, now: i64) -> Result<CheckedProposal, Refusal> {
    let msg = acceptance::parse(message).ok_or(Refusal::Malformed)?;
    let record_text = msg
        .get("proposed")
        .and_then(Value::as_str)
        .ok_or(Refusal::Record("proposed"))?;
    let record = acceptance::parse(record_text.as_bytes()).ok_or(Refusal::Malformed)?;
    let record = &record;
    let Value::Object(r) = record else {
        return Err(Refusal::Record("proposed"));
    };
    let text = |k: &str| r.get(k).and_then(Value::as_str);
    if text("profile") != Some(PROFILE)
        || text("state") != Some("proposed")
        || r.contains_key("proposal_digest")
        || r.contains_key("authority")
    {
        return Err(Refusal::Record("proposed"));
    }
    if text("acceptor") != Some(own_key) {
        return Err(Refusal::Party);
    }
    verify(r, text("proposer"))?;
    let docs = msg.get("documents").ok_or(Refusal::Document("documents"))?;
    let session = r.get("session").ok_or(Refusal::Record("proposed"))?;
    let named = |doc: &str, digest_at: Option<&Value>| -> Result<Value, Refusal> {
        let d = docs.get(doc).ok_or(Refusal::Document(doc_name(doc)))?;
        (digest_at.and_then(Value::as_str) == Some(digest(d).as_str()))
            .then(|| d.clone())
            .ok_or(Refusal::Document(doc_name(doc)))
    };
    // The one contract this plugin undertakes, by its published digest.
    named("contract", r.get("contract_digest"))?;
    if text("contract_digest") != Some(CONTRACT_DIGEST)
        || text("contract_ref") != Some("x-capsules/paid-session@1")
    {
        return Err(Refusal::Document("contract"));
    }
    let policy = named("policy", session.get("policy"))?;
    let terms_doc = named("terms", session.get("terms"))?;
    let terms = read_terms(&terms_doc).ok_or(Refusal::Terms)?;
    let window = |k: &str| {
        session
            .get(k)
            .and_then(Value::as_str)
            .and_then(evidence_request::time::parse_rfc3339)
    };
    match (window("not_before"), window("not_after")) {
        (Some(nb), Some(na)) if nb.seconds <= now && now <= na.seconds => {}
        _ => return Err(Refusal::Window),
    }
    match r.get("transaction") {
        Some(Value::Object(t))
            if t.get("scheme").and_then(Value::as_str) == Some(TRANSACTION_SCHEME)
                && t.get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id.len() >= 32) => {}
        _ => return Err(Refusal::Record("proposed")),
    }
    Ok(CheckedProposal {
        digest: digest(record),
        record: r.clone(),
        record_text: record_text.to_string(),
        terms,
        documents: vec![self::contract(), policy, terms_doc],
    })
}

fn doc_name(doc: &str) -> &'static str {
    match doc {
        "contract" => "contract",
        "policy" => "policy",
        _ => "terms",
    }
}

fn verify(r: &Map<String, Value>, key: Option<&str>) -> Result<(), Refusal> {
    let (Some(key), Some(sig)) = (key, r.get("sig").and_then(Value::as_str)) else {
        return Err(Refusal::Signature);
    };
    let ok = (|| {
        let key: [u8; 32] = hex::decode(key).ok()?.try_into().ok()?;
        let sig: [u8; 64] = hex::decode(sig).ok()?.try_into().ok()?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key).ok()?;
        let body = acceptance::signing_input(r).ok()?;
        key.verify_strict(body.as_bytes(), &ed25519_dalek::Signature::from_bytes(&sig))
            .ok()
    })();
    ok.ok_or(Refusal::Signature)
}

/// The provider's answer to a checked proposal: `accepted` (or `declined`),
/// carrying the proposal's contract, transaction, parties and session, as
/// the §11.1.2 equality rule requires.
pub fn answer(checked: &CheckedProposal, provider: &SigningKey, accept: bool, now: i64) -> Value {
    let mut unsigned = Map::new();
    for k in [
        "profile",
        "contract_ref",
        "contract_digest",
        "transaction",
        "proposer",
        "acceptor",
        "session",
    ] {
        if let Some(v) = checked.record.get(k) {
            unsigned.insert(k.into(), v.clone());
        }
    }
    unsigned.insert(
        "state".into(),
        Value::from(if accept { "accepted" } else { "declined" }),
    );
    unsigned.insert(
        "proposal_digest".into(),
        Value::from(checked.digest.clone()),
    );
    unsigned.insert("issued_at".into(), Value::from(profile_time(now)));
    sign(Value::Object(unsigned), provider)
}

/// What a requester read from the provider's answer.
#[derive(Clone, Debug, PartialEq)]
pub enum Answer {
    /// The provider accepted: the record and its digest.
    Accepted { record: Value, digest: String },
    /// The provider declined, or countered (never auto-accepted, R9).
    NotAccepted,
}

/// The requester's check of an answer to `proposal`: signed by the
/// provider the proposal names, answering this proposal, and equal to it in
/// every member §11.1.2 compares.
pub fn check_answer(proposal: &Proposal, message: &[u8]) -> Result<Answer, Refusal> {
    let answer = acceptance::parse(message).ok_or(Refusal::Malformed)?;
    let Value::Object(a) = &answer else {
        return Err(Refusal::Record("answer"));
    };
    let p = proposal
        .record
        .as_object()
        .expect("a proposal is an object");
    if a.get("proposal_digest").and_then(Value::as_str) != Some(proposal.digest().as_str()) {
        return Err(Refusal::NotThisProposal);
    }
    verify(a, p.get("acceptor").and_then(Value::as_str))?;
    for k in [
        "profile",
        "contract_ref",
        "contract_digest",
        "transaction",
        "proposer",
        "acceptor",
        "session",
    ] {
        if a.get(k) != p.get(k) {
            return Err(Refusal::NotThisProposal);
        }
    }
    match a.get("state").and_then(Value::as_str) {
        Some("accepted") if !a.contains_key("authority") => Ok(Answer::Accepted {
            digest: digest(&answer),
            record: answer.clone(),
        }),
        Some("declined" | "countered") => Ok(Answer::NotAccepted),
        _ => Err(Refusal::Record("answer")),
    }
}

/// The requester's §11.1.4 receipt for an accepted record it holds,
/// received at `now`.
pub fn receipt(acceptance_digest: &str, requester: &SigningKey, now: i64) -> Value {
    sign(
        json!({
            "profile": PROFILE,
            "acceptance_digest": acceptance_digest,
            "received_at": profile_time(now),
            "receiver": hex_key(requester),
        }),
        requester,
    )
}

/// What kind of agreement object a stored file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Record,
    Receipt,
    Document,
}

impl Kind {
    fn dir(self) -> &'static str {
        match self {
            Kind::Record => "records",
            Kind::Receipt => "receipts",
            Kind::Document => "documents",
        }
    }
}

/// Agreement objects, kept byte-exact as sent or received, one file per
/// object named by its record digest: `<ledger>/agreements/<kind>/<digest>.json`.
/// A second copy of the same object is the same file.
pub struct Store {
    root: PathBuf,
}

impl Store {
    pub fn open(ledger_dir: &Path) -> Store {
        Store {
            root: ledger_dir.join("agreements"),
        }
    }

    /// Keep `octets` (which must parse in the profile's data model) and
    /// return their record digest.
    pub fn put(&self, kind: Kind, octets: &[u8]) -> std::io::Result<String> {
        let value = acceptance::parse(octets).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "not a profile JSON value")
        })?;
        let digest = digest(&value);
        let dir = self.root.join(kind.dir());
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{digest}.json"));
        if !path.exists() {
            let tmp = dir.join(format!(".{digest}.tmp"));
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(octets)?;
            f.sync_data()?;
            std::fs::rename(&tmp, &path)?;
        }
        Ok(digest)
    }

    /// The octets kept under `digest`, as they were kept.
    pub fn get(&self, kind: Kind, digest: &str) -> Option<Vec<u8>> {
        if !evidence_request::registry::is_digest(digest) {
            return None;
        }
        std::fs::read(self.root.join(kind.dir()).join(format!("{digest}.json"))).ok()
    }

    /// Every object of `kind` kept, as octets.
    pub fn all(&self, kind: Kind) -> Vec<Vec<u8>> {
        let Ok(entries) = std::fs::read_dir(self.root.join(kind.dir())) else {
            return Vec::new();
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        paths
            .into_iter()
            .filter_map(|p| std::fs::read(p).ok())
            .collect()
    }
}

/// A fresh session id: 128 random bits, as 32 lowercase hex.
pub fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("the OS random source is available");
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_793_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn terms() -> SessionTerms {
        SessionTerms {
            spend_cap_msat: 3_000,
            max_exchanges: Some(2),
            window_seconds: 3_600,
        }
    }

    fn proposal(requester: &SigningKey, provider: &SigningKey) -> Proposal {
        Proposal::new(
            requester,
            &hex_key(provider),
            &new_session_id(),
            &terms(),
            &["hf:example/model@main".to_string()],
            NOW,
        )
    }

    #[test]
    fn the_contract_is_the_published_one() {
        assert_eq!(digest(&contract()), CONTRACT_DIGEST);
    }

    #[test]
    fn terms_come_from_the_settings_or_not_at_all() {
        assert_eq!(SessionTerms::from_values(None, Some("2"), None), None);
        assert_eq!(
            SessionTerms::from_values(Some("3000"), None, None),
            Some(SessionTerms {
                spend_cap_msat: 3000,
                max_exchanges: None,
                window_seconds: DEFAULT_WINDOW_SECONDS
            })
        );
        assert_eq!(
            SessionTerms::from_values(Some("3000"), Some("2"), Some("60")),
            Some(SessionTerms {
                spend_cap_msat: 3000,
                max_exchanges: Some(2),
                window_seconds: 60
            })
        );
        for (cap, count, window) in [
            ("-1", "", ""),
            ("1.5", "", ""),
            ("9007199254740992", "", ""),
            ("3000", "0", ""),
            ("3000", "x", ""),
            ("3000", "", "0"),
        ] {
            assert_eq!(
                SessionTerms::from_values(Some(cap), Some(count), Some(window)),
                None,
                "{cap} {count} {window}"
            );
        }
    }

    #[test]
    fn a_proposal_round_trips_into_an_accepted_record_and_a_receipt() {
        let (p, q) = (key(1), key(2));
        let proposal = proposal(&p, &q);
        let checked = check_proposal(&proposal.to_message(), &hex_key(&q), NOW + 5).unwrap();
        assert_eq!(checked.digest, proposal.digest());
        assert_eq!(
            checked.terms,
            Terms {
                spend_cap_msat: 3_000,
                max_exchanges: Some(2)
            }
        );
        let accepted = answer(&checked, &q, true, NOW + 6);
        let octets = serde_json::to_vec(&accepted).unwrap();
        let Answer::Accepted { record, digest: d } = check_answer(&proposal, &octets).unwrap()
        else {
            panic!("accepted")
        };
        assert_eq!(record, accepted);
        let rc = receipt(&d, &p, NOW + 7);
        assert_eq!(rc["receiver"], json!(hex_key(&p)));

        // The §11.1 verifier finds the agreement and the receipt valid.
        let trust = acceptance::TrustPolicy {
            parties: [(hex_key(&p), "P".into()), (hex_key(&q), "Q".into())].into(),
            ..Default::default()
        };
        let exec = Value::Object(
            acceptance::sign(
                json!({"action_at": profile_time(NOW + 10), "issuer": hex_key(&q),
                       "links": [{"type": "cites", "target": d}],
                       "transaction": proposal.record["transaction"]})
                .as_object()
                .unwrap()
                .clone(),
                &q,
            )
            .unwrap(),
        );
        let bytes = |v: &Value| serde_json::to_vec(v).unwrap();
        assert_eq!(
            checked.record_text, proposal.record_text,
            "the octets as sent"
        );
        let (records, execs, receipts) = (
            [proposal.record_text.as_bytes().to_vec(), octets.clone()],
            [bytes(&exec)],
            [bytes(&rc)],
        );
        let res = acceptance::evaluate(
            &acceptance::Inputs {
                contract: &contract(),
                transaction: &proposal.record["transaction"],
                proposer: &hex_key(&p),
                acceptor: &hex_key(&q),
                records: &[&records[0], &records[1]],
                execution_records: &[&execs[0]],
                receipts: &[&receipts[0]],
                trust: &trust,
                evaluation_time: &profile_time(NOW + 100),
                session: true,
                form_ii_objects: 0,
                profiles_implemented: &[acceptance::PROFILE_ID],
            },
            acceptance::read_fixture_execution_record,
        )
        .unwrap();
        assert_eq!(res.finding, acceptance::Finding::AcceptedBeforeAction);
    }

    #[test]
    fn a_provider_refuses_a_proposal_it_cannot_check() {
        let (p, q) = (key(1), key(2));
        let proposal = proposal(&p, &q);
        let msg = |f: &dyn Fn(&mut Value)| {
            let mut m: Value = serde_json::from_slice(&proposal.to_message()).unwrap();
            f(&mut m);
            serde_json::to_vec(&m).unwrap()
        };
        let own = hex_key(&q);
        assert_eq!(
            check_proposal(b"{\"a\":1,\"a\":1}", &own, NOW),
            Err(Refusal::Malformed)
        );
        assert_eq!(
            check_proposal(&proposal.to_message(), &hex_key(&key(3)), NOW),
            Err(Refusal::Party),
            "addressed to another provider"
        );
        assert_eq!(
            check_proposal(
                &msg(&|m| {
                    let mut r: Value =
                        serde_json::from_str(m["proposed"].as_str().unwrap()).unwrap();
                    r["issued_at"] = json!("2026-01-01T00:00:00Z");
                    m["proposed"] = json!(r.to_string());
                }),
                &own,
                NOW
            ),
            Err(Refusal::Signature)
        );
        assert_eq!(
            check_proposal(
                &msg(&|m| m["documents"]["terms"]["spend_cap"] = json!(9)),
                &own,
                NOW
            ),
            Err(Refusal::Document("terms")),
            "a document that does not match its digest"
        );
        assert_eq!(
            check_proposal(
                &msg(&|m| {
                    m["documents"].as_object_mut().unwrap().remove("policy");
                }),
                &own,
                NOW
            ),
            Err(Refusal::Document("policy"))
        );
        assert_eq!(
            check_proposal(&proposal.to_message(), &own, NOW + 3_601),
            Err(Refusal::Window)
        );
    }

    #[test]
    fn terms_of_another_shape_are_refused() {
        let ok = json!({"spend_cap": 1, "unit": "msat", "payment_ref_type": "ln.payment_hash"});
        assert!(read_terms(&ok).is_some());
        for bad in [
            json!({"spend_cap": 1, "unit": "sat", "payment_ref_type": "ln.payment_hash"}),
            json!({"spend_cap": 1, "unit": "msat", "payment_ref_type": "bolt11"}),
            json!({"spend_cap": 1, "unit": "msat", "payment_ref_type": "ln.payment_hash", "extra": 1}),
            json!({"spend_cap": 1, "unit": "msat", "payment_ref_type": "ln.payment_hash", "max_exchanges": 0}),
            json!({"unit": "msat", "payment_ref_type": "ln.payment_hash"}),
        ] {
            assert_eq!(read_terms(&bad), None, "{bad}");
        }
    }

    #[test]
    fn a_requester_refuses_an_answer_to_another_proposal_and_never_accepts_a_counter() {
        let (p, q) = (key(1), key(2));
        let proposal = proposal(&p, &q);
        let checked = check_proposal(&proposal.to_message(), &hex_key(&q), NOW).unwrap();
        let other = self::proposal(&p, &q);
        let accepted = serde_json::to_vec(&answer(&checked, &q, true, NOW)).unwrap();
        assert_eq!(
            check_answer(&other, &accepted),
            Err(Refusal::NotThisProposal)
        );
        let by_other_key = serde_json::to_vec(&answer(&checked, &key(3), true, NOW)).unwrap();
        assert_eq!(
            check_answer(&proposal, &by_other_key),
            Err(Refusal::Signature)
        );
        let declined = serde_json::to_vec(&answer(&checked, &q, false, NOW)).unwrap();
        assert_eq!(check_answer(&proposal, &declined), Ok(Answer::NotAccepted));
        let mut counter = answer(&checked, &q, false, NOW);
        counter["state"] = json!("countered");
        counter["counter_contract_digest"] = json!("0".repeat(64));
        let counter = sign(Value::Object(counter.as_object().unwrap().clone()), &q);
        assert_eq!(
            check_answer(&proposal, &serde_json::to_vec(&counter).unwrap()),
            Ok(Answer::NotAccepted)
        );
    }

    #[test]
    fn the_store_keeps_the_octets_it_was_given() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path());
        // Member order and spacing as sent, not as re-serialized.
        let octets = br#"{ "b": "x", "a": 1 }"#;
        let d = store.put(Kind::Record, octets).unwrap();
        assert_eq!(d, digest(&json!({"a": 1, "b": "x"})));
        assert_eq!(store.get(Kind::Record, &d).as_deref(), Some(&octets[..]));
        assert_eq!(
            store.put(Kind::Record, octets).unwrap(),
            d,
            "a second copy is the same file"
        );
        assert_eq!(store.all(Kind::Record).len(), 1);
        assert!(store.put(Kind::Record, br#"{"a":1,"a":2}"#).is_err());
        assert_eq!(store.get(Kind::Record, "../x"), None);
    }
}
