//! `x-capsules-agreement/1`: the private plugin mesh channel a requester
//! sets up a service evidence agreement with a provider over
//! ([`crate::agreement`]). Like `commitment/1`, it is declared in the
//! manifest and carried by mesh-llm's plugin mesh streams;
//! `OpenStreamRequest` names no channel, so the requester tags its open with
//! [`agreement::CHANNEL`] in `metadata_json` and `main.rs` dispatches on it.
//!
//! **The frames.** Each message is one stream: the requester writes its
//! frame and half-closes, the provider answers and closes. Records,
//! receipts and documents travel as JSON text, so each side keeps the octets
//! the other signed.
//!
//! - `{"proposed": "<record>", "documents": {...}}` → `{"answer": "<record>"}`,
//!   or `{"error": "<why>"}`. A proposal sent again gets the answer first
//!   given to it, so one proposal never has two answers (§11.1.1).
//! - `{"receipt": "<receipt>"}` → `{"ok": true}` or `{"error": "<why>"}`. The
//!   first receipt kept for an acceptance stays.
//!
//! A provider that predates agreements routes the tagged open to its
//! evidence responder, which answers at once with a frame of another shape:
//! the requester reads any reply without `answer` as "no agreement" and does
//! not wait (R9).
//!
//! **Bounds.** The provider answers only a proposer whose key a peer
//! announced (`peer_keys`), at most [`MAX_IN_FLIGHT`] frames at once, and
//! holds at most [`MAX_OPEN_SESSIONS_PER_REQUESTER`] unexpired sessions per
//! requester. Kept objects are never removed yet: retention is an open item
//! (`docs/AGREEMENTS.md`).
//!
//! **When.** The requester sets up a session on an exchange with a provider
//! once the operator set session terms
//! ([`agreement::SessionTerms::from_settings`]) and no unexpired session
//! with that provider names the exchange's model (R11). That exchange is
//! outside the agreement; later exchanges in the window cite it. The set-up
//! runs in its own task, off the host's ordered channel handling, under one
//! deadline; after a failure the requester waits [`RETRY_AFTER`] before it
//! proposes to that provider again.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{bind_side_stream, LocalListener, PluginContext, PluginError, PluginResult};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use crate::agreement::{self, Answer, Kind, Proposal, SessionTerms, Store};
use crate::capsule_emit::CapsuleState;
use crate::mesh_evidence_bridge::{env_millis, next_stream_id, read_to_end_bounded};

/// The most agreement frames the provider works on at once.
pub const MAX_IN_FLIGHT: usize = 4;
/// The most unexpired sessions a provider holds with one requester.
pub const MAX_OPEN_SESSIONS_PER_REQUESTER: usize = 8;
/// The most sessions a provider accepts from one requester in a day, so
/// what it keeps grows by a bounded amount per requester.
pub const MAX_SESSIONS_PER_REQUESTER_PER_DAY: usize = 48;
/// How long a requester waits before proposing again to a provider after a
/// set-up that did not end in an agreement.
pub const RETRY_AFTER: Duration = Duration::from_secs(600);

/// True exactly when an inbound `OpenStreamRequest` is this module's.
pub fn is_agreement_request(request: &OpenStreamRequest) -> bool {
    request.metadata_json.as_deref() == Some(agreement::CHANNEL)
}

fn responder_timeout() -> Duration {
    env_millis("CAPSULES_AGREEMENT_RESPONDER_TIMEOUT_MS", 10_000)
}

/// The bounded wait for one frame's round trip, connect included (R9).
fn requester_timeout() -> Duration {
    env_millis("CAPSULES_AGREEMENT_TIMEOUT_MS", 8_000)
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn own_key(capsules: &CapsuleState) -> String {
    hex::encode(capsules.public_key())
}

fn parse(octets: &[u8]) -> Option<Value> {
    evidence_request::acceptance::parse(octets)
}

fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

fn window_start(record: &Value) -> Option<i64> {
    record
        .get("session")?
        .get("not_before")?
        .as_str()
        .and_then(evidence_request::time::parse_rfc3339)
        .map(|t| t.seconds)
}

fn window_end(record: &Value) -> Option<i64> {
    record
        .get("session")?
        .get("not_after")?
        .as_str()
        .and_then(evidence_request::time::parse_rfc3339)
        .map(|t| t.seconds)
}

// ---------------------------------------------------------------------
// Provider role
// ---------------------------------------------------------------------

/// Serializes the provider's proposal path, so a proposal sent twice at once
/// is answered once.
static PROPOSALS: Mutex<()> = Mutex::new(());

/// The provider's reply to one frame. `known_requester` says whether a peer
/// announced the proposer's key.
pub fn respond(
    capsules: &CapsuleState,
    store: &Store,
    frame: &[u8],
    known_requester: &dyn Fn(&str) -> bool,
    now: i64,
) -> Value {
    let error = |why: &str| json!({ "error": why });
    let Some(msg) = parse(frame) else {
        return error(&agreement::Refusal::Malformed.to_string());
    };
    if msg.get("proposed").is_some() {
        return match propose_answer(capsules, store, frame, known_requester, now) {
            Ok(answer_text) => json!({ "answer": answer_text }),
            Err(why) => error(&why),
        };
    }
    if let Some(receipt) = text(&msg, "receipt") {
        return match keep_receipt(store, receipt, &own_key(capsules), now) {
            Ok(()) => json!({ "ok": true }),
            Err(why) => error(&why),
        };
    }
    error("an agreement frame holds `proposed` or `receipt`")
}

fn propose_answer(
    capsules: &CapsuleState,
    store: &Store,
    frame: &[u8],
    known_requester: &dyn Fn(&str) -> bool,
    now: i64,
) -> Result<String, String> {
    let checked =
        agreement::check_proposal(frame, &own_key(capsules), now).map_err(|e| e.to_string())?;
    let proposer = checked
        .record
        .get("proposer")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !known_requester(&proposer) {
        return Err("no peer announced the proposer's key".into());
    }
    let _serial = PROPOSALS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let records: Vec<(Vec<u8>, Value)> = store
        .all(Kind::Record)
        .into_iter()
        .filter_map(|o| parse(&o).map(|v| (o, v)))
        .collect();
    // A proposal sent again gets its first answer back.
    if let Some((octets, _)) = records
        .iter()
        .find(|(_, r)| text(r, "proposal_digest") == Some(checked.digest.as_str()))
    {
        return String::from_utf8(octets.clone()).map_err(|e| e.to_string());
    }
    let mine: Vec<&Value> = records
        .iter()
        .map(|(_, r)| r)
        .filter(|r| {
            text(r, "state") == Some("accepted") && text(r, "proposer") == Some(proposer.as_str())
        })
        .collect();
    let open = mine
        .iter()
        .filter(|r| window_end(r).is_some_and(|end| now <= end + agreement::CLOCK_SKEW_SECONDS))
        .count();
    if open >= MAX_OPEN_SESSIONS_PER_REQUESTER {
        return Err("the requester already holds the most open sessions".into());
    }
    let today = mine
        .iter()
        .filter(|r| window_start(r).is_some_and(|nb| now - nb < 86_400))
        .count();
    if today >= MAX_SESSIONS_PER_REQUESTER_PER_DAY {
        return Err("the requester has set up the most sessions for a day".into());
    }
    let answer_text = agreement::answer(&checked, capsules.signing_key(), true, now).to_string();
    // The profile's verifier checks the proposal's own form and signature
    // with the answer; nothing is kept or signed away unless it passes.
    agreement::check_records(
        checked.record_text.as_bytes(),
        answer_text.as_bytes(),
        &[],
        now,
    )?;
    // Documents and the proposal first, the answer last: an answer on disk
    // always has its proposal and documents beside it.
    for doc in &checked.documents {
        store
            .put(Kind::Document, doc.as_bytes())
            .map_err(keep_error)?;
    }
    store
        .put(Kind::Record, checked.record_text.as_bytes())
        .map_err(keep_error)?;
    store
        .put(Kind::Record, answer_text.as_bytes())
        .map_err(keep_error)?;
    Ok(answer_text)
}

fn keep_error(e: std::io::Error) -> String {
    tracing::warn!(error = %e, "agreement object not kept");
    "the provider could not keep the agreement".into()
}

/// Keep a receipt for an accepted record this provider holds as acceptor,
/// once the profile's verifier finds it the proposer's (§11.1.4, §11.1.7).
fn keep_receipt(store: &Store, receipt: &str, own_key: &str, now: i64) -> Result<(), String> {
    let rc = parse(receipt.as_bytes()).ok_or("the receipt is not JSON")?;
    let digest = text(&rc, "acceptance_digest").ok_or("no acceptance_digest")?;
    let accepted = store
        .get(Kind::Record, digest)
        .ok_or("the provider holds no such accepted record")?;
    let record = parse(&accepted).ok_or("the provider holds no such accepted record")?;
    if text(&record, "state") != Some("accepted") || text(&record, "acceptor") != Some(own_key) {
        return Err("the provider holds no such accepted record".into());
    }
    let proposed = text(&record, "proposal_digest")
        .and_then(|d| store.get(Kind::Record, d))
        .ok_or("the provider holds no proposal for that acceptance")?;
    let _serial = PROPOSALS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if receipt_for(store, digest).is_some() {
        return Ok(());
    }
    agreement::check_records(&proposed, &accepted, &[receipt.as_bytes()], now)?;
    store
        .put(Kind::Receipt, receipt.as_bytes())
        .map_err(keep_error)?;
    Ok(())
}

/// The receipt kept for the acceptance `digest`, if any.
fn receipt_for(store: &Store, digest: &str) -> Option<Vec<u8>> {
    store
        .all(Kind::Receipt)
        .into_iter()
        .find(|o| parse(o).is_some_and(|rc| text(&rc, "acceptance_digest") == Some(digest)))
}

fn in_flight() -> &'static tokio::sync::Semaphore {
    static SEMAPHORE: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SEMAPHORE.get_or_init(|| tokio::sync::Semaphore::new(MAX_IN_FLIGHT))
}

pub async fn handle_open_stream(
    request: OpenStreamRequest,
    capsules: Arc<CapsuleState>,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);
    tokio::spawn(async move {
        if let Err(error) = bridge_inbound(listener, capsules).await {
            tracing::warn!(%error, "agreement responder bridge failed");
        }
    });
    Ok(Some(response))
}

async fn bridge_inbound(
    listener: LocalListener,
    capsules: Arc<CapsuleState>,
) -> anyhow::Result<()> {
    let local = tokio::time::timeout(responder_timeout(), listener.accept()).await??;
    let (mut read_half, mut write_half) = local.into_split();
    let frame = tokio::time::timeout(
        responder_timeout(),
        read_to_end_bounded(&mut read_half, "inbound agreement frame"),
    )
    .await??;
    let reply = match in_flight().try_acquire() {
        Err(_) => json!({ "error": "the provider is busy; try again later" }),
        Ok(_permit) => {
            tokio::task::spawn_blocking(move || {
                let store = Store::open(capsules.ledger_dir());
                let registry = crate::peer_keys::registry();
                let known = |key: &str| {
                    crate::peer_keys::peer_id_for_key_in(registry.as_deref(), key).is_some()
                };
                respond(&capsules, &store, &frame, &known, now())
            })
            .await?
        }
    };
    let bytes = serde_json::to_vec(&reply)?;
    tokio::time::timeout(responder_timeout(), async {
        write_half.write_all(&bytes).await?;
        write_half.shutdown().await
    })
    .await??;
    Ok(())
}

// ---------------------------------------------------------------------
// Requester role
// ---------------------------------------------------------------------

/// An accepted session the requester holds with a provider.
#[derive(Clone, Debug, PartialEq)]
pub struct Session {
    pub acceptance_digest: String,
    pub record: Value,
}

/// The unexpired session between `proposer` and `acceptor` that holds `now`,
/// names `model` in its model policy, and has its receipt and documents
/// kept; the latest-starting one if several do. A session whose set-up did
/// not finish (a receipt or document not kept) is never active.
pub fn active_session(
    store: &Store,
    proposer: &str,
    acceptor: &str,
    model: &str,
    now: i64,
) -> Option<Session> {
    let start = |r: &Value| {
        r.get("session")?
            .get("not_before")?
            .as_str()
            .and_then(evidence_request::time::parse_rfc3339)
            .map(|t| t.seconds)
    };
    let document = |r: &Value, k: &str| {
        r.get("session")?
            .get(k)?
            .as_str()
            .and_then(|d| store.get(Kind::Document, d))
            .and_then(|o| parse(&o))
    };
    store
        .all(Kind::Record)
        .into_iter()
        .filter_map(|o| parse(&o))
        .filter(|r| {
            text(r, "state") == Some("accepted")
                && text(r, "proposer") == Some(proposer)
                && text(r, "acceptor") == Some(acceptor)
                && start(r).is_some_and(|nb| nb - agreement::CLOCK_SKEW_SECONDS <= now)
                && window_end(r).is_some_and(|na| now <= na)
                && document(r, "terms").is_some()
                && document(r, "policy")
                    .and_then(|p| agreement::read_policy(&p))
                    .is_some_and(|models| models.iter().any(|m| m == model))
        })
        .filter_map(|record| {
            let digest = evidence_request::acceptance::record_digest(&record).ok()?;
            receipt_for(store, &digest)?;
            Some((start(&record), digest, record))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, acceptance_digest, record)| Session {
            acceptance_digest,
            record,
        })
}

/// What the requester concluded from the provider's reply to a proposal.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// Accepted: everything is kept and the receipt is to be sent.
    Accepted { session: Session, receipt: String },
    /// Declined, countered, refused, or a provider without the channel.
    NoAgreement(String),
}

/// The requester's step after the provider's reply: check the answer, sign
/// the receipt (§11.1.4), and keep the documents, the receipt, the proposal
/// and last the answer, so an answer on disk always has the rest beside it.
pub fn conclude(
    capsules: &CapsuleState,
    store: &Store,
    proposal: &Proposal,
    reply: &[u8],
    now: i64,
) -> Outcome {
    let Some(answer_text) = parse(reply).and_then(|r| text(&r, "answer").map(String::from)) else {
        return Outcome::NoAgreement("the provider gave no answer".into());
    };
    let (answer_text, digest) = match agreement::check_answer(proposal, &answer_text, now) {
        Ok(Answer::Accepted { text, digest }) => (text, digest),
        Ok(Answer::NotAccepted) => {
            return Outcome::NoAgreement("the provider did not accept".into())
        }
        Err(why) => return Outcome::NoAgreement(why.to_string()),
    };
    let receipt = agreement::receipt(&digest, capsules.signing_key(), now).to_string();
    let kept = (|| {
        for doc in &proposal.documents {
            store.put(Kind::Document, doc.as_bytes())?;
        }
        store.put(Kind::Receipt, receipt.as_bytes())?;
        store.put(Kind::Record, proposal.record_text.as_bytes())?;
        store.put(Kind::Record, answer_text.as_bytes())
    })();
    if let Err(e) = kept {
        return Outcome::NoAgreement(format!("the agreement could not be kept: {e}"));
    }
    Outcome::Accepted {
        session: Session {
            acceptance_digest: digest,
            record: parse(answer_text.as_bytes()).unwrap_or_default(),
        },
        receipt,
    }
}

/// Per provider: a set-up in flight (`None`), or when the last one that did
/// not end in an agreement finished.
static ATTEMPTS: Mutex<BTreeMap<String, Option<Instant>>> = Mutex::new(BTreeMap::new());

/// Whether a set-up with `peer_id` may start at `now`; if so, it is marked
/// in flight. A set-up in flight, or one that failed less than
/// [`RETRY_AFTER`] ago, holds the next back.
fn begin_attempt(
    attempts: &mut BTreeMap<String, Option<Instant>>,
    peer_id: &str,
    now: Instant,
) -> bool {
    match attempts.get(peer_id) {
        Some(None) => false,
        Some(Some(failed)) if now.duration_since(*failed) < RETRY_AFTER => false,
        _ => {
            attempts.insert(peer_id.to_string(), None);
            true
        }
    }
}

/// Ends the in-flight mark when the set-up ends, however it ends.
struct Attempt {
    peer_id: String,
    agreed: bool,
}

impl Drop for Attempt {
    fn drop(&mut self) {
        let mut attempts = ATTEMPTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.agreed {
            attempts.remove(&self.peer_id);
        } else {
            attempts.insert(self.peer_id.clone(), Some(Instant::now()));
        }
    }
}

/// Set up a session with the provider at `peer_id`, in its own task, if the
/// operator set session terms, a peer announced the provider's key, and no
/// unexpired session with it names `model`. Best effort: a failure is
/// logged, never raised; the exchange it was triggered by is unaffected.
pub fn ensure_session(
    context: PluginContext<'static>,
    capsules: Arc<CapsuleState>,
    peer_id: String,
    model: String,
) {
    let Some(terms) = SessionTerms::from_settings() else {
        return;
    };
    tokio::spawn(async move {
        let mut context = context;
        let peer = peer_id.clone();
        let result = set_up(&mut context, capsules, peer_id, model, terms).await;
        match result {
            Ok(Some(Outcome::Accepted { session, .. })) => {
                tracing::info!(peer_id = %peer, acceptance = %session.acceptance_digest, "service evidence agreement accepted")
            }
            Ok(Some(Outcome::NoAgreement(why))) => {
                tracing::info!(peer_id = %peer, %why, "no service evidence agreement")
            }
            Ok(None) => {}
            Err(error) => tracing::info!(peer_id = %peer, %error, "no service evidence agreement"),
        }
    });
}

async fn set_up(
    context: &mut PluginContext<'static>,
    capsules: Arc<CapsuleState>,
    peer_id: String,
    model: String,
    terms: SessionTerms,
) -> anyhow::Result<Option<Outcome>> {
    let registry = crate::peer_keys::registry();
    let Some(provider_key) = crate::peer_keys::announced_key_in(registry.as_deref(), &peer_id)
    else {
        tracing::debug!(%peer_id, "no announced key for the provider; no agreement proposed");
        return Ok(None);
    };
    // The in-flight mark first, then the session check, so two exchange
    // events never both find no session and both propose; and the cheap
    // in-memory check before the scan of what is kept.
    let started = {
        let mut attempts = ATTEMPTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        begin_attempt(&mut attempts, &peer_id, Instant::now())
    };
    if !started {
        return Ok(None);
    }
    let mut attempt = Attempt {
        peer_id: peer_id.clone(),
        agreed: false,
    };
    let held = {
        let (capsules, provider_key, model) =
            (capsules.clone(), provider_key.clone(), model.clone());
        tokio::task::spawn_blocking(move || {
            let store = Store::open(capsules.ledger_dir());
            active_session(&store, &own_key(&capsules), &provider_key, &model, now()).is_some()
        })
        .await?
    };
    if held {
        // Not a failure: no cool-down.
        attempt.agreed = true;
        return Ok(None);
    }
    let proposal = Proposal::new(
        capsules.signing_key(),
        &provider_key,
        &agreement::new_session_id(),
        &terms,
        &[model],
        now(),
    );
    let reply = exchange_frame(context, &peer_id, &proposal.to_message()).await?;
    let outcome = {
        let capsules = capsules.clone();
        tokio::task::spawn_blocking(move || {
            let store = Store::open(capsules.ledger_dir());
            conclude(&capsules, &store, &proposal, &reply, now())
        })
        .await?
    };
    if let Outcome::Accepted { receipt, .. } = &outcome {
        attempt.agreed = true;
        // The provider keeps the receipt to serve with its History (R10). A
        // receipt it did not take is still the requester's ordering
        // evidence, kept above.
        let frame = serde_json::to_vec(&json!({ "receipt": receipt }))?;
        if let Err(error) = exchange_frame(context, &peer_id, &frame).await {
            tracing::info!(%peer_id, %error, "agreement receipt not delivered to the provider");
        }
    }
    Ok(Some(outcome))
}

async fn exchange_frame(
    context: &mut PluginContext<'_>,
    peer_id: &str,
    frame: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let deadline = requester_timeout();
    let open = OpenMeshStreamRequest {
        stream_id: next_stream_id("agreement"),
        target_peer_id: peer_id.to_string(),
        plugin_id: String::new(), // the host fills this in.
        channel: agreement::CHANNEL.to_string(),
        purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
        mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
        bidirectional: true,
        content_type: Some("application/json".to_string()),
        correlation_id: Some(next_stream_id("agreement-correlation")),
        metadata_json: Some(agreement::CHANNEL.to_string()),
        expected_bytes: None,
        idle_timeout_ms: Some(deadline.as_millis() as u64),
    };
    // One deadline covers the connect, the write and the reply.
    tokio::time::timeout(deadline, async {
        let stream = context
            .connect_mesh_stream(open)
            .await
            .map_err(|e| anyhow::anyhow!("could not reach the provider: {e}"))?;
        let (read_half, mut write_half) = stream.into_split();
        write_half.write_all(frame).await?;
        write_half.shutdown().await?;
        Ok::<_, anyhow::Error>(read_to_end_bounded(read_half, "agreement reply").await?)
    })
    .await
    .map_err(|_| anyhow::anyhow!("no reply within the bounded wait"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agreement::SessionTerms;

    const NOW: i64 = 1_793_000_000;
    const MODEL: &str = "hf:example/model@main";

    fn node(dir: &std::path::Path, name: &str) -> CapsuleState {
        CapsuleState::open(dir, name).unwrap()
    }

    fn terms() -> SessionTerms {
        SessionTerms {
            spend_cap_msat: 3_000,
            max_exchanges: Some(2),
            window_seconds: 3_600,
        }
    }

    struct Pair {
        _dirs: (tempfile::TempDir, tempfile::TempDir),
        requester: CapsuleState,
        provider: CapsuleState,
        rstore: Store,
        pstore: Store,
    }

    fn pair() -> Pair {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (requester, provider) = (node(a.path(), "requester"), node(b.path(), "provider"));
        let (rstore, pstore) = (
            Store::open(requester.ledger_dir()),
            Store::open(provider.ledger_dir()),
        );
        Pair {
            _dirs: (a, b),
            requester,
            provider,
            rstore,
            pstore,
        }
    }

    impl Pair {
        fn proposal(&self, now: i64) -> Proposal {
            Proposal::new(
                self.requester.signing_key(),
                &own_key(&self.provider),
                &agreement::new_session_id(),
                &terms(),
                &[MODEL.into()],
                now,
            )
        }
        fn propose(&self, proposal: &Proposal, now: i64) -> Value {
            respond(
                &self.provider,
                &self.pstore,
                &proposal.to_message(),
                &|_| true,
                now,
            )
        }
        fn conclude(&self, proposal: &Proposal, reply: &Value, now: i64) -> Outcome {
            conclude(
                &self.requester,
                &self.rstore,
                proposal,
                &serde_json::to_vec(reply).unwrap(),
                now,
            )
        }
        fn send_receipt(&self, receipt: &str, now: i64) -> Value {
            respond(
                &self.provider,
                &self.pstore,
                &serde_json::to_vec(&json!({"receipt": receipt})).unwrap(),
                &|_| true,
                now,
            )
        }
        fn session(&self, store: &Store, model: &str, now: i64) -> Option<Session> {
            active_session(
                store,
                &own_key(&self.requester),
                &own_key(&self.provider),
                model,
                now,
            )
        }
        fn agree(&self, now: i64) -> (Proposal, Session, String) {
            let proposal = self.proposal(now);
            let reply = self.propose(&proposal, now);
            let Outcome::Accepted { session, receipt } = self.conclude(&proposal, &reply, now)
            else {
                panic!("accepted: {reply}")
            };
            assert_eq!(self.send_receipt(&receipt, now), json!({"ok": true}));
            (proposal, session, receipt)
        }
    }

    /// Requester and provider in process: proposal, answer, receipt, and the
    /// session each side then holds, with the same octets on both sides.
    #[test]
    fn a_proposal_becomes_a_session_both_sides_hold() {
        let p = pair();
        let (proposal, session, _) = p.agree(NOW);
        for (store, label) in [(&p.rstore, "requester"), (&p.pstore, "provider")] {
            let held = p
                .session(store, MODEL, NOW + 10)
                .unwrap_or_else(|| panic!("{label} holds the session"));
            assert_eq!(held, session, "{label}");
            assert_eq!(
                store.all(Kind::Receipt).len(),
                1,
                "{label} keeps the receipt"
            );
            assert_eq!(
                store.all(Kind::Document).len(),
                3,
                "{label} keeps the documents"
            );
            let terms_doc = store
                .get(
                    Kind::Document,
                    held.record["session"]["terms"].as_str().unwrap(),
                )
                .unwrap();
            assert_eq!(
                agreement::read_terms(&serde_json::from_slice(&terms_doc).unwrap()),
                Some(agreement::Terms {
                    spend_cap_msat: 3_000,
                    max_exchanges: Some(2)
                }),
                "{label}"
            );
        }
        // The same octets on both sides: the proposal, the answer, the
        // receipt and every document.
        for kind in [Kind::Record, Kind::Receipt, Kind::Document] {
            assert_eq!(p.rstore.all(kind), p.pstore.all(kind), "{kind:?}");
        }
        assert_eq!(
            p.rstore.get(Kind::Record, &proposal.digest()).unwrap(),
            proposal.record_text.as_bytes()
        );
        // Not for another model, and not outside its window.
        assert_eq!(p.session(&p.rstore, "hf:other/model@main", NOW + 10), None);
        assert_eq!(p.session(&p.rstore, MODEL, NOW + 3_601), None);
    }

    #[test]
    fn a_proposal_sent_again_gets_its_first_answer() {
        let p = pair();
        let proposal = p.proposal(NOW);
        let first = p.propose(&proposal, NOW);
        let again = p.propose(&proposal, NOW + 5);
        assert_eq!(first, again, "one proposal, one answer (§11.1.1)");
        let answers = p
            .pstore
            .all(Kind::Record)
            .into_iter()
            .filter(|o| parse(o).is_some_and(|r| text(&r, "state") == Some("accepted")))
            .count();
        assert_eq!(answers, 1);
    }

    #[test]
    fn a_provider_answers_only_an_announced_requester() {
        let p = pair();
        let proposal = p.proposal(NOW);
        let reply = respond(
            &p.provider,
            &p.pstore,
            &proposal.to_message(),
            &|_| false,
            NOW,
        );
        assert!(reply.get("error").is_some(), "{reply}");
        assert!(p.pstore.all(Kind::Record).is_empty(), "nothing kept");
    }

    #[test]
    fn a_provider_holds_a_bounded_number_of_open_sessions_per_requester() {
        let p = pair();
        for i in 0..MAX_OPEN_SESSIONS_PER_REQUESTER {
            let reply = p.propose(&p.proposal(NOW + i as i64), NOW + i as i64);
            assert!(reply.get("answer").is_some(), "{reply}");
        }
        let reply = p.propose(&p.proposal(NOW + 20), NOW + 20);
        assert!(reply.get("error").is_some(), "{reply}");
        // Once the first sessions end, the requester may open more.
        let later = NOW + 3_600 + agreement::CLOCK_SKEW_SECONDS + 10;
        let reply = p.propose(&p.proposal(later), later);
        assert!(reply.get("answer").is_some(), "{reply}");
    }

    #[test]
    fn a_provider_accepts_a_bounded_number_of_sessions_per_requester_per_day() {
        let p = pair();
        let short = SessionTerms {
            window_seconds: 60,
            ..terms()
        };
        let propose_at = |t: i64| {
            let proposal = Proposal::new(
                p.requester.signing_key(),
                &own_key(&p.provider),
                &agreement::new_session_id(),
                &short,
                &[MODEL.into()],
                t,
            );
            p.propose(&proposal, t)
        };
        // One-minute sessions, one after another: never more than one open.
        let step = 60 + agreement::CLOCK_SKEW_SECONDS + 1;
        for i in 0..MAX_SESSIONS_PER_REQUESTER_PER_DAY as i64 {
            assert!(
                propose_at(NOW + i * step).get("answer").is_some(),
                "session {i}"
            );
        }
        let t = NOW + MAX_SESSIONS_PER_REQUESTER_PER_DAY as i64 * step;
        assert!(propose_at(t).get("error").is_some(), "the day's limit");
        assert!(
            propose_at(NOW + 86_400 + 10).get("answer").is_some(),
            "a day later"
        );
    }

    #[test]
    fn a_receipt_that_cannot_order_never_takes_the_first_place() {
        let p = pair();
        let proposal = p.proposal(NOW);
        let reply = p.propose(&proposal, NOW);
        let Outcome::Accepted { receipt, .. } = p.conclude(&proposal, &reply, NOW) else {
            panic!("accepted")
        };
        let mut no_time: Value = serde_json::from_str(&receipt).unwrap();
        no_time["received_at"] = Value::Null;
        no_time.as_object_mut().unwrap().remove("sig");
        let no_time = Value::Object(
            evidence_request::acceptance::sign(
                no_time.as_object().unwrap().clone(),
                p.requester.signing_key(),
            )
            .unwrap(),
        )
        .to_string();
        assert!(p.send_receipt(&no_time, NOW).get("error").is_some());
        assert_eq!(p.send_receipt(&receipt, NOW), json!({"ok": true}));
        assert!(p.session(&p.pstore, MODEL, NOW).is_some());
    }

    #[test]
    fn a_provider_keeps_one_receipt_and_only_the_proposers() {
        let p = pair();
        let proposal = p.proposal(NOW);
        let reply = p.propose(&proposal, NOW);
        let Outcome::Accepted { session, receipt } = p.conclude(&proposal, &reply, NOW) else {
            panic!("accepted")
        };
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let forged = agreement::receipt(&session.acceptance_digest, &stranger, NOW).to_string();
        assert!(p.send_receipt(&forged, NOW).get("error").is_some());
        let unknown =
            agreement::receipt(&"a".repeat(64), p.requester.signing_key(), NOW).to_string();
        assert!(p.send_receipt(&unknown, NOW).get("error").is_some());
        assert!(p.pstore.all(Kind::Receipt).is_empty());
        assert_eq!(p.send_receipt(&receipt, NOW), json!({"ok": true}));
        let later = agreement::receipt(
            &session.acceptance_digest,
            p.requester.signing_key(),
            NOW + 9,
        )
        .to_string();
        assert_eq!(p.send_receipt(&later, NOW + 9), json!({"ok": true}));
        assert_eq!(
            p.pstore.all(Kind::Receipt),
            vec![receipt.into_bytes()],
            "the first receipt stays"
        );
    }

    #[test]
    fn a_reply_without_an_answer_is_no_agreement_at_once() {
        let p = pair();
        let proposal = p.proposal(NOW);
        // What an evidence responder that predates agreements answers.
        for reply in [
            &br#"{"error":"malformed request"}"#[..],
            b"not json",
            br#"{"refusal":{}}"#,
        ] {
            assert!(
                matches!(
                    conclude(&p.requester, &p.rstore, &proposal, reply, NOW),
                    Outcome::NoAgreement(_)
                ),
                "{}",
                String::from_utf8_lossy(reply)
            );
        }
        assert!(
            p.rstore.all(Kind::Record).is_empty(),
            "nothing kept without an agreement"
        );
    }

    #[test]
    fn a_session_whose_set_up_did_not_finish_is_not_active() {
        let p = pair();
        let (_, session, _) = p.agree(NOW);
        // The requester lost its receipt: its session is not active, so it
        // proposes again rather than relying on a session it cannot order.
        let receipts = p.rstore.root_for_tests().join("receipts");
        std::fs::remove_dir_all(&receipts).unwrap();
        assert_eq!(p.session(&p.rstore, MODEL, NOW + 10), None);
        assert!(p.session(&p.pstore, MODEL, NOW + 10).is_some());
        let _ = session;
    }

    #[test]
    fn the_latest_starting_session_is_the_active_one() {
        let p = pair();
        let (_, _, _) = p.agree(NOW);
        let (_, second, _) = p.agree(NOW + 100);
        assert_eq!(p.session(&p.rstore, MODEL, NOW + 200), Some(second));
    }

    #[test]
    fn a_failed_set_up_holds_the_next_back_for_a_while() {
        let mut attempts = BTreeMap::new();
        let t0 = Instant::now();
        assert!(begin_attempt(&mut attempts, "peer", t0));
        assert!(!begin_attempt(&mut attempts, "peer", t0), "one in flight");
        assert!(begin_attempt(&mut attempts, "other", t0), "per peer");
        attempts.insert("peer".into(), Some(t0));
        assert!(!begin_attempt(
            &mut attempts,
            "peer",
            t0 + Duration::from_secs(1)
        ));
        assert!(begin_attempt(&mut attempts, "peer", t0 + RETRY_AFTER));
    }

    #[test]
    fn only_a_tagged_open_is_an_agreement_frame() {
        let mut request = OpenStreamRequest::default();
        assert!(!is_agreement_request(&request));
        request.metadata_json = Some(crate::commitment_bridge::COMMITMENT_CHANNEL.into());
        assert!(!is_agreement_request(&request));
        request.metadata_json = Some(agreement::CHANNEL.into());
        assert!(is_agreement_request(&request));
        assert!(!crate::commitment_bridge::is_commitment_request(&request));
    }
}
