//! `x-capsules-agreement/1`: the private plugin mesh channel a requester
//! sets up a service evidence agreement with a provider over
//! ([`crate::agreement`]). Like `commitment/1`, it is declared in the
//! manifest and carried by mesh-llm's plugin mesh streams;
//! `OpenStreamRequest` names no channel, so the requester tags its open with
//! [`agreement::CHANNEL`] in `metadata_json` and `main.rs` dispatches on it.
//!
//! **The frames.** Each message is one stream: the requester writes its
//! frame and half-closes, the provider answers and closes. Records travel as
//! JSON text, so each side keeps the octets the other signed.
//!
//! - `{"proposed": "<record>", "documents": {...}}` → `{"answer": "<record>"}`
//!   (`accepted` or `declined`), or `{"error": "<why>"}`.
//! - `{"receipt": "<receipt>"}` → `{"ok": true}` or `{"error": "<why>"}`.
//!
//! A provider that predates agreements routes the tagged open to its
//! evidence responder, which answers at once with a frame of another shape:
//! the requester reads any reply without `answer` as "no agreement" and does
//! not wait (R9).
//!
//! **Who may propose.** The provider answers only a proposer whose key a
//! peer announced (`peer_keys`), so an accepted record always names a
//! requester the provider can map to a node.
//!
//! **When.** The requester sets up a session on its first exchange with a
//! provider once the operator set session terms
//! ([`agreement::SessionTerms::from_settings`]), and again once the session's
//! window ends (R11). That first exchange is outside the agreement; later
//! exchanges in the window cite it.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{bind_side_stream, LocalListener, PluginContext, PluginError, PluginResult};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use crate::agreement::{self, Answer, Kind, Proposal, SessionTerms, Store};
use crate::capsule_emit::CapsuleState;
use crate::mesh_evidence_bridge::{env_millis, next_stream_id, read_to_end_bounded};

/// True exactly when an inbound `OpenStreamRequest` is this module's.
pub fn is_agreement_request(request: &OpenStreamRequest) -> bool {
    request.metadata_json.as_deref() == Some(agreement::CHANNEL)
}

fn responder_timeout() -> Duration {
    env_millis("CAPSULES_AGREEMENT_RESPONDER_TIMEOUT_MS", 10_000)
}

/// The bounded wait for the provider's answer (R9).
fn requester_timeout_ms() -> u64 {
    env_millis("CAPSULES_AGREEMENT_TIMEOUT_MS", 8_000).as_millis() as u64
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn own_key(capsules: &CapsuleState) -> String {
    hex::encode(capsules.public_key())
}

// ---------------------------------------------------------------------
// Provider role
// ---------------------------------------------------------------------

/// The provider's reply to one frame. `known_requester` says whether a peer
/// announced the proposer's key.
pub fn respond(
    capsules: &CapsuleState,
    store: &Store,
    frame: &[u8],
    known_requester: &dyn Fn(&str) -> bool,
    now: i64,
) -> Value {
    let error = |why: String| json!({ "error": why });
    let Some(msg) = evidence_request::acceptance::parse(frame) else {
        return error(agreement::Refusal::Malformed.to_string());
    };
    if msg.get("proposed").is_some() {
        let checked = match agreement::check_proposal(frame, &own_key(capsules), now) {
            Ok(c) => c,
            Err(why) => return error(why.to_string()),
        };
        let proposer = checked
            .record
            .get("proposer")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !known_requester(proposer) {
            return error("no peer announced the proposer's key".into());
        }
        let answer = agreement::answer(&checked, capsules.signing_key(), true, now);
        let answer_text = answer.to_string();
        let kept = store
            .put(Kind::Record, checked.record_text.as_bytes())
            .and_then(|_| store.put(Kind::Record, answer_text.as_bytes()))
            .and_then(|_| put_documents(store, checked.documents.iter()));
        if let Err(e) = kept {
            tracing::warn!(error = %e, "agreement records not kept; declining");
            return error("the provider could not keep the records".into());
        }
        return json!({ "answer": answer_text });
    }
    if let Some(text) = msg.get("receipt").and_then(Value::as_str) {
        return match check_receipt(store, text, &own_key(capsules)) {
            Ok(()) => match store.put(Kind::Receipt, text.as_bytes()) {
                Ok(_) => json!({ "ok": true }),
                Err(_) => error("the provider could not keep the receipt".into()),
            },
            Err(why) => error(why.into()),
        };
    }
    error("an agreement frame holds `proposed` or `receipt`".into())
}

/// Keep the session's documents, each under its digest, so the cap, the
/// count and the model policy are read later from what was agreed.
fn put_documents<'a>(store: &Store, docs: impl Iterator<Item = &'a Value>) -> std::io::Result<()> {
    for doc in docs {
        store.put(Kind::Document, doc.to_string().as_bytes())?;
    }
    Ok(())
}

/// A receipt the provider keeps: for an accepted record it holds, as
/// acceptor, signed by that record's proposer.
fn check_receipt(store: &Store, text: &str, own_key: &str) -> Result<(), &'static str> {
    let rc = evidence_request::acceptance::parse(text.as_bytes()).ok_or("not JSON")?;
    let digest = rc
        .get("acceptance_digest")
        .and_then(Value::as_str)
        .ok_or("no acceptance_digest")?;
    let record = store
        .get(Kind::Record, digest)
        .and_then(|o| evidence_request::acceptance::parse(&o))
        .ok_or("the provider holds no such accepted record")?;
    let field = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(String::from);
    if field(&record, "state").as_deref() != Some("accepted")
        || field(&record, "acceptor").as_deref() != Some(own_key)
    {
        return Err("the provider holds no such accepted record");
    }
    if field(&rc, "receiver") != field(&record, "proposer") {
        return Err("the receipt is not the proposer's");
    }
    let Value::Object(map) = &rc else {
        return Err("not an object");
    };
    if !receipt_verifies(map) {
        return Err("the receipt's signature does not verify");
    }
    Ok(())
}

fn receipt_verifies(rc: &serde_json::Map<String, Value>) -> bool {
    let get = |k: &str| rc.get(k).and_then(Value::as_str);
    let (Some(key), Some(sig)) = (get("receiver"), get("sig")) else {
        return false;
    };
    (|| {
        let key: [u8; 32] = hex::decode(key).ok()?.try_into().ok()?;
        let sig: [u8; 64] = hex::decode(sig).ok()?.try_into().ok()?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key).ok()?;
        let body = evidence_request::acceptance::signing_input(rc).ok()?;
        key.verify_strict(body.as_bytes(), &ed25519_dalek::Signature::from_bytes(&sig))
            .ok()
    })()
    .is_some()
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
    let reply = tokio::task::spawn_blocking(move || {
        let store = Store::open(capsules.ledger_dir());
        let registry = crate::peer_keys::registry();
        let known =
            |key: &str| crate::peer_keys::peer_id_for_key_in(registry.as_deref(), key).is_some();
        respond(&capsules, &store, &frame, &known, now())
    })
    .await?;
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

/// The accepted session between `proposer` and `acceptor` whose window holds
/// `now`, the latest-starting one if several do.
pub fn active_session(store: &Store, proposer: &str, acceptor: &str, now: i64) -> Option<Session> {
    let time = |r: &Value, k: &str| {
        r.get("session")?
            .get(k)?
            .as_str()
            .and_then(evidence_request::time::parse_rfc3339)
            .map(|t| t.seconds)
    };
    store
        .all(Kind::Record)
        .into_iter()
        .filter_map(|o| evidence_request::acceptance::parse(&o))
        .filter(|r| {
            r.get("state").and_then(Value::as_str) == Some("accepted")
                && r.get("proposer").and_then(Value::as_str) == Some(proposer)
                && r.get("acceptor").and_then(Value::as_str) == Some(acceptor)
                && time(r, "not_before").is_some_and(|nb| nb <= now)
                && time(r, "not_after").is_some_and(|na| now <= na)
        })
        .max_by_key(|r| time(r, "not_before"))
        .map(|record| Session {
            acceptance_digest: evidence_request::acceptance::record_digest(&record)
                .unwrap_or_default(),
            record,
        })
}

/// What the requester concluded from the provider's reply to a proposal.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// Accepted: the records are kept and the receipt is to be sent.
    Accepted { session: Session, receipt: Value },
    /// Declined, countered, refused, or a provider without the channel.
    NoAgreement(String),
}

/// The requester's step after the provider's reply: check the answer, keep
/// the proposal and the answer as sent, and sign the receipt (§11.1.4).
pub fn conclude(
    capsules: &CapsuleState,
    store: &Store,
    proposal: &Proposal,
    reply: &[u8],
    now: i64,
) -> Outcome {
    let Some(text) = evidence_request::acceptance::parse(reply)
        .and_then(|r| r.get("answer").and_then(Value::as_str).map(String::from))
    else {
        return Outcome::NoAgreement("the provider gave no answer".into());
    };
    match agreement::check_answer(proposal, text.as_bytes()) {
        Ok(Answer::Accepted { record, digest }) => {
            let kept = store
                .put(Kind::Record, proposal.record_text.as_bytes())
                .and_then(|_| store.put(Kind::Record, text.as_bytes()))
                .and_then(|_| put_documents(store, proposal.documents().into_iter()));
            if let Err(e) = kept {
                return Outcome::NoAgreement(format!("the records could not be kept: {e}"));
            }
            let receipt = agreement::receipt(&digest, capsules.signing_key(), now);
            if let Err(e) = store.put(Kind::Receipt, receipt.to_string().as_bytes()) {
                return Outcome::NoAgreement(format!("the receipt could not be kept: {e}"));
            }
            Outcome::Accepted {
                session: Session {
                    acceptance_digest: digest,
                    record,
                },
                receipt,
            }
        }
        Ok(Answer::NotAccepted) => Outcome::NoAgreement("the provider did not accept".into()),
        Err(why) => Outcome::NoAgreement(why.to_string()),
    }
}

/// Peers a proposal is in flight to, so one exchange event at a time
/// proposes per provider.
static IN_FLIGHT: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

/// Set up a session with the provider at `peer_id` if the operator set
/// session terms, a peer announced the provider's key, and no session with
/// it holds the present time. Best effort: a failure is logged, never
/// raised; the exchange it was triggered by is unaffected.
pub async fn ensure_session(
    context: &mut PluginContext<'_>,
    capsules: &Arc<CapsuleState>,
    peer_id: &str,
    model: &str,
) {
    let Some(terms) = SessionTerms::from_settings() else {
        return;
    };
    let registry = crate::peer_keys::registry();
    let Some(provider_key) = crate::peer_keys::announced_key_in(registry.as_deref(), peer_id)
    else {
        tracing::debug!(%peer_id, "no announced key for the provider; no agreement proposed");
        return;
    };
    let store = Store::open(capsules.ledger_dir());
    let own = own_key(capsules);
    if active_session(&store, &own, &provider_key, now()).is_some() {
        return;
    }
    {
        let mut in_flight = IN_FLIGHT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !in_flight.insert(peer_id.to_string()) {
            return;
        }
    }
    let result = propose(
        context,
        capsules,
        &store,
        peer_id,
        &provider_key,
        &terms,
        model,
    )
    .await;
    IN_FLIGHT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(peer_id);
    match result {
        Ok(Outcome::Accepted { session, .. }) => {
            tracing::info!(%peer_id, acceptance = %session.acceptance_digest, "service evidence agreement accepted")
        }
        Ok(Outcome::NoAgreement(why)) => {
            tracing::info!(%peer_id, %why, "no service evidence agreement")
        }
        Err(error) => tracing::info!(%peer_id, %error, "no service evidence agreement"),
    }
}

async fn propose(
    context: &mut PluginContext<'_>,
    capsules: &Arc<CapsuleState>,
    store: &Store,
    peer_id: &str,
    provider_key: &str,
    terms: &SessionTerms,
    model: &str,
) -> anyhow::Result<Outcome> {
    let proposal = Proposal::new(
        capsules.signing_key(),
        provider_key,
        &agreement::new_session_id(),
        terms,
        &[model.to_string()],
        now(),
    );
    let reply = exchange_frame(context, peer_id, &proposal.to_message()).await?;
    let outcome = conclude(capsules, store, &proposal, &reply, now());
    if let Outcome::Accepted { receipt, .. } = &outcome {
        // The provider keeps the receipt to serve with its History (R10). A
        // receipt it did not take is still the requester's ordering
        // evidence, kept above.
        let frame = serde_json::to_vec(&json!({ "receipt": receipt.to_string() }))?;
        if let Err(error) = exchange_frame(context, peer_id, &frame).await {
            tracing::info!(%peer_id, %error, "agreement receipt not delivered to the provider");
        }
    }
    Ok(outcome)
}

async fn exchange_frame(
    context: &mut PluginContext<'_>,
    peer_id: &str,
    frame: &[u8],
) -> anyhow::Result<Vec<u8>> {
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
        idle_timeout_ms: Some(requester_timeout_ms()),
    };
    let stream = context
        .connect_mesh_stream(open)
        .await
        .map_err(|e| anyhow::anyhow!("could not reach the provider: {e}"))?;
    let (read_half, mut write_half) = stream.into_split();
    let bytes = tokio::time::timeout(Duration::from_millis(requester_timeout_ms()), async {
        write_half.write_all(frame).await?;
        write_half.shutdown().await?;
        read_to_end_bounded(read_half, "agreement reply").await
    })
    .await
    .map_err(|_| anyhow::anyhow!("no reply within the bounded wait"))??;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agreement::SessionTerms;

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

    const NOW: i64 = 1_793_000_000;

    /// Requester and provider in process: proposal, answer, receipt, and the
    /// session each side then holds.
    #[test]
    fn a_proposal_becomes_a_session_both_sides_hold() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (requester, provider) = (node(a.path(), "requester"), node(b.path(), "provider"));
        let (rstore, pstore) = (
            Store::open(requester.ledger_dir()),
            Store::open(provider.ledger_dir()),
        );
        let proposal = Proposal::new(
            requester.signing_key(),
            &own_key(&provider),
            &agreement::new_session_id(),
            &terms(),
            &["m".into()],
            NOW,
        );
        let reply = respond(
            &provider,
            &pstore,
            &proposal.to_message(),
            &|_| true,
            NOW + 1,
        );
        let Outcome::Accepted { session, receipt } = conclude(
            &requester,
            &rstore,
            &proposal,
            &serde_json::to_vec(&reply).unwrap(),
            NOW + 2,
        ) else {
            panic!("accepted: {reply}")
        };
        let ack = respond(
            &provider,
            &pstore,
            &serde_json::to_vec(&json!({"receipt": receipt.to_string()})).unwrap(),
            &|_| true,
            NOW + 3,
        );
        assert_eq!(ack, json!({"ok": true}));
        for (store, label) in [(&rstore, "requester"), (&pstore, "provider")] {
            let held = active_session(store, &own_key(&requester), &own_key(&provider), NOW + 10)
                .unwrap_or_else(|| panic!("{label} holds the session"));
            assert_eq!(held, session, "{label}");
            assert_eq!(
                store.all(Kind::Receipt).len(),
                1,
                "{label} keeps the receipt"
            );
            let terms_digest = held.record["session"]["terms"].as_str().unwrap();
            let terms_doc = store
                .get(Kind::Document, terms_digest)
                .expect("the terms document");
            assert_eq!(
                agreement::read_terms(&serde_json::from_slice(&terms_doc).unwrap()),
                Some(agreement::Terms {
                    spend_cap_msat: 3_000,
                    max_exchanges: Some(2)
                }),
                "{label}"
            );
        }
        // The proposal's octets are kept as sent, on both sides.
        let d = proposal.digest();
        assert_eq!(rstore.get(Kind::Record, &d), pstore.get(Kind::Record, &d),);
        assert_eq!(
            rstore.get(Kind::Record, &d).unwrap(),
            proposal.record_text.as_bytes()
        );
        // Outside its window, the session is not active.
        assert_eq!(
            active_session(
                &rstore,
                &own_key(&requester),
                &own_key(&provider),
                NOW + 3_601
            ),
            None
        );
    }

    #[test]
    fn a_provider_answers_only_an_announced_requester() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (requester, provider) = (node(a.path(), "requester"), node(b.path(), "provider"));
        let pstore = Store::open(provider.ledger_dir());
        let proposal = Proposal::new(
            requester.signing_key(),
            &own_key(&provider),
            &agreement::new_session_id(),
            &terms(),
            &["m".into()],
            NOW,
        );
        let reply = respond(&provider, &pstore, &proposal.to_message(), &|_| false, NOW);
        assert!(reply.get("error").is_some(), "{reply}");
        assert!(pstore.all(Kind::Record).is_empty(), "nothing kept");
    }

    #[test]
    fn a_provider_keeps_only_its_own_proposers_receipt() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (requester, provider) = (node(a.path(), "requester"), node(b.path(), "provider"));
        let (rstore, pstore) = (
            Store::open(requester.ledger_dir()),
            Store::open(provider.ledger_dir()),
        );
        let proposal = Proposal::new(
            requester.signing_key(),
            &own_key(&provider),
            &agreement::new_session_id(),
            &terms(),
            &["m".into()],
            NOW,
        );
        let reply = respond(&provider, &pstore, &proposal.to_message(), &|_| true, NOW);
        let Outcome::Accepted { session, .. } = conclude(
            &requester,
            &rstore,
            &proposal,
            &serde_json::to_vec(&reply).unwrap(),
            NOW,
        ) else {
            panic!("accepted")
        };
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let forged = agreement::receipt(&session.acceptance_digest, &stranger, NOW);
        let frame = |rc: &Value| serde_json::to_vec(&json!({"receipt": rc.to_string()})).unwrap();
        let reply = respond(&provider, &pstore, &frame(&forged), &|_| true, NOW);
        assert!(reply.get("error").is_some(), "{reply}");
        let unknown = agreement::receipt(&"a".repeat(64), requester.signing_key(), NOW);
        let reply = respond(&provider, &pstore, &frame(&unknown), &|_| true, NOW);
        assert!(reply.get("error").is_some(), "{reply}");
        assert!(pstore.all(Kind::Receipt).is_empty());
    }

    #[test]
    fn a_reply_without_an_answer_is_no_agreement_at_once() {
        let a = tempfile::tempdir().unwrap();
        let requester = node(a.path(), "requester");
        let store = Store::open(requester.ledger_dir());
        let proposal = Proposal::new(
            requester.signing_key(),
            &"b".repeat(64),
            &agreement::new_session_id(),
            &terms(),
            &["m".into()],
            NOW,
        );
        // What an evidence responder that predates agreements answers.
        for reply in [
            &br#"{"error":"malformed request"}"#[..],
            b"not json",
            br#"{"refusal":{}}"#,
        ] {
            assert!(
                matches!(
                    conclude(&requester, &store, &proposal, reply, NOW),
                    Outcome::NoAgreement(_)
                ),
                "{}",
                String::from_utf8_lossy(reply)
            );
        }
        assert!(
            store.all(Kind::Record).is_empty(),
            "nothing kept without an agreement"
        );
    }
}
