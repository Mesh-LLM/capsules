//! A provider's exact model id from the host's console status, for a
//! service evidence agreement when the exchange event names none
//! (evidencebook#48, R11).
//!
//! The session's model policy names the model by the provider's own
//! canonical reference. Hosts up to mesh-llm 0.78 (2809443) leave
//! `serving_provenance.model_canonical_ref` null on both sides, and the
//! admission hook's `backend_selected` carries only the name the client
//! asked for. The host's `GET /api/status`, on the same console the plugin
//! already reads announced keys from (`peer_keys::announced`), lists each
//! node's `serving_models`: the node's own at the top level, each peer's
//! under `peers[]`, named by a prefix of its node id. A node serving exactly
//! one model gives that model; one serving several, or none, or a peer the
//! status does not name exactly once, gives nothing, and no session is
//! proposed or cited for it rather than one guessed.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::Value;

const ROUTE: &str = "/api/status";
const TIMEOUT: Duration = Duration::from_secs(2);
/// After a failed read, how long the console is not asked again, so an
/// unreachable console does not cost each exchange its timeout.
const BACK_OFF: Duration = Duration::from_secs(30);
/// The shortest node id prefix the status may name a peer by.
const MIN_PREFIX: usize = 8;

/// The one model in `models`, if it lists exactly one.
fn only_one(models: Option<&Value>) -> Option<String> {
    match models?.as_array()?.as_slice() {
        [only] => only.as_str().filter(|m| !m.is_empty()).map(String::from),
        _ => None,
    }
}

/// The model this node serves, from its own status.
pub fn own_model(status: &Value) -> Option<String> {
    only_one(status.get("serving_models"))
}

/// The model the peer `peer_id` (full lowercase hex) serves: the one entry
/// of `serving_models` of the one `peers[]` entry whose `id` is a prefix of
/// `peer_id`.
pub fn peer_model(status: &Value, peer_id: &str) -> Option<String> {
    let peer_id = peer_id.to_ascii_lowercase();
    let mut named = status.get("peers")?.as_array()?.iter().filter(|peer| {
        peer.get("id").and_then(Value::as_str).is_some_and(|id| {
            id.len() >= MIN_PREFIX
                && id.bytes().all(|b| b.is_ascii_hexdigit())
                && peer_id.starts_with(&id.to_ascii_lowercase())
        })
    });
    let peer = named.next()?;
    if named.next().is_some() {
        return None;
    }
    only_one(peer.get("serving_models"))
}

/// The host's id for a local GGUF whose bytes hash to `weights_digest`
/// (mesh-llm `direct_gguf_model_id`, startup_models.rs: `local-gguf/sha256-`
/// and the file's SHA-256), the name its status lists the model by. A
/// provider's served exchange states this digest even when it names no
/// model (mesh-llm 0.78); `None` unless it is a SHA-256 in hex.
pub fn local_gguf_ref(weights_digest: &str) -> Option<String> {
    (weights_digest.len() == 64 && weights_digest.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| format!("local-gguf/sha256-{}", weights_digest.to_ascii_lowercase()))
}

/// The host's status, read now; `None` when it cannot be read, or within
/// [`BACK_OFF`] of a read that failed. Never reused: a model the provider
/// changed is read as changed.
async fn fetch() -> Option<Value> {
    static FAILED: Mutex<Option<Instant>> = Mutex::new(None);
    let backing_off = |at: &Option<Instant>| at.is_some_and(|at| at.elapsed() < BACK_OFF);
    if backing_off(&FAILED.lock().unwrap_or_else(PoisonError::into_inner)) {
        return None;
    }
    let status = fetch_from(&crate::peer_keys::announced::console_url()).await;
    if status.is_none() {
        *FAILED.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
    }
    status
}

/// [`fetch`] from the console at `base`.
async fn fetch_from(base: &str) -> Option<Value> {
    let url = format!("{}{ROUTE}", base.trim_end_matches('/'));
    let client = reqwest::Client::builder().timeout(TIMEOUT).build().ok()?;
    let response = client.get(&url).send().await.ok()?;
    if !response.status().is_success() {
        tracing::debug!(status = %response.status(), "host status not read");
        return None;
    }
    response.json().await.ok()
}

/// [`own_model`], read from the host now.
pub async fn own_model_now() -> Option<String> {
    own_model(&fetch().await?)
}

/// [`peer_model`], read from the host now.
pub async fn peer_model_now(peer_id: &str) -> Option<String> {
    peer_model(&fetch().await?, peer_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SHOCKLEY: &str = "284a8bb62c0491b1a27f57425ce585626f7dc9a1495de4519a869a8c11d9f478";
    const MODEL: &str =
        "local-gguf/sha256-74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db";

    /// As Brattain's host (mesh-llm 0.78, 2dc55de) answers, trimmed.
    fn status() -> Value {
        json!({
            "node_id": "c5e7af08d8",
            "serving_models": [],
            "peers": [
                {"id": "bacb082de9", "serving_models": []},
                {"id": "284a8bb62c", "serving_models": [MODEL]},
                {"id": "82e2fe799a", "serving_models": ["Qwen3.6-27B-Q6_K", "other"]},
            ],
        })
    }

    #[test]
    fn a_peer_serving_one_model_gives_it_by_its_id_prefix() {
        assert_eq!(peer_model(&status(), SHOCKLEY).as_deref(), Some(MODEL));
        assert_eq!(
            peer_model(&status(), &SHOCKLEY.to_ascii_uppercase()).as_deref(),
            Some(MODEL)
        );
    }

    /// Nothing is guessed: no model, several, a peer the status lists twice
    /// or not at all, or an id too short to name one, give nothing.
    #[test]
    fn an_ambiguous_or_unlisted_peer_gives_no_model() {
        let several = format!("82e2fe799a{}", "0".repeat(54));
        let none = format!("bacb082de9{}", "0".repeat(54));
        let unlisted = "f".repeat(64);
        for peer in [several.as_str(), none.as_str(), unlisted.as_str()] {
            assert_eq!(peer_model(&status(), peer), None, "{peer}");
        }
        let mut twice = status();
        twice["peers"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id": "284a8bb6", "serving_models": [MODEL]}));
        assert_eq!(peer_model(&twice, SHOCKLEY), None);
        let short = json!({"peers": [{"id": "284a", "serving_models": [MODEL]}]});
        assert_eq!(peer_model(&short, SHOCKLEY), None);
    }

    /// Read over HTTP from a console that answers as Brattain's host does,
    /// as the exchange path does when the event names no model; a console
    /// that cannot be read gives nothing.
    #[tokio::test]
    async fn the_model_is_read_from_the_hosts_console() {
        let app =
            axum::Router::new().route(ROUTE, axum::routing::get(|| async { axum::Json(status()) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let read = fetch_from(&base).await.expect("the status is read");
        assert_eq!(peer_model(&read, SHOCKLEY).as_deref(), Some(MODEL));
        assert_eq!(fetch_from("http://127.0.0.1:9").await, None);
    }

    /// As Shockley's served halves state it: the digest is the one in the
    /// name its status lists. Anything but a SHA-256 in hex gives nothing.
    #[test]
    fn a_weights_digest_gives_the_local_gguf_name_it_is_listed_by() {
        let digest = MODEL.trim_start_matches("local-gguf/sha256-");
        assert_eq!(local_gguf_ref(digest).as_deref(), Some(MODEL));
        assert_eq!(
            local_gguf_ref(&digest.to_ascii_uppercase()).as_deref(),
            Some(MODEL)
        );
        for not in [
            "",
            "sha256:loaded-weights",
            &digest[..63],
            &format!("{digest}0"),
        ] {
            assert_eq!(local_gguf_ref(not), None, "{not}");
        }
        assert_eq!(local_gguf_ref(&format!("{}g", &digest[..63])), None);
    }

    #[test]
    fn this_node_gives_its_own_model_only_when_it_serves_one() {
        assert_eq!(
            own_model(&json!({"serving_models": [MODEL]})).as_deref(),
            Some(MODEL)
        );
        assert_eq!(own_model(&status()), None);
        assert_eq!(own_model(&json!({"serving_models": ["a", "b"]})), None);
        assert_eq!(own_model(&json!({})), None);
    }
}
