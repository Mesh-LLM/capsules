//! `commitment/1`: the plugin mesh channel a peer fetches this node's
//! commitment over (`crate::commitment`). It is a plugin channel declared in
//! the manifest (`mesh_channel`), carried by mesh-llm's existing plugin mesh
//! streams, with no mesh-llm core change and no gossip slot (Steven's
//! 2026-10-26 ruling on Mesh-LLM/capsules-plugin#51).
//!
//! **The frame.** The requester writes `{}` and half-closes. The responder
//! writes `{"commitment": {...}, "policy": "<base64>"}`, where `policy` is
//! the signed policy file's bytes, so the requester hashes exactly what the
//! commitment's `lcap.policy_digest` commits to; or `{"error": "<why>"}`
//! when it has none (no checkpoint yet, or its mesh id is not known yet).
//! The commitment is the same for every asker and is given to anyone: it
//! says only what the node can answer, under which policy. Nothing in the
//! frame is signed but the commitment and the policy themselves.
//!
//! **Dispatch.** As for `ledger-fetch/1`, `OpenStreamRequest` names no
//! channel, so the requester tags its open with [`COMMITMENT_CHANNEL`] in
//! `metadata_json` and `main.rs` dispatches on that tag.
//!
//! **The two operations.** `commitment` returns this node's own pair, for
//! the operator to publish to loop's `nodes/commitments/` (the commitment as
//! `<node_id>.json`, the policy bytes as `policies/<node_id>.json`).
//! `mesh_commitment_fetch` fetches a peer's pair over this channel and checks
//! it ([`crate::commitment::verify`]), that it names the peer asked, and,
//! when the host announced the peer's key, that it is under that key.
use std::sync::Arc;
use std::time::Duration;

use mesh_llm_plugin::proto::{OpenMeshStreamRequest, OpenStreamRequest, OpenStreamResponse};
use mesh_llm_plugin::{
    bind_side_stream, LocalListener, LocalStream, PluginContext, PluginError, PluginResult,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use crate::capsule_emit::CapsuleState;
use crate::commitment::{self, Signed};
use crate::mesh_evidence_bridge::{env_millis, next_stream_id, read_to_end_bounded};

/// The mesh channel, declared on both ends, and the tag the requester puts
/// in its open's `metadata_json`.
pub const COMMITMENT_CHANNEL: &str = "commitment/1";

/// `POST /api/plugins/<plugin_id>/tools/commitment`.
pub const OWN_COMMITMENT_OPERATION: &str = "commitment";

/// `POST /api/plugins/<plugin_id>/tools/mesh_commitment_fetch`.
pub const FETCH_COMMITMENT_OPERATION: &str = "mesh_commitment_fetch";

/// True exactly when an inbound `OpenStreamRequest` is this module's.
pub fn is_commitment_request(request: &OpenStreamRequest) -> bool {
    request.metadata_json.as_deref() == Some(COMMITMENT_CHANNEL)
}

/// How long the responder waits at each step of an open stream.
fn responder_timeout() -> Duration {
    env_millis("CAPSULES_COMMITMENT_HTTP_TIMEOUT_MS", 10_000)
}

/// How long the requester waits for the reply once the stream is open.
fn requester_idle_timeout_ms() -> u64 {
    env_millis("CAPSULES_COMMITMENT_TIMEOUT_MS", 8_000).as_millis() as u64
}

/// This node's commitment as it stands now, or why there is none.
fn own(capsules: &CapsuleState, node_id: Option<&str>) -> Result<Signed, String> {
    let node_id = node_id.ok_or("this node's mesh id is not known yet")?;
    let now = crate::evidence_answer::now_utc();
    commitment::with_responder(capsules, &now, Some(node_id), |responder, policy| {
        commitment::build(responder, node_id, policy)
    })
}

/// The frame the responder writes.
fn reply(capsules: &CapsuleState, node_id: Option<&str>) -> Value {
    match own(capsules, node_id) {
        Ok(signed) => signed.to_wire(),
        Err(error) => json!({ "error": error }),
    }
}

// ---------------------------------------------------------------------
// Responder role
// ---------------------------------------------------------------------

pub async fn handle_open_stream(
    request: OpenStreamRequest,
    capsules: Arc<CapsuleState>,
    self_peer: crate::self_peer::SelfPeer,
) -> PluginResult<Option<OpenStreamResponse>> {
    let listener = bind_side_stream(crate::PLUGIN_ID, &request.stream_id)
        .await
        .map_err(|error| PluginError::internal(error.to_string()))?;
    let response = listener.open_stream_response(&request);
    let node_id = self_peer.current();
    tokio::spawn(async move {
        if let Err(error) = bridge_inbound(listener, capsules, node_id).await {
            tracing::warn!(%error, "mesh commitment responder bridge failed");
        }
    });
    Ok(Some(response))
}

async fn bridge_inbound(
    listener: LocalListener,
    capsules: Arc<CapsuleState>,
    node_id: Option<String>,
) -> anyhow::Result<()> {
    let local = tokio::time::timeout(responder_timeout(), listener.accept()).await??;
    let (mut read_half, mut write_half) = local.into_split();
    // The request says nothing; it is read, bounded, so the stream is used
    // as every other carrier uses it.
    tokio::time::timeout(
        responder_timeout(),
        read_to_end_bounded(&mut read_half, "inbound commitment request"),
    )
    .await??;
    let frame = tokio::task::spawn_blocking(move || reply(&capsules, node_id.as_deref())).await?;
    let bytes = serde_json::to_vec(&frame)?;
    tokio::time::timeout(responder_timeout(), async {
        write_half.write_all(&bytes).await?;
        write_half.shutdown().await
    })
    .await??;
    Ok(())
}

// ---------------------------------------------------------------------
// The operations
// ---------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OwnCommitmentArgs {}

/// `commitment`: this node's own commitment and policy file.
pub async fn handle_own(
    capsules: Arc<CapsuleState>,
    node_id: Option<String>,
) -> PluginResult<Value> {
    tokio::task::spawn_blocking(move || own(&capsules, node_id.as_deref()))
        .await
        .map_err(|e| PluginError::internal(format!("commitment task did not complete: {e}")))?
        .map(|signed| signed.to_wire())
        .map_err(PluginError::internal)
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MeshCommitmentFetchArgs {
    /// Hex-encoded mesh peer id whose commitment to fetch.
    pub peer_id: String,
}

/// `mesh_commitment_fetch`: the peer's pair, beside what checking it found.
pub async fn handle_fetch(
    args: MeshCommitmentFetchArgs,
    context: &mut PluginContext<'_>,
) -> PluginResult<Value> {
    let peer_id = args.peer_id.trim().to_ascii_lowercase();
    if peer_id.is_empty() {
        return Err(PluginError::invalid_params("peer_id must not be empty"));
    }
    let open_request = OpenMeshStreamRequest {
        stream_id: next_stream_id("commitment"),
        target_peer_id: peer_id.clone(),
        plugin_id: String::new(), // the host fills this in.
        channel: COMMITMENT_CHANNEL.to_string(),
        purpose: mesh_llm_plugin::proto::StreamPurpose::Generic as i32,
        mode: mesh_llm_plugin::proto::StreamMode::RawBytes as i32,
        bidirectional: true,
        content_type: Some("application/json".to_string()),
        correlation_id: Some(next_stream_id("commitment-correlation")),
        metadata_json: Some(COMMITMENT_CHANNEL.to_string()),
        expected_bytes: None,
        idle_timeout_ms: Some(requester_idle_timeout_ms()),
    };
    let stream: LocalStream = context
        .connect_mesh_stream(open_request)
        .await
        .map_err(|error| PluginError::internal(format!("could not reach peer: {error}")))?;
    let (read_half, mut write_half) = stream.into_split();
    let bytes = tokio::time::timeout(Duration::from_millis(requester_idle_timeout_ms()), async {
        write_half.write_all(b"{}").await?;
        write_half.shutdown().await?;
        read_to_end_bounded(read_half, "peer commitment response").await
    })
    .await
    .map_err(|_| PluginError::internal("peer does not serve a commitment"))?
    .map_err(|e| PluginError::internal(format!("peer does not serve a commitment: {e}")))?;
    let frame: Value = serde_json::from_slice(&bytes).map_err(|e| {
        PluginError::internal(format!("peer returned a malformed commitment frame: {e}"))
    })?;
    let registry = crate::peer_keys::registry();
    let announced = crate::peer_keys::announced_key_in(registry.as_deref(), &peer_id);
    Ok(checked(&frame, &peer_id, announced.as_deref()))
}

/// The frame as fetched, with `problems` (empty when every check passed) and
/// whether its key is the one the host announced for the peer.
fn checked(frame: &Value, peer_id: &str, announced: Option<&str>) -> Value {
    if let Some(error) = frame.get("error").and_then(Value::as_str) {
        return json!({ "error": error });
    }
    let signed = match Signed::from_wire(frame) {
        Ok(signed) => signed,
        Err(e) => return json!({ "problems": [format!("malformed frame: {e}")] }),
    };
    let mut problems = commitment::verify(&signed);
    if signed.commitment["node_id"] != peer_id {
        problems.push("the commitment does not name the peer asked".into());
    }
    let key = match announced {
        None => "not_announced",
        Some(k) if signed.commitment["key_id"] == k => "matches",
        Some(_) => {
            problems
                .push("the commitment is not under the key the host announced for the peer".into());
            "differs"
        }
    };
    let mut out = signed.to_wire();
    out["announced_key"] = json!(key);
    out["problems"] = json!(problems);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tagged_open_is_this_modules_and_no_other_is() {
        let mut open = OpenStreamRequest::default();
        assert!(!is_commitment_request(&open));
        open.metadata_json = Some(COMMITMENT_CHANNEL.into());
        assert!(is_commitment_request(&open));
        open.metadata_json = Some("ledger-fetch/1".into());
        assert!(!is_commitment_request(&open));
    }

    #[test]
    fn an_error_frame_is_reported_as_the_peer_gave_it() {
        let out = checked(&json!({"error": "no checkpoint yet"}), "aa", None);
        assert_eq!(out, json!({"error": "no checkpoint yet"}));
    }
}
