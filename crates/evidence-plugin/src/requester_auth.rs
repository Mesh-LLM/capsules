//! Who asked: the requester's signature on an evidence request, both sides.
//!
//! A request's `requester_id` is the asker's own word. A node that answers
//! some askers and not others (a record to the node it names, Standard
//! History to a counterparty) needs to know who asked, so the asker signs.
//!
//! **The signature** is a profile member of this deployment inside the
//! request map, never an Evidence Request field:
//!
//! ```text
//! requester_auth = {"key_id": <64 lowercase hex>, "sig": <128 lowercase hex>}
//! sig = Ed25519(UTF8("evidence-request/1/requester-auth") || 0x00
//!               || UTF8(JCS(the request map without requester_auth)))
//! ```
//!
//! `key_id` is the key this node's records are signed with, the one it
//! announces through its host (`peer_keys::own`). The domain tag keeps a
//! request signature from ever verifying as a record or anything else that
//! key signs. Every other member is covered. A signed request carries an
//! `audience`, the node it is addressed to, so a node it was sent to cannot
//! forward it to another; and a `nonce` and a `deadline`, so a responder
//! refuses it once that deadline has passed, and a second time before then
//! while it runs (the replay cache is in memory). The spec ruling is
//! `svc-ev-m1-request-signing-ruling` with its u289 addendum.
//!
//! **The asker** ([`sign_outgoing`]) signs only once its host took its key
//! ([`set_announced`]): a key no host announced is bound to no node.
//!
//! **The responder** ([`check`]) runs before anything is looked up: window,
//! signature, audience, replay, then the key's binding and the stated id
//! against it. It yields the verified principal, the node the host's
//! announced key is bound to ([`bound_node`]), or why there is none.
//! `evidence_answer` decides what that means for the subject asked: a valid
//! signature under a key no host binds ([`Failure::Unbound`]) reads as an
//! unsigned request where the answer needs no identity; every other failure
//! is refused.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock, PoisonError};

use capsule_emit_evidence_request::jcs;
use capsule_emit_evidence_request::time::UtcTime;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};

/// The request member the signature travels in.
pub const MEMBER: &str = "requester_auth";

/// The request member naming the node a signed request is addressed to:
/// its mesh node id, as the asker addressed the stream. Required whenever
/// [`MEMBER`] is present.
pub const AUDIENCE: &str = "audience";

/// The domain tag: the carrier's own identifier, then the profile member.
pub const DOMAIN_TAG: &[u8] = b"evidence-request/1/requester-auth";

/// How far ahead a signed request's deadline may be, in seconds. A later
/// deadline is refused: the replay cache holds each nonce until its deadline.
pub const MAX_WINDOW_SECS: i64 = 300;

/// How far ahead this node sets the deadline of a request it signs, in
/// seconds: inside [`MAX_WINDOW_SECS`], with room for the two clocks to
/// disagree.
pub const ASKER_DEADLINE_SECS: i64 = 120;

/// The longest nonce a signed request may carry, in bytes.
pub const MAX_NONCE_BYTES: usize = 256;

/// The most nonces held for one bound key at once. Each is held at most
/// [`MAX_WINDOW_SECS`]; past it, that key's next request is refused rather
/// than a nonce forgotten, and one key filling its share refuses no other.
pub const MAX_NONCES_PER_KEY: usize = 4096;

/// The most nonces held, all together, for keys no host binds. Anyone can
/// make such a key, so they share one pool: when it is full their signed
/// requests are refused (sent unsigned they are answered as before), and no
/// bound key is affected.
pub const MAX_UNBOUND_NONCES: usize = 16_384;

/// The signing input for `map`: the domain tag, a zero byte, and the map
/// without [`MEMBER`] in the protocol crate's canonical JSON (RFC 8785 for
/// strings, maps and integers; it encodes no non-integer number). `None`
/// when the map has none.
pub fn signing_input(map: &Map<String, Value>) -> Option<Vec<u8>> {
    let mut covered = map.clone();
    covered.remove(MEMBER);
    let body = jcs::to_string(&Value::Object(covered)).ok()?;
    let mut input = Vec::with_capacity(DOMAIN_TAG.len() + 1 + body.len());
    input.extend_from_slice(DOMAIN_TAG);
    input.push(0);
    input.extend_from_slice(body.as_bytes());
    Some(input)
}

/// Sign `request` as `key`, addressed to the node `audience`: set
/// [`AUDIENCE`], add a fresh `nonce` and a `deadline` [`ASKER_DEADLINE_SECS`]
/// after `now` unless it carries them, then [`MEMBER`] over the rest. A
/// request that already carries [`MEMBER`], is not a map, or has no JSON
/// form to sign is left exactly as it is.
pub fn sign(
    request: &mut Value,
    key: &SigningKey,
    now: chrono::DateTime<chrono::Utc>,
    audience: &str,
) {
    let Some(given) = request.as_object() else {
        return;
    };
    if given.contains_key(MEMBER) {
        return;
    }
    let mut map = given.clone();
    map.insert(AUDIENCE.into(), json!(audience));
    map.entry("nonce")
        .or_insert_with(|| json!(crate::producer::capsule::fresh_store_nonce()));
    map.entry("deadline").or_insert_with(|| {
        let deadline = now + chrono::Duration::seconds(ASKER_DEADLINE_SECS);
        json!(deadline.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    });
    let Some(input) = signing_input(&map) else {
        return;
    };
    let sig = key.sign(&input);
    map.insert(
        MEMBER.into(),
        json!({
            "key_id": hex::encode(key.verifying_key().to_bytes()),
            "sig": hex::encode(sig.to_bytes()),
        }),
    );
    *request = Value::Object(map);
}

fn signer() -> &'static OnceLock<SigningKey> {
    static SIGNER: OnceLock<SigningKey> = OnceLock::new();
    &SIGNER
}

/// This node's host took its key (`peer_keys::own::Announced::Sent`): from
/// now on, every evidence request it sends is signed with `key`.
pub fn set_announced(key: SigningKey) {
    let _ = signer().set(key);
}

/// Sign an outgoing request to the node `audience` ([`sign`]) when this
/// node's key is announced; otherwise leave it unsigned, as before.
pub fn sign_outgoing(request: &mut Value, audience: &str) {
    if let Some(key) = signer().get() {
        sign(request, key, chrono::Utc::now(), audience);
    }
}

/// What a request's [`MEMBER`] says, by form alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Form {
    /// No [`MEMBER`].
    Unsigned,
    /// A well-formed [`MEMBER`], with the [`AUDIENCE`], `nonce` and
    /// `deadline` a signed request carries.
    Signed { key_id: String, sig: String },
    /// [`MEMBER`] is there but is not `{key_id, sig}` in lowercase hex of the
    /// right lengths, or the request lacks a text [`AUDIENCE`], a `nonce` of
    /// 1 to [`MAX_NONCE_BYTES`] bytes or a `deadline`: `request_malformed`.
    Malformed,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The [`Form`] of the parsed request map `map`.
pub fn form(map: &Map<String, Value>) -> Form {
    let Some(auth) = map.get(MEMBER) else {
        return Form::Unsigned;
    };
    let Some(auth) = auth.as_object() else {
        return Form::Malformed;
    };
    let text = |k: &str| auth.get(k).and_then(Value::as_str);
    let (Some(key_id), Some(sig)) = (text("key_id"), text("sig")) else {
        return Form::Malformed;
    };
    if auth.len() != 2 || !is_lower_hex(key_id, 64) || !is_lower_hex(sig, 128) {
        return Form::Malformed;
    }
    let nonce_ok = map
        .get("nonce")
        .and_then(Value::as_str)
        .is_some_and(|n| (1..=MAX_NONCE_BYTES).contains(&n.len()));
    if !nonce_ok
        || !map.get("deadline").is_some_and(Value::is_string)
        || !map.get(AUDIENCE).is_some_and(Value::is_string)
    {
        return Form::Malformed;
    }
    Form::Signed {
        key_id: key_id.to_string(),
        sig: sig.to_string(),
    }
}

/// The nodes `key_id` is bound to: each peer whose key for this plugin the
/// host announced as `key_id`, after checking that peer's binding against
/// its node key (`peer_keys::announced`). An operator entry
/// (`CAPSULES_PEER_KEYS`) binds nothing on its own, and one that gives that
/// peer another key vetoes it, as for pushed records (`peer_keys::merged`).
///
/// A host binds a key to a node by the node's signature alone, without
/// proof that the node holds the key, so a node can announce another's
/// public key. A request's own signature is that proof, so more than one
/// node here does not make the key unusable: the request's stated id picks
/// among them ([`bound_node`]).
pub fn claimants(
    announced: &BTreeMap<String, String>,
    configured: Option<&str>,
    key_id: &str,
) -> Vec<String> {
    let merged = crate::peer_keys::merged(configured, announced)
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok());
    let Some(Value::Object(merged)) = merged else {
        return Vec::new();
    };
    announced
        .iter()
        .filter(|(node, key)| {
            key.as_str() == key_id && merged.get(*node).and_then(Value::as_str) == Some(key_id)
        })
        .map(|(node, _)| node.clone())
        .collect()
}

/// What a key's [`claimants`] and a request's stated id make of who asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Binding {
    /// The node the request comes from: the stated id when it is one of the
    /// claimants (the signature proves the asker holds the key, and that
    /// node announced it), or the key's one claimant when none is stated.
    Node(String),
    /// The key is bound, but the stated id is none of its nodes: a false
    /// claim. Carries the key's node when it has exactly one.
    Mismatch(Option<String>),
    /// No host binds the key, or several nodes announced it and the request
    /// states no id to pick between them.
    Unbound,
}

/// The [`Binding`] of a request signed under a key with these
/// `claimants`, stating `stated`.
pub fn bound_node(claimants: &[String], stated: Option<&str>) -> Binding {
    match (claimants, stated) {
        ([], _) => Binding::Unbound,
        (_, Some(id)) if claimants.iter().any(|node| node == id) => Binding::Node(id.to_string()),
        ([one], Some(_)) => Binding::Mismatch(Some(one.clone())),
        (_, Some(_)) => Binding::Mismatch(None),
        ([one], None) => Binding::Node(one.clone()),
        (_, None) => Binding::Unbound,
    }
}

/// The nonces seen, each held until its deadline: per key for bound keys,
/// and in one shared pool for keys no host binds.
#[derive(Default)]
pub struct ReplayCache {
    bound: Mutex<HashMap<String, HashMap<String, i64>>>,
    unbound: Mutex<HashMap<(String, String), i64>>,
}

impl ReplayCache {
    /// Record `nonce` for `key_id` until `deadline` (Unix seconds). `false`
    /// when it is already held, or when there is no room for it: a bound key
    /// already holding [`MAX_NONCES_PER_KEY`] live nonces, or unbound keys
    /// together holding [`MAX_UNBOUND_NONCES`].
    pub fn first_use(
        &self,
        key_id: &str,
        nonce: &str,
        deadline: i64,
        now: i64,
        bound: bool,
    ) -> bool {
        if !bound {
            let mut seen = self.unbound.lock().unwrap_or_else(PoisonError::into_inner);
            let pair = (key_id.to_string(), nonce.to_string());
            if seen.get(&pair).is_some_and(|&until| until >= now) {
                return false;
            }
            if seen.len() >= MAX_UNBOUND_NONCES {
                seen.retain(|_, &mut until| until >= now);
            }
            if seen.len() >= MAX_UNBOUND_NONCES {
                return false;
            }
            seen.insert(pair, deadline);
            return true;
        }
        let mut seen = self.bound.lock().unwrap_or_else(PoisonError::into_inner);
        seen.retain(|_, nonces| {
            nonces.retain(|_, &mut until| until >= now);
            !nonces.is_empty()
        });
        let nonces = seen.entry(key_id.to_string()).or_default();
        if nonces.contains_key(nonce) || nonces.len() >= MAX_NONCES_PER_KEY {
            return false;
        }
        nonces.insert(nonce.to_string(), deadline);
        true
    }
}

/// The one cache the mesh responder uses.
pub fn replay_cache() -> &'static ReplayCache {
    static CACHE: OnceLock<ReplayCache> = OnceLock::new();
    CACHE.get_or_init(ReplayCache::default)
}

/// The keys a responder checks a signature's binding against.
#[derive(Clone, Copy)]
pub struct Keys<'a> {
    /// `peer_keys::announced::snapshot()`.
    pub announced: &'a BTreeMap<String, String>,
    /// `CAPSULES_PEER_KEYS`, raw.
    pub configured: Option<&'a str>,
}

/// The requester a signed request proved to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// The key the signature verified under.
    pub key_id: String,
    /// The node that key is bound to ([`bound_node`]).
    pub node_id: String,
}

/// Why a signed request names no principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The deadline is more than [`MAX_WINDOW_SECS`] ahead.
    OutsideWindow,
    /// The signature does not verify over the signing input.
    BadSignature,
    /// The request is addressed to another node than this one (or this node
    /// does not know its own id yet).
    AudienceMismatch { key_id: String },
    /// This (key_id, nonce) was already seen within its deadline, or there
    /// is no room to hold it.
    Replayed { key_id: String },
    /// The key is bound to no node, or to several and the request states
    /// no id. The only failure that may read as unsigned
    /// ([`Failure::reads_as_unsigned`]).
    Unbound { key_id: String },
    /// The key is bound, and the request states a `requester_id` that is
    /// none of its nodes (`node_id`: its node, when it has one).
    ClaimMismatch {
        key_id: String,
        node_id: Option<String>,
    },
}

impl Failure {
    /// The key the signature verified under, if it did.
    pub fn verified_key(&self) -> Option<&str> {
        match self {
            Failure::OutsideWindow | Failure::BadSignature => None,
            Failure::AudienceMismatch { key_id }
            | Failure::Replayed { key_id }
            | Failure::Unbound { key_id }
            | Failure::ClaimMismatch { key_id, .. } => Some(key_id),
        }
    }

    /// The node that key is bound to, if the binding verified.
    pub fn verified_node(&self) -> Option<&str> {
        match self {
            Failure::ClaimMismatch { node_id, .. } => node_id.as_deref(),
            _ => None,
        }
    }

    /// Whether a request that failed this way is answered as an unsigned
    /// one would be, where the answer needs no identity: only a valid
    /// signature under a key the host cannot bind (ruling addendum §2).
    /// Every other failure is refused.
    pub fn reads_as_unsigned(&self) -> bool {
        matches!(self, Failure::Unbound { .. })
            || cfg!(feature = "mutant-requester-auth-downgrades-all")
    }
}

/// Check a [`Form::Signed`] request, before anything else is read: its
/// window, its signature, its [`AUDIENCE`] against `own_node` (this node's
/// id), its nonce, then its key's binding and its stated id against the
/// bound one. `deadline` is the parsed request's.
#[allow(clippy::too_many_arguments)]
pub fn check(
    map: &Map<String, Value>,
    key_id: &str,
    sig: &str,
    deadline: UtcTime,
    now: UtcTime,
    keys: Keys<'_>,
    replay: &ReplayCache,
    own_node: Option<&str>,
) -> Result<Principal, Failure> {
    if deadline.seconds > now.seconds.saturating_add(MAX_WINDOW_SECS) {
        return Err(Failure::OutsideWindow);
    }
    if !verifies(map, key_id, sig) {
        return Err(Failure::BadSignature);
    }
    let audience = map.get(AUDIENCE).and_then(Value::as_str);
    if !audience_matches(audience, own_node) {
        return Err(Failure::AudienceMismatch {
            key_id: key_id.to_string(),
        });
    }
    let stated = map
        .get("requester_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let claimants = claimants(keys.announced, keys.configured, key_id);
    let nonce = map.get("nonce").and_then(Value::as_str).unwrap_or_default();
    let bound = !claimants.is_empty();
    if !replay.first_use(key_id, nonce, deadline.seconds, now.seconds, bound) {
        return Err(Failure::Replayed {
            key_id: key_id.to_string(),
        });
    }
    let node_id = match bound_node(&claimants, stated) {
        Binding::Node(node_id) => node_id,
        Binding::Mismatch(node_id) => {
            return Err(Failure::ClaimMismatch {
                key_id: key_id.to_string(),
                node_id,
            })
        }
        Binding::Unbound => {
            return Err(Failure::Unbound {
                key_id: key_id.to_string(),
            })
        }
    };
    Ok(Principal {
        key_id: key_id.to_string(),
        node_id,
    })
}

/// Whether a signed request's [`AUDIENCE`] is this node, compared as exact
/// strings. A node that does not know its own id yet matches nothing.
fn audience_matches(audience: Option<&str>, own_node: Option<&str>) -> bool {
    if cfg!(feature = "mutant-requester-auth-skips-audience") {
        return true;
    }
    matches!((audience, own_node), (Some(a), Some(own)) if a == own)
}

/// Whether `sig` verifies over [`signing_input`] of `map` under `key_id`,
/// except in the deliberately broken build CI uses to show the tests catch
/// a responder that skips it.
fn verifies(map: &Map<String, Value>, key_id: &str, sig: &str) -> bool {
    if cfg!(feature = "mutant-requester-auth-skips-verify") {
        return true;
    }
    let key = hex::decode(key_id)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok());
    let sig = hex::decode(sig)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .map(|b| Signature::from_bytes(&b));
    match (key, sig, signing_input(map)) {
        (Some(key), Some(sig), Some(input)) => key.verify_strict(&input, &sig).is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().into()
    }

    fn signed(seed: u8) -> Map<String, Value> {
        let mut request = json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": 60}, "nonce": "n-1"});
        sign(
            &mut request,
            &key(seed),
            at("2026-10-13T00:00:00Z"),
            "node-r",
        );
        request.as_object().unwrap().clone()
    }

    #[test]
    fn a_signed_request_carries_the_member_a_nonce_and_a_deadline_inside_the_window() {
        let map = signed(1);
        let Form::Signed { key_id, .. } = form(&map) else {
            panic!("not signed: {map:?}");
        };
        assert_eq!(key_id, hex::encode(key(1).verifying_key().to_bytes()));
        assert_eq!(map["nonce"], json!("n-1"), "a caller's nonce is kept");
        assert_eq!(map["deadline"], json!("2026-10-13T00:02:00Z"));
        assert_eq!(map[AUDIENCE], json!("node-r"));
        let mut fresh = json!({"subject": {"checkpoints": null}});
        sign(&mut fresh, &key(1), at("2026-10-13T00:00:00Z"), "node-r");
        assert!(is_lower_hex(fresh["nonce"].as_str().unwrap(), 64));
    }

    #[test]
    fn the_signature_covers_the_domain_tag() {
        let map = signed(1);
        let Form::Signed { key_id, sig } = form(&map) else {
            panic!()
        };
        assert!(verifies(&map, &key_id, &sig));
        // The same map signed without the tag does not verify.
        let mut covered = map.clone();
        covered.remove(MEMBER);
        let body = jcs::to_string(&Value::Object(covered)).unwrap();
        let untagged = hex::encode(key(1).sign(body.as_bytes()).to_bytes());
        assert!(!verifies(&map, &key_id, &untagged));
    }

    #[test]
    fn a_member_that_is_not_two_lowercase_hex_strings_is_malformed() {
        let base = signed(1);
        let with = |auth: Value| {
            let mut m = base.clone();
            m.insert(MEMBER.into(), auth);
            form(&m)
        };
        let key_id = base[MEMBER]["key_id"].as_str().unwrap();
        let sig = base[MEMBER]["sig"].as_str().unwrap();
        assert_eq!(
            with(json!({"key_id": &key_id[1..], "sig": sig})),
            Form::Malformed
        );
        assert_eq!(
            with(json!({"key_id": key_id.to_uppercase(), "sig": sig})),
            Form::Malformed
        );
        assert_eq!(
            with(json!({"key_id": key_id, "sig": &sig[2..]})),
            Form::Malformed
        );
        assert_eq!(
            with(json!({"key_id": key_id, "sig": sig, "x": 1})),
            Form::Malformed
        );
        assert_eq!(with(json!("signed")), Form::Malformed);
        let mut no_nonce = base.clone();
        no_nonce.remove("nonce");
        assert_eq!(form(&no_nonce), Form::Malformed);
        let mut long_nonce = base.clone();
        long_nonce.insert("nonce".into(), json!("n".repeat(MAX_NONCE_BYTES + 1)));
        assert_eq!(form(&long_nonce), Form::Malformed);
        let mut no_deadline = base.clone();
        no_deadline.remove("deadline");
        assert_eq!(form(&no_deadline), Form::Malformed);
        let mut no_audience = base.clone();
        no_audience.remove(AUDIENCE);
        assert_eq!(form(&no_audience), Form::Malformed);
        let mut audience_not_text = base.clone();
        audience_not_text.insert(AUDIENCE.into(), json!(["node-r"]));
        assert_eq!(form(&audience_not_text), Form::Malformed);
    }

    #[test]
    fn a_key_binds_only_through_the_host_and_an_operator_entry_can_only_veto() {
        let k = "ab".repeat(32);
        let announced = BTreeMap::from([("node-a".to_string(), k.clone())]);
        assert_eq!(claimants(&announced, None, &k), ["node-a"]);
        let configured_only = format!(r#"{{"node-a": "{k}"}}"#);
        assert!(claimants(&BTreeMap::new(), Some(&configured_only), &k).is_empty());
        let disagrees = format!(r#"{{"node-a": "{}"}}"#, "cd".repeat(32));
        assert!(claimants(&announced, Some(&disagrees), &k).is_empty());
        assert!(claimants(&announced, Some("not json"), &k).is_empty());
    }

    /// A node announcing another's public key does not unbind it: the
    /// request's signature proves who holds the key, and its stated id picks
    /// among the nodes that announced it. Naming none of them is unbound;
    /// naming another node than a key's one claimant is a false claim.
    #[test]
    fn the_stated_id_picks_among_the_nodes_that_announced_the_key() {
        let node = |id: &str| Binding::Node(id.to_string());
        let both = ["node-a".to_string(), "node-m".to_string()];
        assert_eq!(bound_node(&both, Some("node-a")), node("node-a"));
        assert_eq!(bound_node(&both, None), Binding::Unbound);
        assert_eq!(bound_node(&both, Some("node-z")), Binding::Mismatch(None));
        let one = ["node-a".to_string()];
        assert_eq!(bound_node(&one, None), node("node-a"));
        assert_eq!(bound_node(&one, Some("node-a")), node("node-a"));
        assert_eq!(
            bound_node(&one, Some("node-z")),
            Binding::Mismatch(Some("node-a".into()))
        );
        assert_eq!(bound_node(&[], Some("node-a")), Binding::Unbound);
    }

    #[test]
    fn a_nonce_is_used_once_until_its_deadline() {
        let cache = ReplayCache::default();
        assert!(cache.first_use("k", "n", 100, 0, true));
        assert!(!cache.first_use("k", "n", 100, 50, true));
        assert!(cache.first_use("k2", "n", 100, 50, true), "per key");
        assert!(
            cache.first_use("k", "n", 300, 101, true),
            "after its deadline"
        );
        assert!(cache.first_use("u", "n", 100, 0, false));
        assert!(
            !cache.first_use("u", "n", 100, 50, false),
            "an unbound key's nonce too"
        );
    }

    #[test]
    fn a_key_that_fills_its_share_refuses_only_itself_until_its_nonces_expire() {
        let cache = ReplayCache::default();
        for i in 0..MAX_NONCES_PER_KEY {
            assert!(cache.first_use("noisy", &i.to_string(), 100, 0, true));
        }
        assert!(!cache.first_use("noisy", "one-more", 100, 1, true));
        assert!(
            cache.first_use("quiet", "n", 100, 1, true),
            "another key is unaffected"
        );
        assert!(
            cache.first_use("noisy", "one-more", 200, 101, true),
            "after they expire"
        );
    }

    /// Keys no host binds share one pool: filling it refuses only them.
    #[test]
    fn unbound_keys_share_one_pool_and_cannot_crowd_out_a_bound_key() {
        let cache = ReplayCache::default();
        for i in 0..MAX_UNBOUND_NONCES {
            assert!(cache.first_use(&format!("k{i}"), "n", 100, 0, false));
        }
        assert!(!cache.first_use("fresh", "n", 100, 1, false));
        assert!(cache.first_use("bound", "n", 100, 1, true));
        assert!(!cache.first_use("k0", "n", 100, 1, false), "still a replay");
        assert!(
            cache.first_use("fresh", "n", 200, 101, false),
            "after they expire"
        );
    }

    /// The audience is this node's id, exactly; a node that does not know
    /// its id matches nothing.
    #[test]
    fn the_audience_must_be_exactly_this_node() {
        assert!(audience_matches(Some("node-r"), Some("node-r")));
        assert!(!audience_matches(Some("node-x"), Some("node-r")));
        assert!(!audience_matches(Some("node-r "), Some("node-r")));
        assert!(!audience_matches(Some("node-r"), None));
        assert!(!audience_matches(None, Some("node-r")));
    }

    #[test]
    fn a_request_that_cannot_be_signed_is_sent_as_given() {
        let mut request =
            json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": 1.5}});
        let given = request.clone();
        sign(&mut request, &key(1), at("2026-10-13T00:00:00Z"), "node-r");
        assert_eq!(
            request, given,
            "no nonce or deadline added to an unsigned request"
        );
    }

    /// The asker signs only once its key is announced, and then signs every
    /// request it sends.
    #[test]
    fn an_asker_signs_only_once_its_key_is_announced() {
        let mut request = json!({"subject": {"checkpoints": null}});
        sign_outgoing(&mut request, "node-r");
        assert_eq!(form(request.as_object().unwrap()), Form::Unsigned);
        set_announced(key(3));
        sign_outgoing(&mut request, "node-r");
        assert_eq!(
            request[AUDIENCE],
            json!("node-r"),
            "addressed to the node it goes to"
        );
        let Form::Signed { key_id, sig } = form(request.as_object().unwrap()) else {
            panic!("not signed: {request}");
        };
        assert_eq!(key_id, hex::encode(key(3).verifying_key().to_bytes()));
        assert!(verifies(request.as_object().unwrap(), &key_id, &sig));
    }
}
