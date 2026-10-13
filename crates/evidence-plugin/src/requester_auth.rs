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
//! key signs. Every other member is covered, and a signed request carries a
//! `nonce` and a `deadline`: a responder refuses it once that deadline has
//! passed, and refuses it a second time before then while it runs (the
//! replay cache is in memory). It does not name the responder it is for, so
//! one node it was sent to can still forward it to another.
//!
//! **The asker** ([`sign_outgoing`]) signs only once its host took its key
//! ([`set_announced`]): a key no host announced is bound to no node, and a
//! signature under it would only get the request refused.
//!
//! **The responder** ([`check`]) runs before anything is looked up:
//! window, signature, binding, the stated id against the bound one, replay.
//! It yields the verified principal, the node the host's announced key is
//! bound to ([`bound_node`]), or why there is none. `evidence_answer` decides what that means
//! for the subject asked.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock, PoisonError};

use capsule_emit_evidence_request::jcs;
use capsule_emit_evidence_request::time::UtcTime;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};

/// The request member the signature travels in.
pub const MEMBER: &str = "requester_auth";

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

/// The most nonces held for one key at once. Each is held at most
/// [`MAX_WINDOW_SECS`]; past it, that key's next request is refused rather
/// than a nonce forgotten. Only a key that verified and is bound reaches the
/// cache, and one key filling its share refuses no other key.
pub const MAX_NONCES_PER_KEY: usize = 4096;

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

/// Sign `request` as `key`: add a fresh `nonce` and a `deadline`
/// [`ASKER_DEADLINE_SECS`] after `now` unless it carries them, then
/// [`MEMBER`] over the rest. A request that already carries [`MEMBER`], is
/// not a map, or has no JSON form to sign is left exactly as it is.
pub fn sign(request: &mut Value, key: &SigningKey, now: chrono::DateTime<chrono::Utc>) {
    let Some(given) = request.as_object() else {
        return;
    };
    if given.contains_key(MEMBER) {
        return;
    }
    let mut map = given.clone();
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

/// Sign an outgoing request ([`sign`]) when this node's key is announced;
/// otherwise leave it unsigned, as before.
pub fn sign_outgoing(request: &mut Value) {
    if let Some(key) = signer().get() {
        sign(request, key, chrono::Utc::now());
    }
}

/// What a request's [`MEMBER`] says, by form alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Form {
    /// No [`MEMBER`].
    Unsigned,
    /// A well-formed [`MEMBER`], with the `nonce` and `deadline` a signed
    /// request carries.
    Signed { key_id: String, sig: String },
    /// [`MEMBER`] is there but is not `{key_id, sig}` in lowercase hex of the
    /// right lengths, or the request lacks a `nonce` of 1 to
    /// [`MAX_NONCE_BYTES`] bytes or a `deadline`: `request_malformed`.
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
    if !nonce_ok || !map.get("deadline").is_some_and(Value::is_string) {
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

/// The node a request signed under `key_id` comes from, given the id it
/// states: that id when it is one of the key's [`claimants`] (the signature
/// proves the asker holds the key, and that node announced it); with no id
/// stated, the key's one claimant. `Err` with the key's one claimant when
/// the stated id is another node; `Err(None)` when the key is bound to no
/// node, or to several and the request names none of them.
pub fn bound_node(claimants: &[String], stated: Option<&str>) -> Result<String, Option<String>> {
    if let Some(id) = stated {
        if claimants.iter().any(|node| node == id) {
            return Ok(id.to_string());
        }
    }
    match (claimants, stated) {
        ([one], None) => Ok(one.clone()),
        ([one], Some(_)) => Err(Some(one.clone())),
        _ => Err(None),
    }
}

/// The nonces seen, per key, each held until its deadline.
#[derive(Default)]
pub struct ReplayCache {
    seen: Mutex<HashMap<String, HashMap<String, i64>>>,
}

impl ReplayCache {
    /// Record `nonce` for `key_id` until `deadline` (Unix seconds). `false`
    /// when it is already held, or when that key already holds
    /// [`MAX_NONCES_PER_KEY`] nonces whose deadline has not passed.
    pub fn first_use(&self, key_id: &str, nonce: &str, deadline: i64, now: i64) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
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

/// Why a signed request names no principal. Each is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The deadline is more than [`MAX_WINDOW_SECS`] ahead.
    OutsideWindow,
    /// The signature does not verify over the signing input.
    BadSignature,
    /// The key is bound to no node, or to several and the request names
    /// none of them.
    Unbound { key_id: String },
    /// The request states a `requester_id` other than the bound node.
    ClaimMismatch { key_id: String, node_id: String },
    /// This (key_id, nonce) was already answered within its deadline.
    Replayed { key_id: String, node_id: String },
}

impl Failure {
    /// The key the signature verified under, if it did.
    pub fn verified_key(&self) -> Option<&str> {
        match self {
            Failure::OutsideWindow | Failure::BadSignature => None,
            Failure::Unbound { key_id }
            | Failure::ClaimMismatch { key_id, .. }
            | Failure::Replayed { key_id, .. } => Some(key_id),
        }
    }

    /// The node that key is bound to, if the binding verified.
    pub fn verified_node(&self) -> Option<&str> {
        match self {
            Failure::ClaimMismatch { node_id, .. } | Failure::Replayed { node_id, .. } => {
                Some(node_id)
            }
            _ => None,
        }
    }
}

/// Check a [`Form::Signed`] request: its window, its signature, its key's
/// binding, its stated id against the bound one, and its nonce, in that
/// order, before anything else is read. `deadline` is the parsed request's.
pub fn check(
    map: &Map<String, Value>,
    key_id: &str,
    sig: &str,
    deadline: UtcTime,
    now: UtcTime,
    keys: Keys<'_>,
    replay: &ReplayCache,
) -> Result<Principal, Failure> {
    if deadline.seconds > now.seconds.saturating_add(MAX_WINDOW_SECS) {
        return Err(Failure::OutsideWindow);
    }
    if !verifies(map, key_id, sig) {
        return Err(Failure::BadSignature);
    }
    let stated = map
        .get("requester_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let claimants = claimants(keys.announced, keys.configured, key_id);
    let node_id = match bound_node(&claimants, stated) {
        Ok(node_id) => node_id,
        Err(Some(node_id)) => {
            return Err(Failure::ClaimMismatch {
                key_id: key_id.to_string(),
                node_id,
            })
        }
        Err(None) => {
            return Err(Failure::Unbound {
                key_id: key_id.to_string(),
            })
        }
    };
    let nonce = map.get("nonce").and_then(Value::as_str).unwrap_or_default();
    if !replay.first_use(key_id, nonce, deadline.seconds, now.seconds) {
        return Err(Failure::Replayed {
            key_id: key_id.to_string(),
            node_id,
        });
    }
    Ok(Principal {
        key_id: key_id.to_string(),
        node_id,
    })
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
        sign(&mut request, &key(seed), at("2026-10-13T00:00:00Z"));
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
        let mut fresh = json!({"subject": {"checkpoints": null}});
        sign(&mut fresh, &key(1), at("2026-10-13T00:00:00Z"));
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
        let both = ["node-a".to_string(), "node-m".to_string()];
        assert_eq!(bound_node(&both, Some("node-a")), Ok("node-a".into()));
        assert_eq!(bound_node(&both, None), Err(None));
        assert_eq!(bound_node(&both, Some("node-z")), Err(None));
        let one = ["node-a".to_string()];
        assert_eq!(bound_node(&one, None), Ok("node-a".into()));
        assert_eq!(bound_node(&one, Some("node-a")), Ok("node-a".into()));
        assert_eq!(bound_node(&one, Some("node-z")), Err(Some("node-a".into())));
        assert_eq!(bound_node(&[], Some("node-a")), Err(None));
    }

    #[test]
    fn a_nonce_is_used_once_until_its_deadline() {
        let cache = ReplayCache::default();
        assert!(cache.first_use("k", "n", 100, 0));
        assert!(!cache.first_use("k", "n", 100, 50));
        assert!(cache.first_use("k2", "n", 100, 50), "per key");
        assert!(cache.first_use("k", "n", 300, 101), "after its deadline");
    }

    #[test]
    fn a_key_that_fills_its_share_refuses_only_itself_until_its_nonces_expire() {
        let cache = ReplayCache::default();
        for i in 0..MAX_NONCES_PER_KEY {
            assert!(cache.first_use("noisy", &i.to_string(), 100, 0));
        }
        assert!(!cache.first_use("noisy", "one-more", 100, 1));
        assert!(
            cache.first_use("quiet", "n", 100, 1),
            "another key is unaffected"
        );
        assert!(
            cache.first_use("noisy", "one-more", 200, 101),
            "after they expire"
        );
    }

    #[test]
    fn a_request_that_cannot_be_signed_is_sent_as_given() {
        let mut request =
            json!({"subject": {"checkpoints": null}, "coverage": {"min_freshness": 1.5}});
        let given = request.clone();
        sign(&mut request, &key(1), at("2026-10-13T00:00:00Z"));
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
        sign_outgoing(&mut request);
        assert_eq!(form(request.as_object().unwrap()), Form::Unsigned);
        set_announced(key(3));
        sign_outgoing(&mut request);
        let Form::Signed { key_id, sig } = form(request.as_object().unwrap()) else {
            panic!("not signed: {request}");
        };
        assert_eq!(key_id, hex::encode(key(3).verifying_key().to_bytes()));
        assert!(verifies(request.as_object().unwrap(), &key_id, &sig));
    }
}
