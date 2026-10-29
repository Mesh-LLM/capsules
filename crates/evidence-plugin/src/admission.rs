//! Admission (loop step 4): before each attempt to a mesh peer, the node
//! decides GO or NO from the operator's allow and deny lists and default
//! (#55), and seals the decision with what the base policy's five rows read
//! about that peer ([`base`], #64). The rows decide nothing: a NO only ever
//! comes from the operator's config (Steven, 10-29).
//!
//! The host asks through its OpenAI exchange lifecycle (mesh-llm#2226): the
//! plugin declares an admission hook on the `backend_selected` phase, and the
//! host calls it on the routing node just before it dispatches to the backend
//! it selected. The host acts on the answer only when the operator's grant for
//! this plugin allows admission; without the grant, or on a host older than
//! the lifecycle, nothing here runs. A NO is the host's deny: today a 403 for
//! the request (`plugin_policy_denied`); skipping to the next candidate waits
//! on mesh-llm#2061.
//!
//! The policy is local state only, read once at start: `CAPSULES_ADMISSION_ALLOW`
//! and `CAPSULES_ADMISSION_DENY` (comma-separated 64-hex mesh node ids) and
//! `CAPSULES_ADMISSION_DEFAULT` (`go`, the default, or `no`) for a peer on
//! neither list. Deny wins over allow.
//! Nothing is fetched while a request waits. A setting that does not read or parse fails closed: the plugin keeps
//! running and every peer gets NO (`unreadable_policy`) until the operator
//! fixes it and restarts, so a typo never admits a peer the operator meant to
//! refuse. Stopping the plugin instead would not, under a `best_effort` grant:
//! a host then routes to every peer past a plugin it has no manifest for
//! (under a `required` grant it refuses every request, peers and all).
//!
//! Each decision about a peer is sealed as an `admission_decision` record
//! before the answer goes back, so no GO is acted on unsealed; when sealing
//! fails the answer is NO with the reason [`SEAL_FAILED`], not a deny. The
//! record never names the peer in clear: a `range` answer returns whole
//! records to its asker, so it would tell others whom this node admitted or
//! refused (the same reason routing-choice records name a peer only by
//! commitment). It names the peer by `sha256(salt || node id)`, and cites the
//! policy it read by a digest over the lists' commitments, never over the
//! clear ids, which are public and few enough to guess. The salt is derived
//! from this node's signing key, so the operator, and only the operator, can
//! say which peer a record names.
//!
//! A record about a peer also carries `rows` (each `pass`, `fail` or
//! `not_read`, never a count) and, in `reads`, the history card the rows
//! read, cited by `sha256(salt || artifact digest)`: a card is stranger-safe,
//! so a clear digest would let anyone who fetches every peer's card say which
//! peer a record names.

use std::collections::BTreeSet;
use std::sync::Arc;

use mesh_llm_plugin::openai_exchange::{
    openai_exchange_hook, OpenAiAdmissionDecision, OpenAiExchangeDecision,
};
use mesh_llm_plugin::proto::OpenAiExchangeHookManifest;
use serde_json::{json, Map, Value};

use crate::capsule_emit::CapsuleState;
use crate::producer::capsule::peer_commitment;

pub mod base;

pub const ALLOW_SETTING: &str = "CAPSULES_ADMISSION_ALLOW";
pub const DENY_SETTING: &str = "CAPSULES_ADMISSION_DENY";
pub const DEFAULT_SETTING: &str = "CAPSULES_ADMISSION_DEFAULT";

/// The lifecycle service the host invokes for each decision.
pub const HANDLER: &str = "admission";
/// The `compute_attestation` block an admission record carries its facts
/// under. PROVISIONAL (not a registered AAC field): a reader identifies the
/// record kind by this block alone.
pub const BLOCK: &str = "admission_decision";
/// The policy this module applies, as a record cites it: the lists and the
/// default (#55), and the rows' thresholds (#64).
pub const POLICY: &str = "base/1";
/// The reason a NO carries when the decision could not be sealed.
pub const SEAL_FAILED: &str = "admission_seal_failed";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Go,
    No,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "GO",
            Self::No => "NO",
        }
    }
}

/// What produced a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    AllowList,
    DenyList,
    Default,
    /// The host named a mesh backend in a shape this plugin cannot read.
    UnreadableTarget,
    /// The operator's settings did not read or parse.
    UnreadablePolicy,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowList => "allow_list",
            Self::DenyList => "deny_list",
            Self::Default => "default",
            Self::UnreadableTarget => "unreadable_target",
            Self::UnreadablePolicy => "unreadable_policy",
        }
    }
}

/// The operator's allow and deny lists and the verdict for anyone else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    allow: BTreeSet<String>,
    deny: BTreeSet<String>,
    default: Verdict,
}

impl Policy {
    /// The policy the three settings give.
    /// An unset setting takes its default; one set but unreadable (not
    /// UTF-8) is an error, never "unset".
    pub fn from_settings() -> anyhow::Result<Self> {
        Self::from_reader(crate::settings::var)
    }

    fn from_reader(
        read: impl Fn(&str) -> Result<String, std::env::VarError>,
    ) -> anyhow::Result<Self> {
        let read = |name: &str| match read(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(error) => Err(anyhow::anyhow!("{name}: {error}")),
        };
        Self::parse(
            read(ALLOW_SETTING)?.as_deref(),
            read(DENY_SETTING)?.as_deref(),
            read(DEFAULT_SETTING)?.as_deref(),
        )
    }

    pub fn parse(
        allow: Option<&str>,
        deny: Option<&str>,
        default: Option<&str>,
    ) -> anyhow::Result<Self> {
        let default = match default.map(str::trim).filter(|v| !v.is_empty()) {
            None => Verdict::Go,
            Some(v) if v.eq_ignore_ascii_case("go") => Verdict::Go,
            Some(v) if v.eq_ignore_ascii_case("no") => Verdict::No,
            Some(v) => anyhow::bail!("{DEFAULT_SETTING} must be `go` or `no`, not {v:?}"),
        };
        Ok(Self {
            allow: node_ids(ALLOW_SETTING, allow)?,
            deny: node_ids(DENY_SETTING, deny)?,
            default,
        })
    }

    /// The verdict for `peer` (a lowercase 64-hex node id) and what gave it.
    pub fn decide(&self, peer: &str) -> (Verdict, Source) {
        if self.deny.contains(peer) {
            (Verdict::No, Source::DenyList)
        } else if self.allow.contains(peer) {
            (Verdict::Go, Source::AllowList)
        } else {
            (self.default, Source::Default)
        }
    }

    /// The policy as a record cites it: a digest over the lists' commitments
    /// under `salt`, the default and the rows' thresholds, so the digest says
    /// which policy was read without letting anyone confirm a guessed list.
    pub fn digest(&self, salt: &[u8; 32]) -> String {
        let commitments = |ids: &BTreeSet<String>| {
            let mut out: Vec<String> = ids.iter().map(|id| peer_commitment(id, salt)).collect();
            out.sort();
            out
        };
        let policy = json!({
            "policy": POLICY,
            "default": self.default.as_str(),
            "allow": commitments(&self.allow),
            "deny": commitments(&self.deny),
            "rows": base::thresholds(),
        });
        crate::capsule_emit::digest_json(&policy).expect("the policy is plain JSON")
    }
}

fn node_ids(setting: &str, raw: Option<&str>) -> anyhow::Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for entry in raw.unwrap_or("").split(',').map(str::trim) {
        if entry.is_empty() {
            continue;
        }
        if entry.len() != 64 || !entry.bytes().all(|b| b.is_ascii_hexdigit()) {
            anyhow::bail!("{setting}: {entry:?} is not a 64-hex mesh node id");
        }
        ids.insert(entry.to_ascii_lowercase());
    }
    Ok(ids)
}

/// The salt the records' commitments use: a domain-separated digest of this
/// node's signing key, so it is never stored apart from the key and is lost
/// only with it.
pub fn salt(signing_key: &ed25519_dalek::SigningKey) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"capsules/admission-salt/1\0");
    hasher.update(signing_key.to_bytes());
    hasher.finalize().into()
}

/// The hook the plugin declares: admission on `backend_selected` only, no
/// bodies or headers. Not required, so a host without the lifecycle still
/// loads the plugin; the operator's grant decides whether a failed hook
/// blocks the request.
pub fn hook_manifest() -> OpenAiExchangeHookManifest {
    let mut hook = openai_exchange_hook(HANDLER);
    hook.phases = vec!["backend_selected".into()];
    hook.admission = true;
    hook
}

/// Which backend a `backend_selected` event names.
#[derive(Debug, PartialEq, Eq)]
enum Target {
    /// A mesh peer, by its lowercase 64-hex node id.
    Peer(String),
    /// Not a peer: this node's own backend, an HTTP backend, or none.
    NotAPeer,
    Unreadable,
}

/// The host names a mesh backend by its routing target's `Debug` form,
/// `Remote(PublicKey(<64 hex>))` for a peer (mesh-llm's `InferenceTarget`
/// and iroh's `PublicKey`). That is not a stable contract, so any other shape
/// of a mesh target is unreadable, and an unreadable target is a NO.
fn target(event: &Value) -> Target {
    if event.get("provider").and_then(Value::as_str) != Some("mesh") {
        return Target::NotAPeer;
    }
    let Some(target) = event.get("target").and_then(Value::as_str) else {
        return Target::Unreadable;
    };
    if target == "None" || target.starts_with("Local(") || target.starts_with("local") {
        return Target::NotAPeer;
    }
    match target
        .strip_prefix("Remote(PublicKey(")
        .and_then(|rest| rest.strip_suffix("))"))
    {
        Some(id) if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) => {
            Target::Peer(id.to_ascii_lowercase())
        }
        _ => Target::Unreadable,
    }
}

/// Seals one decision's block onto the node's chain.
type Seal = Box<dyn Fn(Map<String, Value>) -> anyhow::Result<()> + Send + Sync>;

/// The policy in force and where its decisions are sealed.
pub struct Admission {
    /// `None`: the settings did not read or parse, and every peer gets NO.
    policy: Option<Policy>,
    salt: [u8; 32],
    policy_digest: Option<String>,
    seal: Seal,
    base: Arc<base::Base>,
}

impl Admission {
    /// `policy` as [`Policy::from_settings`] read it; an error is logged
    /// once here and fails closed.
    pub fn new(policy: anyhow::Result<Policy>, capsules: Arc<CapsuleState>) -> Self {
        let salt = salt(capsules.signing_key());
        let base = Arc::new(base::Base::new(capsules.ledger_dir().to_path_buf()));
        Self::with_seal(
            policy,
            salt,
            Box::new(move |block| capsules.emit_admission_decision(block).map(|_| ())),
            base,
        )
    }

    fn with_seal(
        policy: anyhow::Result<Policy>,
        salt: [u8; 32],
        seal: Seal,
        base: Arc<base::Base>,
    ) -> Self {
        let policy = match policy {
            Ok(policy) => Some(policy),
            Err(error) => {
                tracing::error!(
                    %error,
                    "admission settings are unreadable; every peer gets NO until they are fixed and mesh-llm restarts"
                );
                None
            }
        };
        let policy_digest = policy.as_ref().map(|policy| policy.digest(&salt));
        Self {
            policy,
            salt,
            policy_digest,
            seal,
            base,
        }
    }

    /// Start the rows' background card asks and local refresh.
    pub fn start(&self, context: mesh_llm_plugin::PluginContext<'static>) {
        self.base.start(context);
    }

    /// The host's answer for one lifecycle event.
    pub fn answer(&self, event: &Value) -> OpenAiExchangeDecision {
        self.answer_at(event, std::time::Instant::now(), chrono::Utc::now())
    }

    fn answer_at(
        &self,
        event: &Value,
        at: std::time::Instant,
        now: chrono::DateTime<chrono::Utc>,
    ) -> OpenAiExchangeDecision {
        if event.get("phase").and_then(Value::as_str) != Some("backend_selected") {
            return OpenAiExchangeDecision::default();
        }
        let (peer, (verdict, source)) = match target(event) {
            Target::NotAPeer => return OpenAiExchangeDecision::default(),
            Target::Peer(peer) => {
                let decided = match &self.policy {
                    Some(policy) => policy.decide(&peer),
                    None => (Verdict::No, Source::UnreadablePolicy),
                };
                (Some(peer), decided)
            }
            Target::Unreadable => (None, (Verdict::No, Source::UnreadableTarget)),
        };
        let rows = peer.as_deref().map(|peer| self.base.read(peer, at, now));
        let block = self.block(peer.as_deref(), verdict, source, rows.as_ref(), event);
        if let Err(error) = (self.seal)(block) {
            tracing::error!(%error, reason = SEAL_FAILED, "could not seal an admission decision; answering NO");
            return seal_failed();
        }
        match verdict {
            Verdict::Go => OpenAiExchangeDecision {
                decision: OpenAiAdmissionDecision::Allow,
                ..Default::default()
            },
            Verdict::No => deny(format!("admission NO ({})", source.as_str())),
        }
    }

    fn block(
        &self,
        peer: Option<&str>,
        verdict: Verdict,
        source: Source,
        rows: Option<&base::Read>,
        event: &Value,
    ) -> Map<String, Value> {
        let mut block = Map::new();
        block.insert(
            "peer_commitment".into(),
            peer.map_or(
                Value::Null,
                |peer| json!({"alg": "SHA-256", "digest": peer_commitment(peer, &self.salt)}),
            ),
        );
        block.insert("verdict".into(), json!(verdict.as_str()));
        block.insert("source".into(), json!(source.as_str()));
        let mut reads = vec![json!({
            "kind": "operator_policy",
            "policy": POLICY,
            "digest": self.policy_digest.as_ref().map(|digest| json!({"alg": "SHA-256", "digest": digest})),
        })];
        if let Some(rows) = rows {
            reads.push(match &rows.card {
                Some(card) => json!({
                    "kind": "history_card",
                    "derivation": "history_card/1",
                    "commitment": {"alg": "SHA-256", "digest": peer_commitment(card, &self.salt)},
                }),
                None => json!({"kind": "history_card", "state": "not_read"}),
            });
            block.insert(
                "rows".into(),
                base::ROWS
                    .iter()
                    .zip(rows.rows)
                    .map(|(row, result)| json!({"row": row, "result": result.as_str()}))
                    .collect(),
            );
        }
        block.insert("reads".into(), Value::Array(reads));
        for field in ["request_id", "attempt", "model"] {
            block.insert(
                field.into(),
                event.get(field).cloned().unwrap_or(Value::Null),
            );
        }
        block
    }
}

/// The answer when a decision could not be sealed: NO, with a reason that
/// says so rather than a deny.
pub fn seal_failed() -> OpenAiExchangeDecision {
    deny(SEAL_FAILED.to_string())
}

fn deny(reason: String) -> OpenAiExchangeDecision {
    OpenAiExchangeDecision {
        decision: OpenAiAdmissionDecision::Deny,
        reason: Some(reason),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOWED: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
    const DENIED: &str = "dd00000000000000000000000000000000000000000000000000000000000002";
    const STRANGER: &str = "5500000000000000000000000000000000000000000000000000000000000003";

    fn policy(default: Option<&str>) -> Policy {
        Policy::parse(Some(ALLOWED), Some(DENIED), default).expect("parses")
    }

    fn admission(policy: Policy) -> (Admission, Arc<CapsuleState>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let capsules = Arc::new(CapsuleState::open(dir.path(), "node-under-test").expect("open"));
        (Admission::new(Ok(policy), capsules.clone()), capsules, dir)
    }

    fn selected(target: &str) -> Value {
        json!({
            "phase": "backend_selected",
            "provider": "mesh",
            "target": target,
            "request_id": "req-1",
            "attempt": 1,
            "model": "e2e-model",
        })
    }

    fn remote(id: &str) -> String {
        format!("Remote(PublicKey({id}))")
    }

    fn sealed_block(capsules: &CapsuleState) -> Value {
        let head = capsules.chain_head().expect("a record was sealed");
        let entry = capsules.lookup(&head).expect("lookup").expect("present");
        entry.capsule["model_attestation"]["compute_attestation"][BLOCK].clone()
    }

    #[test]
    fn a_denied_peer_gets_no_and_an_allowed_peer_gets_go() {
        let (admission, capsules, _dir) = admission(policy(None));

        let answer = admission.answer(&selected(&remote(DENIED)));
        assert_eq!(answer.decision, OpenAiAdmissionDecision::Deny);
        assert_eq!(answer.reason.as_deref(), Some("admission NO (deny_list)"));
        let block = sealed_block(&capsules);
        assert_eq!(block["verdict"], "NO");
        assert_eq!(block["source"], "deny_list");

        let answer = admission.answer(&selected(&remote(ALLOWED)));
        assert_eq!(answer.decision, OpenAiAdmissionDecision::Allow);
        let block = sealed_block(&capsules);
        assert_eq!(block["verdict"], "GO");
        assert_eq!(block["source"], "allow_list");
        assert_eq!(
            capsules.capsule_ids_in_order().len(),
            2,
            "one record per decision"
        );
    }

    #[test]
    fn an_unlisted_peer_gets_the_default() {
        for (default, verdict, decision) in [
            (None, "GO", OpenAiAdmissionDecision::Allow),
            (Some("go"), "GO", OpenAiAdmissionDecision::Allow),
            (Some("NO"), "NO", OpenAiAdmissionDecision::Deny),
        ] {
            let (admission, capsules, _dir) = admission(policy(default));
            assert_eq!(
                admission.answer(&selected(&remote(STRANGER))).decision,
                decision
            );
            let block = sealed_block(&capsules);
            assert_eq!(block["verdict"], verdict, "{default:?}");
            assert_eq!(block["source"], "default");
        }
    }

    fn row_results(block: &Value) -> Vec<(&str, &str)> {
        block["rows"]
            .as_array()
            .expect("rows are sealed")
            .iter()
            .map(|r| (r["row"].as_str().unwrap(), r["result"].as_str().unwrap()))
            .collect()
    }

    #[test]
    fn every_decision_about_a_peer_seals_its_rows() {
        let (admission, capsules, _dir) = admission(policy(None));
        for peer in [ALLOWED, DENIED, STRANGER] {
            admission.answer(&selected(&remote(peer)));
            let block = sealed_block(&capsules);
            assert_eq!(
                row_results(&block),
                base::ROWS
                    .iter()
                    .map(|row| (*row, "not_read"))
                    .collect::<Vec<_>>(),
                "nothing read yet about {peer}"
            );
            assert_eq!(
                block["reads"][1],
                json!({"kind": "history_card", "state": "not_read"})
            );
        }
        assert!(
            sealed_block(&capsules).get("limit").is_none(),
            "no cap: step 4 is GO or NO only"
        );
    }

    /// A peer whose rows all pass: a verified card a month old, and one
    /// settled, corroborated exchange with no adverse adjudication.
    fn all_rows_pass(admission: &Admission, peer: &str, at: std::time::Instant) {
        let now = chrono::Utc::now();
        let key = "ab00000000000000000000000000000000000000000000000000000000000006";
        crate::peer_keys::announced::announce_for_test(peer, key);
        admission.base.record_card(
            peer,
            base::CardOutcome::Read(base::Card {
                artifact_digest: "c".repeat(64),
                first_checkpoint_at: Some(now - chrono::Duration::days(30)),
                key_id: key.to_string(),
            }),
            at,
        );
        admission.base.set_facts_for_test(
            peer,
            base::LocalFacts {
                settled: 1,
                held_halves: 1,
                verdicts: 1,
                adverse: 0,
            },
        );
    }

    #[test]
    fn the_record_cites_the_card_the_rows_read_by_commitment() {
        let (admission, capsules, _dir) = admission(policy(None));
        let at = std::time::Instant::now();
        all_rows_pass(&admission, STRANGER, at);
        let answer = admission.answer_at(&selected(&remote(STRANGER)), at, chrono::Utc::now());
        assert_eq!(answer.decision, OpenAiAdmissionDecision::Allow);
        let head = capsules.chain_head().unwrap();
        let record = capsules.lookup(&head).unwrap().unwrap().capsule;
        assert!(
            !record.to_string().contains(&"c".repeat(64)),
            "the card's digest is never sealed in clear"
        );
        let block = &record["model_attestation"]["compute_attestation"][BLOCK];
        assert_eq!(block["verdict"], "GO");
        assert_eq!(block["source"], "default");
        assert_eq!(
            row_results(block),
            base::ROWS
                .iter()
                .map(|row| (*row, "pass"))
                .collect::<Vec<_>>()
        );
        let salt = salt(capsules.signing_key());
        assert_eq!(block["reads"][1]["kind"], "history_card");
        assert_eq!(block["reads"][1]["derivation"], "history_card/1");
        assert_eq!(
            block["reads"][1]["commitment"]["digest"],
            peer_commitment(&"c".repeat(64), &salt)
        );
    }

    #[test]
    fn an_adverse_adjudication_is_sealed_as_a_row_and_never_blocks_on_its_own() {
        let at = std::time::Instant::now();
        let adverse = base::LocalFacts {
            settled: 3,
            held_halves: 3,
            verdicts: 1,
            adverse: 1,
        };
        for (default, decision, verdict) in [
            (None, OpenAiAdmissionDecision::Allow, "GO"),
            (Some("no"), OpenAiAdmissionDecision::Deny, "NO"),
        ] {
            let (admission, capsules, _dir) = admission(policy(default));
            all_rows_pass(&admission, STRANGER, at);
            admission.base.set_facts_for_test(STRANGER, adverse.clone());
            let answer = admission.answer_at(&selected(&remote(STRANGER)), at, chrono::Utc::now());
            assert_eq!(answer.decision, decision, "the config decides: {default:?}");
            let block = sealed_block(&capsules);
            assert_eq!(block["verdict"], verdict);
            assert_eq!(block["source"], "default");
            assert_eq!(
                block["rows"][3],
                json!({"row": "disputes", "result": "fail"})
            );
        }
    }

    #[test]
    fn deny_wins_when_a_peer_is_on_both_lists() {
        let both = Policy::parse(Some(DENIED), Some(DENIED), None).unwrap();
        assert_eq!(both.decide(DENIED), (Verdict::No, Source::DenyList));
    }

    #[test]
    fn the_record_cites_the_policy_and_never_names_the_peer() {
        let (admission, capsules, _dir) = admission(policy(None));
        admission.answer(&selected(&remote(DENIED)));
        let head = capsules.chain_head().unwrap();
        let record = capsules.lookup(&head).unwrap().unwrap().capsule;
        let text = record.to_string();
        assert!(
            !text.contains(DENIED),
            "the peer's id is never sealed in clear"
        );
        assert!(!text.contains(ALLOWED), "nor any listed id");

        let block = &record["model_attestation"]["compute_attestation"][BLOCK];
        let salt = salt(capsules.signing_key());
        assert_eq!(
            block["peer_commitment"]["digest"],
            peer_commitment(DENIED, &salt),
            "the operator, who holds the key, can say which peer it names"
        );
        assert_eq!(block["reads"][0]["kind"], "operator_policy");
        assert_eq!(block["reads"][0]["policy"], POLICY);
        assert_eq!(
            block["reads"][0]["digest"]["digest"],
            policy(None).digest(&salt)
        );
        assert_eq!(block["request_id"], "req-1");
        assert_eq!(block["attempt"], 1);
        assert_eq!(block["model"], "e2e-model");
    }

    #[test]
    fn the_policy_digest_changes_with_the_salt_alone() {
        let policy = policy(None);
        assert_ne!(policy.digest(&[1; 32]), policy.digest(&[2; 32]));
        assert_eq!(policy.digest(&[1; 32]), policy.digest(&[1; 32]));
    }

    #[test]
    fn the_policy_digest_changes_with_the_policy() {
        let salt = [1; 32];
        let base = policy(None).digest(&salt);
        assert_ne!(base, policy(Some("no")).digest(&salt));
        let swapped = Policy::parse(Some(DENIED), Some(ALLOWED), None).unwrap();
        assert_ne!(base, swapped.digest(&salt));
    }

    #[test]
    fn an_unreadable_mesh_target_is_no_and_is_sealed() {
        for target in [
            "Remote(EndpointId(abc))".to_string(),
            remote("abc"),
            remote(&"g".repeat(64)),
            "PublicKey(x)".to_string(),
        ] {
            let (admission, capsules, _dir) = admission(policy(None));
            let answer = admission.answer(&selected(&target));
            assert_eq!(answer.decision, OpenAiAdmissionDecision::Deny, "{target}");
            let block = sealed_block(&capsules);
            assert_eq!(block["source"], "unreadable_target");
            assert_eq!(block["peer_commitment"], Value::Null);
            assert!(block.get("rows").is_none(), "no peer, no rows");
        }
        let (admission, capsules, _dir) = admission(policy(None));
        let mut event = selected("");
        event.as_object_mut().unwrap().remove("target");
        assert_eq!(
            admission.answer(&event).decision,
            OpenAiAdmissionDecision::Deny
        );
        assert_eq!(sealed_block(&capsules)["source"], "unreadable_target");
    }

    #[test]
    fn a_target_that_is_not_a_peer_is_not_decided() {
        let (admission, capsules, _dir) = admission(policy(Some("no")));
        let mut http = selected("http://127.0.0.1:9000");
        http["provider"] = json!("plugin");
        for event in [
            selected("Local(9337)"),
            selected("local-native"),
            selected("None"),
            http,
            json!({"phase": "request_received", "provider": "mesh", "target": remote(DENIED)}),
        ] {
            assert_eq!(
                admission.answer(&event).decision,
                OpenAiAdmissionDecision::Abstain,
                "{event}"
            );
        }
        assert_eq!(
            capsules.chain_head(),
            None,
            "nothing about a non-peer is sealed"
        );
    }

    #[test]
    fn upper_case_ids_match() {
        let upper = ALLOWED.to_ascii_uppercase();
        let policy = Policy::parse(Some(&upper), None, Some("no")).unwrap();
        assert_eq!(policy.decide(ALLOWED), (Verdict::Go, Source::AllowList));
        let (admission, _capsules, _dir) = admission(policy);
        assert_eq!(
            admission.answer(&selected(&remote(&upper))).decision,
            OpenAiAdmissionDecision::Allow
        );
    }

    #[test]
    fn bad_settings_are_refused() {
        assert!(Policy::parse(Some("abc"), None, None).is_err());
        assert!(Policy::parse(None, Some(&"z".repeat(64)), None).is_err());
        assert!(Policy::parse(None, None, Some("maybe")).is_err());
        let empty = Policy::parse(Some(" , "), Some(""), Some(" ")).unwrap();
        assert_eq!(empty.decide(STRANGER), (Verdict::Go, Source::Default));
    }

    #[test]
    fn a_failed_seal_answers_no_and_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        let admission = Admission::with_seal(
            Ok(policy(None)),
            [1; 32],
            Box::new(|_| anyhow::bail!("disk full")),
            Arc::new(base::Base::new(dir.path().to_path_buf())),
        );
        let answer = admission.answer(&selected(&remote(ALLOWED)));
        assert_eq!(
            answer.decision,
            OpenAiAdmissionDecision::Deny,
            "never an unsealed GO"
        );
        assert_eq!(answer.reason.as_deref(), Some(SEAL_FAILED));
    }

    #[test]
    fn unreadable_settings_fail_closed_for_every_peer() {
        let (admission, capsules, _dir) = {
            let dir = tempfile::tempdir().expect("tempdir");
            let capsules =
                Arc::new(CapsuleState::open(dir.path(), "node-under-test").expect("open"));
            let bad = Policy::parse(None, Some("typo"), None);
            (Admission::new(bad, capsules.clone()), capsules, dir)
        };
        for peer in [ALLOWED, DENIED, STRANGER] {
            let answer = admission.answer(&selected(&remote(peer)));
            assert_eq!(answer.decision, OpenAiAdmissionDecision::Deny, "{peer}");
            assert_eq!(
                answer.reason.as_deref(),
                Some("admission NO (unreadable_policy)")
            );
            let block = sealed_block(&capsules);
            assert_eq!(block["source"], "unreadable_policy");
            assert_eq!(
                block["reads"][0]["digest"],
                Value::Null,
                "no policy was read"
            );
            assert_eq!(
                block["rows"].as_array().map(Vec::len),
                Some(5),
                "the peer is still named, so its rows are read"
            );
        }
    }

    #[test]
    fn a_set_but_unreadable_setting_is_an_error_not_unset() {
        use std::env::VarError;
        let read = |name: &str| match name {
            DENY_SETTING => Err(VarError::NotUnicode("\u{fffd}".into())),
            _ => Err(VarError::NotPresent),
        };
        let error = Policy::from_reader(read).expect_err("not silently empty");
        assert!(error.to_string().contains(DENY_SETTING), "{error}");
        let unset = Policy::from_reader(|_| Err(VarError::NotPresent)).expect("all unset");
        assert_eq!(unset.decide(STRANGER), (Verdict::Go, Source::Default));
    }

    #[test]
    fn the_hook_asks_for_admission_on_backend_selected_only() {
        let hook = hook_manifest();
        assert_eq!(hook.handler, HANDLER);
        assert_eq!(hook.phases, vec!["backend_selected".to_string()]);
        assert!(hook.admission);
        assert!(
            !hook.required,
            "a host without the lifecycle still loads the plugin"
        );
        assert!(!hook.request_body && !hook.response_body && hook.headers.is_empty());
        mesh_llm_plugin::openai_exchange::validate_openai_exchange_manifest(&hook)
            .expect("the host accepts the declaration");
    }
}
