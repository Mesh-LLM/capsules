//! The price rule (#105): before a paid attempt, the selected peer's
//! advertised input and output rates against the operator's caps, decided by
//! capsule-engine's guard with its `asg/inference` terms pack
//! (`capsule_engine::guard`, the crate Muse's Go guard shares vectors with),
//! never by a second evaluator here.
//!
//! The rates are the ones the host routed on: mesh-llm puts the selected
//! peer's `Pricing` on the `backend_selected` event as `pricing`, and says so
//! by listing [`PRICING_CAPABILITY`]. With the capability, an event without
//! `pricing` is a free route, rates 0. Without it the host never sends a
//! price, so a paid route cannot be told from a free one: with an operator
//! profile (or a shipped default cap) in force that is NO
//! ([`Read::Unavailable`], fail closed); with neither, the pack is not run
//! and the record says the price was not checked.
//!
//! The operator's values are a `policy-profile/v0` file ([`PROFILE_SETTING`]):
//! `rate_cap.max_input_msat_per_million`, `rate_cap.max_output_msat_per_million`,
//! and the pack's `counterparty_list`. The sealed decision cites the pack, its
//! definition digest and the profile's digest. Every dedupe check reads an
//! empty history: a purchase is keyed on its exchange id, and the host pays
//! each attempt at most once, so nothing here could repeat one.

use capsule_engine::guard::{Action, ConstraintResult, Engine, History, Outcome, Profile};
use serde_json::{json, Value};

/// The setting naming the operator's `policy-profile/v0` file.
pub const PROFILE_SETTING: &str = "CAPSULES_ADMISSION_PROFILE";

/// The host capability that says `backend_selected` carries the selected
/// peer's price (mesh-llm `host_capabilities`).
pub const PRICING_CAPABILITY: &str = "openai_exchange.backend_pricing.v1";

/// The rate caps, msat per million input and output tokens, that apply when
/// the operator's profile sets none. `None`: the pack's own default, which no
/// price reaches. Steven's ruling on a shipped default is open
/// (buzz 3998d6d0); either answer changes only this constant.
pub const DEFAULT_RATE_CAPS: Option<(u64, u64)> = None;

/// What `doctor` shows of the rule this process loaded (set once, when the
/// admission hook is built); `None` before that or when its profile did not
/// read.
static LOADED: std::sync::OnceLock<Value> = std::sync::OnceLock::new();

/// The loaded rule's description for `doctor`: the pack, its definition
/// digest, the profile's digest and values. An unreadable profile says so.
pub fn loaded_description() -> Value {
    LOADED.get().cloned().unwrap_or_else(
        || json!({"state": "unreadable_or_not_loaded", "profile_setting": PROFILE_SETTING}),
    )
}

/// Record the loaded rule for `doctor`; a second load (tests) keeps the first.
pub(crate) fn set_loaded(description: Value) -> Result<(), Value> {
    LOADED.set(description)
}

/// The pack's served id, as a profile names it.
const PACK: &str = "asg/inference";

/// What the price rule read for one attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    /// The guard decided: its outcome and each check's result, with the
    /// rates it read.
    Checked {
        outcome: Outcome,
        constraints: Vec<(String, &'static str)>,
        input: u64,
        output: u64,
    },
    /// Nothing is in force and the host sends no price: the pack was not run.
    NotChecked,
    /// A profile or default cap is in force but the host sends no price, or
    /// the attempt does not make an action the engine reads: NO, failing
    /// closed.
    Unavailable,
}

impl Read {
    /// NO when the guard did not allow (`deny` or `escalate`), or the price
    /// is unavailable under a cap.
    pub fn refuses(&self) -> bool {
        match self {
            Read::Checked { outcome, .. } => *outcome != Outcome::Allow,
            Read::NotChecked => false,
            Read::Unavailable => true,
        }
    }

    /// The check that refused, for the decision's `source`.
    pub fn source(&self) -> &str {
        match self {
            Read::Checked { constraints, .. } => constraints
                .iter()
                .find(|(_, result)| *result != "pass" && *result != "n/a")
                .or_else(|| constraints.iter().find(|(_, result)| *result != "pass"))
                .map_or("price", |(id, _)| id.as_str()),
            Read::NotChecked => "price",
            Read::Unavailable => "price_unavailable",
        }
    }
}

/// The pack, the operator's profile over it, and their digests.
pub struct PriceRule {
    engine: Engine,
    profile_digest: Option<String>,
    /// Whether anything is in force: the operator's profile or
    /// [`DEFAULT_RATE_CAPS`].
    in_force: bool,
    /// The profile's values as read, for `doctor`.
    values: Value,
}

impl PriceRule {
    /// The rule [`PROFILE_SETTING`] gives: the named file, or no profile when
    /// it is unset. A file that does not read or decode is an error, never
    /// "unset": the caller fails closed.
    pub fn from_settings() -> anyhow::Result<Self> {
        match crate::settings::var(PROFILE_SETTING) {
            Ok(path) if !path.trim().is_empty() => {
                let raw = std::fs::read(path.trim())
                    .map_err(|e| anyhow::anyhow!("{PROFILE_SETTING}: {e}"))?;
                Self::from_profile(Some(&raw))
            }
            Ok(_) | Err(std::env::VarError::NotPresent) => Self::from_profile(None),
            Err(e) => Err(anyhow::anyhow!("{PROFILE_SETTING}: {e}")),
        }
    }

    /// The rule over `profile` (`policy-profile/v0` bytes), or over the
    /// shipped default when there is none.
    pub fn from_profile(profile: Option<&[u8]>) -> anyhow::Result<Self> {
        let base =
            Engine::inference().map_err(|e| anyhow::anyhow!("asg/inference: {}", e.message()))?;
        let raw = match (profile, DEFAULT_RATE_CAPS) {
            (Some(raw), _) => Some(raw.to_vec()),
            (None, Some((input, output))) => Some(default_profile(input, output)),
            (None, None) => None,
        };
        let Some(raw) = raw else {
            return Ok(Self {
                engine: base,
                profile_digest: None,
                in_force: false,
                values: Value::Null,
            });
        };
        let profile = Profile::decode(&raw)
            .map_err(|e| anyhow::anyhow!("{PROFILE_SETTING}: {}", e.message()))?;
        let engine = base
            .with_profile(&profile)
            .map_err(|e| anyhow::anyhow!("{PROFILE_SETTING}: {}", e.message()))?;
        let values: Value = serde_json::from_slice(&raw)?;
        Ok(Self {
            engine,
            profile_digest: Some(profile.digest().to_string()),
            in_force: true,
            values,
        })
    }

    /// The pack the rule runs, as a decision cites it.
    pub fn reads(&self) -> Value {
        json!({
            "kind": "terms_pack",
            "pack": self.engine.pack_id(),
            "definition_digest": {"alg": "SHA-256", "digest": self.engine.definition_digest()},
            "profile": self.profile_digest.as_ref().map(|d| json!({"alg": "SHA-256", "digest": d})),
        })
    }

    /// What `doctor` shows: the pack, the profile digest and its values.
    pub fn describe(&self) -> Value {
        json!({
            "pack": self.engine.pack_id(),
            "definition_digest": self.engine.definition_digest(),
            "profile_setting": PROFILE_SETTING,
            "profile_digest": self.profile_digest,
            "profile": self.values,
            "default_rate_caps": DEFAULT_RATE_CAPS.map(|(i, o)| json!({"max_input_msat_per_million": i, "max_output_msat_per_million": o})),
            "in_force": self.in_force,
        })
    }

    /// The rule for one `backend_selected` attempt to `peer`. `host_prices`
    /// is whether the host listed [`PRICING_CAPABILITY`].
    pub fn check(&self, event: &Value, peer: &str, host_prices: bool) -> Read {
        let (input, output) = if host_prices {
            match event.get("pricing") {
                None | Some(Value::Null) => (Some(0), Some(0)),
                Some(pricing) => (
                    pricing["input_msat_per_million"].as_u64(),
                    pricing["output_msat_per_million"].as_u64(),
                ),
            }
        } else if self.in_force {
            return Read::Unavailable;
        } else {
            return Read::NotChecked;
        };
        let mut action = json!({
            "operator": crate::settings::PLUGIN_NAME,
            "developer": concat!("capsules@", env!("CARGO_PKG_VERSION")),
            "action_type": "decide",
            "taxonomy_version": "6",
            "verb": "inference.purchase",
            "action_class": "money.purchase",
            "action_id": format!("admission/{}", event["exchange_id"].as_str().unwrap_or("")),
            "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "target": peer,
            "equivalence_key": event["exchange_id"],
        });
        // A rate that does not read is left out, and rate_cap refuses it.
        if let Some(input) = input {
            action["input_msat_per_million"] = json!(input);
        }
        if let Some(output) = output {
            action["output_msat_per_million"] = json!(output);
        }
        let decided = serde_json::to_vec(&action)
            .ok()
            .and_then(|raw| Action::decode(&raw).ok())
            .and_then(|action| self.engine.decide(&action, &History::new()).ok());
        match decided {
            Some(decision) => Read::Checked {
                outcome: decision.outcome(),
                constraints: decision
                    .constraints()
                    .iter()
                    .map(|c| (c.id().to_string(), result_str(c.result())))
                    .collect(),
                input: input.unwrap_or(0),
                output: output.unwrap_or(0),
            },
            // An action the engine cannot read (no exchange id, a rate
            // outside the integers JSON holds) is refused, never admitted.
            None => Read::Unavailable,
        }
    }
}

fn result_str(result: ConstraintResult) -> &'static str {
    result.as_str()
}

/// The shipped default as a profile over the pack.
fn default_profile(input: u64, output: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "format": "policy-profile/v0",
        "packs": [{"pack": PACK, "parameters": {"rate_cap": {
            "max_input_msat_per_million": input,
            "max_output_msat_per_million": output,
        }}}],
    }))
    .expect("a profile of integers serializes")
}

/// The record's view of one read: the rates and each check, never the
/// peer's id (the record names it by commitment).
pub fn record(read: &Read) -> Value {
    match read {
        Read::Checked {
            outcome,
            constraints,
            input,
            output,
        } => json!({
            "state": "checked",
            "outcome": outcome.as_str(),
            "input_msat_per_million": input,
            "output_msat_per_million": output,
            "checks": constraints.iter().map(|(id, r)| json!({"check": id, "result": r})).collect::<Vec<_>>(),
        }),
        Read::NotChecked => json!({"state": "not_checked"}),
        Read::Unavailable => json!({"state": "unavailable"}),
    }
}
