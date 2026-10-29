//! The #315 conformance vectors (`vectors/inference-service-history-v0`,
//! action-state-group/agent-action-capsule#315 at f8c946ed) over this
//! module's checker. Their definition is another one than this node's (a
//! daily policy from 2026-10-01), so each case's `period_policy` is taken
//! from the definition the case hands over.
//!
//! Of the 27 cases, 19 run here and 8 are listed by id, not run:
//! [`OUT_OF_SCOPE`]. The checker holds one History at a time, so
//! `period_fixed` over a pair is evaluated by [`period_fixed`] below, in this
//! test.

use base64::Engine;
use serde_json::{Map, Value};

use super::*;

const VECTORS: &str = include_str!("../../../../vectors/inference-service-history-v0/vectors.json");

/// The cases this plugin does not run, each with why: it serves no Detailed
/// level (no `exchanges` member, no recipient, no peer-confirmed labels).
const OUT_OF_SCOPE: [&str; 8] = [
    "refused-detailed-other-requester",
    "detailed-peer-confirmed",
    "mutant-labelled-corroborated",
    "mutant-same-key-halves-labelled-peer-confirmed",
    "mutant-unjoined-halves-labelled-peer-confirmed",
    "mutant-uncited-halves-labelled-peer-confirmed",
    "mutant-one-sided-labelled-peer-confirmed",
    "mutant-untrusted-peer-labelled-peer-confirmed",
];

fn cases() -> Vec<Value> {
    let corpus: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(corpus["count"], json!(27));
    corpus["cases"].as_array().unwrap().clone()
}

fn id(case: &Value) -> &str {
    case["id"].as_str().unwrap()
}

/// The JSON a case carries as octets.
fn octets(part: &Value) -> Value {
    serde_json::from_str(part["octets_text"].as_str().unwrap()).unwrap()
}

/// The artifact of a case's reply envelope.
fn artifact(reply: &Value) -> Map<String, Value> {
    let envelope = octets(reply);
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(envelope["artifact"].as_str().unwrap().trim_end_matches('='))
        .unwrap();
    serde_json::from_slice::<Value>(&bytes)
        .unwrap()
        .as_object()
        .unwrap()
        .clone()
}

/// The property a failed check names: the word before the first `:`.
fn failed_property(why: &str) -> &str {
    why.split(':').next().unwrap()
}

/// Check one History as the case hands it over: its definition's policy,
/// then every rule over its artifact. The counts, or the failed property.
fn check_history(definition: &Value, reply: &Value) -> Result<Counts, String> {
    let def = Definition::from_document(definition)?;
    let art = artifact(reply);
    let history = art["history_card"]["history"].as_array().unwrap();
    let times: Vec<&str> = history
        .iter()
        .map(|h| h["checkpoint"]["timestamp"].as_str().unwrap())
        .collect();
    let log_size = history.last().unwrap()["checkpoint"]["log_size"]
        .as_u64()
        .unwrap();
    assert_eq!(
        art["derivation"],
        json!(def.digest()),
        "a reply names its definition by digest"
    );
    check_artifact(
        &def,
        &art,
        &times,
        art["anchor"].as_str().unwrap(),
        art["evidence_stream"].as_str().unwrap(),
        log_size,
    )
}

/// `period_fixed` (ISH §6.1 item 4, §8.3) over two Histories of one node,
/// the earlier first: every period of the earlier is in the later, with the
/// same cells.
fn period_fixed(earlier: &Counts, later: &Counts) -> bool {
    earlier
        .periods
        .iter()
        .all(|p| later.periods.iter().any(|q| q == p))
}

/// The failing property a case expects, `None` when it expects none.
fn expected_failure(expected: &Value) -> Option<&str> {
    let fails = expected["fails"].as_array().unwrap();
    assert!(fails.len() <= 1, "a case fails one property");
    fails.first().map(|f| f.as_str().unwrap())
}

fn is_standard(case: &Value) -> bool {
    case["inputs"]["definition"]["level"] == json!("standard")
}

#[test]
fn the_vector_files_are_the_ones_pinned() {
    // The copy is byte-identical to the source's, which its own manifest and
    // SHA256SUMS pin.
    let digest = hex::encode(Sha256::digest(VECTORS.as_bytes()));
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../../vectors/inference-service-history-v0/manifest.json"
    ))
    .unwrap();
    assert_eq!(manifest["files"][0]["sha256"], json!(digest));
    assert_eq!(manifest["files"][0]["count"], json!(27));
}

#[test]
fn every_case_runs_or_is_listed_by_id() {
    let all = cases();
    let listed: Vec<&str> = all.iter().filter(|c| !is_run(c)).map(id).collect();
    assert_eq!(listed, OUT_OF_SCOPE);
    assert_eq!(all.len() - listed.len(), 19);
}

/// Whether this module runs the case: a Standard History or pair of them, or
/// a refusal this node's responder also gives.
fn is_run(case: &Value) -> bool {
    match case["kind"].as_str().unwrap() {
        "history" => is_standard(case),
        "pair" => true,
        "refusal" => !OUT_OF_SCOPE.contains(&id(case)),
        other => panic!("a case of kind {other}"),
    }
}

#[test]
fn the_standard_histories_check_as_the_vectors_expect() {
    let mut run = 0;
    for case in cases()
        .iter()
        .filter(|c| c["kind"] == json!("history") && is_standard(c))
    {
        let got = check_history(&case["inputs"]["definition"], &case["inputs"]["reply"]);
        // `definition_form` and `definition_binding` pass in every case.
        match (expected_failure(&case["expected"]), got) {
            (None, Ok(_)) => {}
            (Some(want), Err(why)) => {
                assert_eq!(failed_property(&why), want, "{}: {why}", id(case))
            }
            (want, got) => panic!("{}: expected {want:?}, got {got:?}", id(case)),
        }
        run += 1;
    }
    assert_eq!(run, 13);
}

#[test]
fn the_periods_of_a_pair_are_fixed_as_the_vectors_expect() {
    let mut run = 0;
    for case in cases().iter().filter(|c| c["kind"] == json!("pair")) {
        let histories = case["inputs"]["histories"].as_array().unwrap();
        assert_eq!(histories.len(), 2, "{}: not two Histories", id(case));
        let checked: Vec<Result<Counts, String>> = histories
            .iter()
            .map(|h| check_history(&h["definition"], &h["reply"]))
            .collect();
        let want = case["expected"]["period_fixed"].as_str().unwrap();
        let fixed = match (&checked[0], &checked[1]) {
            (Ok(earlier), Ok(later)) => period_fixed(earlier, later),
            // A period dropped at the later anchor leaves that History's
            // periods short of the closed ones: this checker refuses it as
            // `period_alignment` before the pair is compared, which is
            // `period_fixed` failing all the same.
            (Ok(_), Err(why)) => {
                assert_eq!(failed_property(why), "period_alignment", "{}", id(case));
                false
            }
            (earlier, later) => panic!("{}: {earlier:?} {later:?}", id(case)),
        };
        assert_eq!(fixed, want == "PASS", "{}", id(case));
        run += 1;
    }
    assert_eq!(run, 3);
}

/// The time of the checkpoint a pin names, in any case's card: the pin is
/// the digest of the checkpoint (README, "history card").
fn pinned_time(cases: &[Value], pin: &str) -> String {
    for case in cases {
        let replies = match case["kind"].as_str().unwrap() {
            "pair" => case["inputs"]["histories"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h["reply"].clone())
                .collect(),
            _ => vec![case["inputs"]["reply"].clone()],
        };
        for reply in replies {
            if octets(&reply).get("artifact").is_none() {
                continue;
            }
            for entry in artifact(&reply)["history_card"]["history"]
                .as_array()
                .unwrap()
            {
                let text = jcs::to_string(&entry["checkpoint"]).unwrap();
                if hex::encode(Sha256::digest(text.as_bytes())) == pin {
                    return entry["checkpoint"]["timestamp"]
                        .as_str()
                        .unwrap()
                        .to_string();
                }
            }
        }
    }
    panic!("no case holds the checkpoint {pin}");
}

/// The refusals this node also gives: an interval that is no run of whole
/// periods, and an anchor off a period boundary, each `policy_declined`
/// (ISH §6.1 items 2 and 5).
#[test]
fn the_refusals_are_the_ones_this_node_gives() {
    let all = cases();
    let mut run = 0;
    for case in all
        .iter()
        .filter(|c| c["kind"] == json!("refusal") && is_run(c))
    {
        assert_eq!(case["expected"]["reason"], json!("policy_declined"));
        let def = Definition::from_document(&case["inputs"]["definition"]).unwrap();
        let request = octets(&case["inputs"]["request"]);
        assert_eq!(request["derivation"], json!(def.digest()));
        let declined = if request["subject"].get("full_history").is_none() {
            true
        } else {
            let pin = request["coverage"]["expected_pin"].as_str().unwrap();
            !def.policy.is_boundary(&pinned_time(&all, pin))
        };
        assert!(declined, "{}", id(case));
        run += 1;
    }
    assert_eq!(run, 3);
}

#[test]
fn a_definition_that_is_not_the_profiles_is_refused() {
    let case = &cases()[0];
    let good = case["inputs"]["definition"].clone();
    assert!(Definition::from_document(&good).is_ok());
    for (member, value) in [
        ("level", json!("detailed")),
        ("embeds", json!([])),
        ("name", json!("Service-History")),
        ("reads", json!(["a field no member reads"])),
        ("extra", json!(1)),
    ] {
        let mut bad = good.clone();
        bad[member] = value;
        let why = Definition::from_document(&bad).unwrap_err();
        assert!(why.starts_with("definition_form:"), "{member}: {why}");
    }
    for (member, value) in [
        ("length_s", json!(3600)),
        ("floor", json!(0)),
        ("epoch", json!("2026-10-01T00:00:00.5Z")),
        ("suppression", json!("none")),
    ] {
        let mut bad = good.clone();
        bad["period_policy"][member] = value;
        let why = Definition::from_document(&bad).unwrap_err();
        assert!(why.starts_with("definition_form:"), "{member}: {why}");
    }
    let mut missing = good;
    missing["period_policy"]
        .as_object_mut()
        .unwrap()
        .remove("floor");
    assert!(Definition::from_document(&missing).is_err());
}

/// The two-node e2e script names its two-minute definition by the digest it
/// computes with `jq`; this build computes the same one.
#[test]
fn the_e2e_override_is_another_definition_with_its_own_digest() {
    let mut document: Value = serde_json::from_str(DEFINITION_DOCUMENT).unwrap();
    document["period_policy"]["length_s"] = json!(120);
    document["period_policy"]["min_length_s"] = json!(120);
    let def = Definition::from_document(&document).unwrap();
    assert_eq!(def.policy.length_s, 120);
    assert_eq!(
        def.digest(),
        "cf7f57f95044d0cb573320f6eaba74d4a85bc73136f23c8112ca9d41f5c11eeb"
    );
    assert_ne!(def.digest(), DEFINITION_DIGEST);
    assert_ne!(def.policy_digest, POLICY_DIGEST);
}
