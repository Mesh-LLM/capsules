//! T9, the service evidence agreement fixtures (evidencebook#48 design §5, PR 6),
//! run through this plugin: real served halves sealed by the provider's
//! node, read by the Mesh reader, with sessions built and signed by the
//! plugin's own agreement code. Each case asserts the coverage label, the
//! profile's finding and the requirement results, not the finding alone.
//!
//! The plugin seals every half at the present minute, so the design's times
//! are kept as offsets from the served half's minute `m`: proposed at
//! `m - 10 min`, accepted at `m - 5 min`, the receipt at `m - 4 min`, the
//! served half at `m`. Terms are `{spend_cap: 3000, max_exchanges: 2}` with
//! `ln.payment_hash` (design R2), window one hour.

use super::*;
use crate::agreement::{answer, check_proposal, receipt, Proposal, SessionTerms};
use crate::capsule_emit::{CapsuleState, HostProvenance};
use crate::lifecycle_channel::DispatchPath;
use ed25519_dalek::SigningKey;
use evidence_request::acceptance::record_digest;
use sha2::{Digest, Sha256};

const MODEL: &str = "hf:example/t9@main";
const MIN: i64 = 60;

/// A deterministic key from the design's seed rule.
fn seeded_key(label: &str) -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(format!("svc-ev T9 fixtures: {label}")).into();
    SigningKey::from_bytes(&seed)
}

struct Fixture {
    _dirs: (tempfile::TempDir, tempfile::TempDir),
    requester: CapsuleState,
    provider: CapsuleState,
    requester_node: String,
    registry: String,
    /// The served halves' minute.
    m: i64,
}

impl Fixture {
    /// Two nodes, both announced, and `m`, the present minute (away from its
    /// end, so the halves sealed next fall in it).
    fn new(tag: u64) -> Fixture {
        let dirs = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let requester = CapsuleState::open(dirs.0.path(), "t9-requester").unwrap();
        let provider = CapsuleState::open(dirs.1.path(), "t9-provider").unwrap();
        let requester_node = format!("{:064x}", 0x79_0000_0000u64 + tag);
        let provider_node = format!("{:064x}", 0x79_1000_0000u64 + tag);
        let registry = json!({
            &requester_node: hex::encode(requester.public_key()),
            &provider_node: hex::encode(provider.public_key()),
        })
        .to_string();
        let now = present_minute();
        Fixture {
            _dirs: dirs,
            requester,
            provider,
            requester_node,
            registry,
            m: now - now % MIN,
        }
    }

    fn requester_key(&self) -> String {
        hex::encode(self.requester.public_key())
    }

    fn provider_key(&self) -> String {
        hex::encode(self.provider.public_key())
    }

    /// A session proposed at `proposed`, accepted at `accepted`, with the
    /// receipt `receipt_by` signs at `receipt_at`, if any.
    fn session(
        &self,
        proposed: i64,
        accepted: i64,
        receipt_by: Option<(&SigningKey, i64)>,
    ) -> SessionView {
        let terms = SessionTerms {
            spend_cap_msat: 3_000,
            max_exchanges: Some(2),
            window_seconds: 3_600,
        };
        let proposal = Proposal::new(
            self.requester.signing_key(),
            &self.provider_key(),
            &agreement::new_session_id(),
            &terms,
            &[MODEL.to_string()],
            proposed,
        );
        let checked = check_proposal(&proposal.to_message(), &self.provider_key(), proposed)
            .expect("the provider accepts the T9 proposal");
        let accepted = answer(&checked, self.provider.signing_key(), true, accepted);
        let digest = record_digest(&accepted).unwrap();
        let receipt = receipt_by
            .map(|(key, at)| serde_json::to_vec(&receipt(&digest, key, at)).unwrap())
            .unwrap_or_default();
        SessionView {
            acceptance_digest: digest,
            proposer: self.requester_key(),
            acceptor: self.provider_key(),
            start: proposed - proposed % MIN,
            end: proposed - proposed % MIN + 3_600,
            models: vec![MODEL.into()],
            terms: agreement::Terms {
                spend_cap_msat: 3_000,
                max_exchanges: Some(2),
            },
            proposed: proposal.record_text.into_bytes(),
            accepted: serde_json::to_vec(&accepted).unwrap(),
            receipt,
        }
    }

    /// The default T9 session: accepted at `m - 5 min`, the requester's
    /// receipt at `m - 4 min`.
    fn session_p(&self) -> SessionView {
        let m = self.m;
        self.session(
            m - 10 * MIN,
            m - 5 * MIN,
            Some((self.requester.signing_key(), m - 4 * MIN)),
        )
    }

    /// A served half for host exchange `ex`, sealed by the provider now,
    /// citing `cites`.
    fn served(&self, ex: &str, cites: Option<&str>) -> Value {
        let cites = cites.map(String::from);
        self.provider
            .settlement_legs()
            .decide_served_citation(ex, || cites);
        let request = hex::encode(Sha256::digest(ex));
        let observed = observed(
            MODEL,
            ex,
            &request,
            DispatchPath::RawProxy,
            HostProvenance {
                requested_by_node_id: Some(self.requester_node.clone()),
                model_canonical_ref: Some(MODEL.to_string()),
                ..HostProvenance::default()
            },
        );
        self.provider
            .emit_for_observed_host_exchange(&observed)
            .unwrap()
            .capsule
    }

    /// `agreement` on each served half's row, read with `sessions`, these
    /// invoices and legs.
    fn rows(
        &self,
        halves: &[Value],
        sessions: &[SessionView],
        invoices: &[Value],
        legs: &[Value],
    ) -> Vec<Value> {
        attached_in(
            halves,
            sessions,
            invoices,
            legs,
            &self.registry,
            self.m + 110 * MIN,
        )
    }

    /// One exchange's row, with one payment of 1000 msat observed.
    fn one(&self, half: Value, session: SessionView) -> Value {
        let ex = half_exchange(&half);
        self.rows(
            &[half],
            &[session],
            &[invoice(&ex, "p1")],
            &[payee_leg("p1", 1_000, None)],
        )
        .remove(0)
    }
}

fn half_exchange(half: &Value) -> String {
    record_exchange_id(half).unwrap().to_string()
}

/// The case's coverage, finding and requirement results, with T9-A and
/// `R-served` held for every case.
fn outcome(row: &Value) -> (&str, Option<&str>, Vec<&str>) {
    // T9-A: a half citing a session states its spend against the cap, and
    // the cap is the requester's own assertion.
    if row["coverage"] != json!("not_cited") {
        assert_eq!(
            row["spend"]["basis"],
            json!("agent_origin_assertion"),
            "T9-A: {row:#}"
        );
    }
    let results = results(row);
    assert_eq!(results[1], "met", "R-served is unaffected: {row:#}");
    (
        row["coverage"].as_str().unwrap(),
        row["finding"].as_str(),
        results,
    )
}

/// T9-P, the default: the requester's receipt before the served half, both
/// halves cite. Accepted before the exchange; every requirement met, with
/// the accepted record and the receipt as `R-prior`'s evidence.
#[test]
fn t9_p_a_receipt_before_the_exchange_reads_accepted_before() {
    let f = Fixture::new(1);
    let s = f.session_p();
    let digest = s.acceptance_digest.clone();
    let row = f.one(f.served("p-ex", Some(&digest)), s);
    assert_eq!(
        outcome(&row),
        (
            "covered",
            Some("accepted_before_action"),
            vec!["met", "met", "met"]
        ),
        "{row:#}"
    );
    let evidence = row["requirements"][0]["evidence"].as_array().unwrap();
    assert!(evidence.contains(&json!(digest)), "{row:#}");
    assert_eq!(
        evidence.len(),
        2,
        "the accepted record and the receipt: {row:#}"
    );
}

/// T9-N and T9-F1: no receipt, the served half cites. The citation alone is
/// not ordering evidence (P-28), so ordering is not established and
/// `R-prior` is not evaluable. The plugin keeps a session only with its
/// receipt, so on a node this is read with the session as built.
#[test]
fn t9_n_and_f1_a_citation_without_a_receipt_does_not_establish_ordering() {
    let f = Fixture::new(2);
    let m = f.m;
    let s = f.session(m - 10 * MIN, m - 5 * MIN, None);
    let digest = s.acceptance_digest.clone();
    let row = f.one(f.served("n-ex", Some(&digest)), s);
    assert_eq!(
        outcome(&row),
        (
            "covered",
            Some("accepted_execution_cites"),
            vec!["not_evaluable", "met", "met"]
        ),
        "{row:#}"
    );
}

/// T9-L: an honest late receipt, after the served half. Ordering is not
/// established.
#[test]
fn t9_l_a_late_receipt_does_not_establish_ordering() {
    let f = Fixture::new(3);
    let m = f.m;
    let s = f.session(
        m - 10 * MIN,
        m - 5 * MIN,
        Some((f.requester.signing_key(), m + 10 * MIN)),
    );
    let digest = s.acceptance_digest.clone();
    let row = f.one(f.served("l-ex", Some(&digest)), s);
    assert_eq!(
        outcome(&row),
        (
            "covered",
            Some("accepted_execution_cites"),
            vec!["not_evaluable", "met", "met"]
        ),
        "{row:#}"
    );
}

/// T9-D: the provider's own accepted record says it was issued after the
/// served half. Accepted after the exchange; `R-prior` not met.
#[test]
fn t9_d_an_acceptance_issued_after_the_exchange_reads_accepted_after() {
    let f = Fixture::new(4);
    let m = f.m;
    let s = f.session(
        m - 10 * MIN,
        m + 10 * MIN,
        Some((f.requester.signing_key(), m + 11 * MIN)),
    );
    let digest = s.acceptance_digest.clone();
    let row = f.one(f.served("d-ex", Some(&digest)), s);
    assert_eq!(
        outcome(&row),
        (
            "covered",
            Some("accepted_after_action"),
            vec!["not_met", "met", "met"]
        ),
        "{row:#}"
    );
}

/// T9-K: a receipt the provider's side signed, with its announced key or a
/// second key, is not the requester's receipt, so it establishes nothing.
#[test]
fn t9_k_a_receipt_signed_by_the_provider_establishes_nothing() {
    let f = Fixture::new(5);
    let m = f.m;
    let second = seeded_key("Q2");
    for (ex, signer) in [("k-ex", f.provider.signing_key()), ("k2-ex", &second)] {
        let s = f.session(m - 10 * MIN, m - 5 * MIN, Some((signer, m - 4 * MIN)));
        let digest = s.acceptance_digest.clone();
        let row = f.one(f.served(ex, Some(&digest)), s);
        assert_eq!(
            outcome(&row),
            (
                "covered",
                Some("accepted_execution_cites"),
                vec!["not_evaluable", "met", "met"]
            ),
            "{row:#}"
        );
    }
}

/// T9-U: the served half cites nothing while a session with this requester
/// holds its time. "Agreement present; exchange does not cite it", and the
/// finding says the execution does not cite it.
#[test]
fn t9_u_an_uncited_served_half_reads_agreement_present_not_cited() {
    let f = Fixture::new(6);
    let s = f.session_p();
    let digest = s.acceptance_digest.clone();
    let row = f.one(f.served("u-ex", None), s);
    assert_eq!(
        outcome(&row),
        (
            "not_cited",
            Some("accepted_not_cited"),
            vec!["not_evaluable", "met", "met"]
        ),
        "{row:#}"
    );
    assert_eq!(row["acceptance_digest"], json!(digest));
}

/// T9-W: a served half citing a session whose window ended before it. Not
/// covered, outside the window; the half is no candidate for the session.
#[test]
fn t9_w_an_exchange_after_the_window_reads_outside_window() {
    let f = Fixture::new(7);
    let m = f.m;
    let s = f.session(
        m - 70 * MIN,
        m - 65 * MIN,
        Some((f.requester.signing_key(), m - 64 * MIN)),
    );
    let digest = s.acceptance_digest.clone();
    let row = f.one(f.served("w-ex", Some(&digest)), s);
    let (coverage, finding, results) = outcome(&row);
    assert_eq!(coverage, "outside_window", "{row:#}");
    assert_eq!(finding, Some("not_accepted"), "{row:#}");
    assert_eq!(results[0], "not_evaluable", "{row:#}");
}

/// T9-C: three citing exchanges in the window with payments of 1000, 1000
/// and 1500 msat against a count of two and a cap of 3000. The third is not
/// covered: over the count, which outranks over the cap, with the observed
/// 3500 msat shown against the cap. The profile finding is the same for all
/// three; the coverage labels are the Mesh layer.
#[test]
fn t9_c_the_third_exchange_is_over_the_count_and_the_cap() {
    let f = Fixture::new(8);
    let s = f.session_p();
    let digest = s.acceptance_digest.clone();
    let halves: Vec<Value> = ["c1", "c2", "c3"]
        .iter()
        .map(|ex| f.served(ex, Some(&digest)))
        .collect();
    let invoices: Vec<Value> = halves
        .iter()
        .zip(["p1", "p2", "p3"])
        .map(|(h, p)| invoice(&half_exchange(h), p))
        .collect();
    let legs = [
        payee_leg("p1", 1_000, None),
        payee_leg("p2", 1_000, None),
        payee_leg("p3", 1_500, None),
    ];
    let rows = f.rows(&halves, &[s], &invoices, &legs);
    let outcomes: Vec<_> = rows.iter().map(outcome).collect();
    for o in &outcomes {
        assert_eq!(o.1, Some("accepted_before_action"), "{rows:#?}");
        assert_eq!(o.2, ["met", "met", "met"], "{rows:#?}");
    }
    assert_eq!(
        outcomes.iter().map(|o| o.0).collect::<Vec<_>>(),
        ["covered", "covered", "over_count"]
    );
    assert_eq!(rows[2]["count"], json!({"position": 3, "max_exchanges": 2}));
    assert_eq!(rows[2]["spend"]["observed_msat"], json!(3_500));
    assert_eq!(rows[2]["spend"]["spend_cap_msat"], json!(3_000));
    assert_eq!(rows[2]["spend"]["lower_bound"], json!(false));
}
