//! The M4 exit gate on test rails (evidencebook#48): a two-node paid session
//! under one agreement, one exchange over the cap shown "not covered: over
//! cap", read on each node's own Evidence page data.
//!
//! Both nodes run in this process with the plugin's real code: the agreement
//! set up through the bridge, host-shaped payment lifecycle events sealed
//! and turned into settlement legs (the provider's wallet credits each
//! payment in full; no wallet or money is involved), each side's half
//! sealed with the citation its own side decides, and the payer's terms leg
//! pushed to the provider. mesh-llm main accepts only a mainnet wallet for
//! paid inference, so a run between two real hosts would spend real money.

use super::*;
use crate::agreement::{Proposal, SessionTerms, Store};
use crate::agreement_bridge::{conclude, delivered_citation, respond, served_citation, Outcome};
use crate::capsule_emit::{CapsuleState, HostProvenance, ObservedHostExchange};
use crate::lifecycle_channel::DispatchPath;
use crate::settlement_channel::Phase;

const MODEL: &str = "hf:example/exit-gate@main";

fn observed<'a>(
    exchange_id: &'a str,
    request_digest: &'a str,
    path: DispatchPath,
    provenance: HostProvenance,
) -> ObservedHostExchange<'a> {
    ObservedHostExchange {
        model: MODEL,
        exchange_id: Some(exchange_id),
        request_digest: Some(request_digest),
        response_digest: None,
        tool_calls_digest: None,
        reasoning_digest: None,
        usage: None,
        host_provenance: provenance,
        dispatch_path: path,
        nonce: None,
        peer_capsule_id: None,
        peer_capsule_id_provenance: None,
        twin_bracket_id: None,
        response_text_digest: None,
    }
}

/// The payer host's `final_accounted` for `exchange_id`.
fn accounted(node: &CapsuleState, exchange_id: &str, bill_msat: u64) {
    use crate::settlement_channel::{host_shaped_event, parse_and_check};
    let mut body = host_shaped_event(exchange_id, Phase::FinalAccounted, None, None, bill_msat);
    body["role"] = json!("payer");
    body["event_ref"] = json!("");
    body["event_ref"] = json!(crate::producer::jcs::json_digest(&body).unwrap());
    let event = parse_and_check(&serde_json::to_vec(&body).unwrap()).unwrap();
    node.emit_settlement_record(&event.observation()).unwrap();
    node.settlement_legs().on_lifecycle(node, &event);
}

/// Each row's `agreement` on `node`'s own Exchanges pane, by the capsule id
/// of its own half.
fn agreements_by_half(node: &CapsuleState) -> HashMap<String, Value> {
    let pane = super::super::super::build_pane_json("pane-c", node.ledger_dir(), None).unwrap();
    pane["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|row| {
            let id = row["mine"]["capsule_id"].as_str()?;
            Some((id.to_string(), row["agreement"].clone()))
        })
        .collect()
}

#[test]
fn a_paid_session_under_one_agreement_shows_the_exchange_over_the_cap() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let requester = CapsuleState::open(a.path(), "gate-requester").unwrap();
    let provider = CapsuleState::open(b.path(), "gate-provider").unwrap();
    let requester_node = format!("{:064x}", 0x6a7e_0001u64);
    let provider_node = format!("{:064x}", 0x6a7e_0002u64);
    crate::peer_keys::announced::announce_for_test(
        &requester_node,
        &hex::encode(requester.public_key()),
    );
    crate::peer_keys::announced::announce_for_test(
        &provider_node,
        &hex::encode(provider.public_key()),
    );

    // The session, agreed in the minute before the exchanges, so the
    // requester's receipt orders it before every served half.
    let mut now = chrono::Utc::now().timestamp();
    if now % 60 >= 50 {
        std::thread::sleep(std::time::Duration::from_secs((61 - now % 60) as u64));
        now = chrono::Utc::now().timestamp();
    }
    let agreed = now - now % 60 - 60;
    let (rstore, pstore) = (
        Store::open(requester.ledger_dir()),
        Store::open(provider.ledger_dir()),
    );
    let proposal = Proposal::new(
        requester.signing_key(),
        &hex::encode(provider.public_key()),
        &agreement::new_session_id(),
        &SessionTerms {
            spend_cap_msat: 2_500,
            max_exchanges: None,
            window_seconds: 3_600,
        },
        &[MODEL.to_string()],
        agreed,
    );
    let reply = respond(
        &provider,
        &pstore,
        &proposal.to_message(),
        &|_| true,
        agreed,
    );
    let Outcome::Accepted { session, receipt } = conclude(
        &requester,
        &rstore,
        &proposal,
        &serde_json::to_vec(&reply).unwrap(),
        agreed,
    ) else {
        panic!("accepted: {reply}")
    };
    let frame = serde_json::to_vec(&json!({ "receipt": receipt })).unwrap();
    assert_eq!(
        respond(&provider, &pstore, &frame, &|_| true, agreed),
        json!({"ok": true})
    );

    // Three paid exchanges of 1000 msat each against a 2500 msat cap.
    let mut halves = Vec::new();
    for n in 1..=3u64 {
        let (ex, p_ex) = (format!("ex{n}"), format!("p-ex{n}"));
        let hash = format!("{n:064x}");
        let request = format!("{:064x}", 0xabc0 + n);
        lifecycle(
            &provider,
            "provider",
            &p_ex,
            Phase::InputInvoiceIssued,
            &hash,
            &[],
        );
        lifecycle(
            &requester,
            "payer",
            &ex,
            Phase::InputInvoiceIssued,
            &hash,
            &[],
        );
        let wallet = [("credited_msat", 1_000), ("fee_msat", 0)];
        lifecycle(
            &provider,
            "provider",
            &p_ex,
            Phase::InputSettlementObserved,
            &hash,
            &wallet,
        );
        lifecycle(
            &requester,
            "payer",
            &ex,
            Phase::InputSettlementObserved,
            &hash,
            &[("fee_msat", 0)],
        );
        accounted(&requester, &ex, 1_000);

        // Each side decides its citation at the exchange's terminal event,
        // as main.rs does, then seals its half.
        provider
            .settlement_legs()
            .decide_served_citation(&p_ex, || {
                served_citation(&provider, &requester_node, MODEL, now)
            });
        let served = provider
            .emit_for_observed_host_exchange(&observed(
                &p_ex,
                &request,
                DispatchPath::RawProxy,
                HostProvenance {
                    requested_by_node_id: Some(requester_node.clone()),
                    model_canonical_ref: Some(MODEL.to_string()),
                    ..HostProvenance::default()
                },
            ))
            .unwrap();
        requester.settlement_legs().decide_citation(&ex, || {
            delivered_citation(&requester, &provider_node, MODEL, now)
        });
        let requested = requester
            .emit_for_observed_host_exchange(&observed(
                &ex,
                &request,
                DispatchPath::RemoteMesh,
                HostProvenance {
                    served_by_node_id: Some(provider_node.clone()),
                    model_canonical_ref: Some(MODEL.to_string()),
                    ..HostProvenance::default()
                },
            ))
            .unwrap();
        for push in
            requester
                .settlement_legs()
                .on_exchange(&requester, &ex, Some(&provider_node), None)
        {
            provider
                .settlement_legs()
                .on_received(&provider, &push.capsule);
        }
        halves.push((requested.capsule_id, served.capsule_id));
    }

    for (side, node, pick) in [
        ("provider", &provider, 1usize),
        ("requester", &requester, 0usize),
    ] {
        let rows = agreements_by_half(node);
        let labelled: Vec<&Value> = halves
            .iter()
            .map(|h| if pick == 0 { &h.0 } else { &h.1 })
            .map(|id| {
                rows.get(id)
                    .unwrap_or_else(|| panic!("{side}: no row for {id}: {rows:#?}"))
            })
            .collect();
        let coverage: Vec<&str> = labelled
            .iter()
            .map(|a| a["coverage"].as_str().unwrap_or("none"))
            .collect();
        assert_eq!(
            coverage,
            ["covered", "covered", "over_cap"],
            "{side}: {labelled:#?}"
        );
        for (n, a) in labelled.iter().enumerate() {
            assert_eq!(a["side"], json!(side));
            assert_eq!(a["acceptance_digest"], json!(session.acceptance_digest));
            assert_eq!(
                a["spend"]["observed_msat"],
                json!(1_000 * (n as u64 + 1)),
                "{side}: {a:#}"
            );
            assert_eq!(a["spend"]["lower_bound"], json!(false), "{side}: {a:#}");
            assert_eq!(a["spend"]["basis"], json!("agent_origin_assertion"));
        }
        if side == "provider" {
            // The provider holds its own served halves: accepted before the
            // exchange, every requirement met, over the cap included.
            for a in &labelled {
                assert_eq!(a["finding"], json!("accepted_before_action"), "{a:#}");
                assert_eq!(results(a), ["met", "met", "met"], "{a:#}");
            }
        } else {
            // The requester holds no served half here: no finding stated.
            for a in &labelled {
                assert_eq!(
                    a["finding_not_evaluated"],
                    json!(SERVED_HALF_NOT_HELD),
                    "{a:#}"
                );
            }
        }
    }
}
