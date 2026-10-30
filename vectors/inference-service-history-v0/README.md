# Inference-Service History v0: conformance vectors

These vectors exercise `spec/inference-service-history-profile-v0.md` (cited as the profile) over
`spec/interop-profile-v0.md` (`evidence-interop/0`, cited as IP). They cover:

- a served-only Standard History, with requested exchanges counted in no cell;
- the period rules: overlapping, duplicated, open and short periods, a first, a middle and a last
  period left out, an answer at an anchor inside an open period, a cell below the floor, a missing
  complementary suppression, and a closed period changed or dropped between two anchors;
- peer confirmation at the Detailed level, and labels: `self_reported`, `peer_confirmed`, and
  `corroborated`, which no case derives;
- refusals: an interval that is not a run of whole periods (`policy_declined`, the same for two
  requesters), an anchor that is not a period boundary (`policy_declined`), and a Detailed History asked by a requester it does not name (`policy_declined`, so
  the refusal does not show that the node holds a Detailed History for anyone).

Every case cites the sections its expected values come from. The profile's §9.4 lists every case.

## Derivation

`python/scripts/generate_inference_service_history_v0_vectors.py` writes every file except this
README. It mints one node's stream itself, uses no repository implementation, and states every
expected status by hand from the profile text. Every case's `source` is `constructed`, with the
change from the positive it is built from where there is one.

`python/tests/test_inference_service_history_v0_vectors.py` checks the corpus from the case inputs
alone:

- It runs every request and reply through the IP reference verifier
  (`agent_action_capsule.interop_profile`).
- It derives the profile's History properties (§8.3), coverage report (§4.2), witness receipts
  shown (§5.2), exchange labels (§7.2) and `period_fixed` (§6.3) with its own evaluator.
- It compares all of them with the case's whole `expected` block.
- It runs defective evaluators, each of which must disagree with at least one case.
- It regenerates the directory twice and requires both runs to be byte-identical to the committed
  files.

## Formats fixed for these vectors only, not registered (profile §9, SH-12)

| Format | What it is |
|---|---|
| `service_history_example/0` | a Standard definition: `history_card` and `period_counts` (unit `exchanges_served`), period policy of one day from 2026-10-01, floor 5 |
| `service_history_detail_example/0` | a Detailed definition: `history_card` and `exchanges`, recipient `principal:recipient-example` |
| history card | `{anchor, derivation, evidence_stream, history, subject}`; each `history` entry is `{checkpoint, receipts}`; a checkpoint is `{key_id, log_size, root, timestamp, sig}` and a receipt `{checkpoint, witness, sig}`, each `sig` Ed25519 over UTF-8 of JCS of the other members. A checkpoint's digest is SHA-256 of UTF-8 of JCS of the whole checkpoint |
| period counts | `{policy, periods: [{from, to, cells: [{unit, label, dimension, value, suppressed?}]}]}`; `dimension` is null on a unit's total |
| half | `{client_nonce, committed_at, producer, role, references?, sig}`; the node's half cites the peer's by a `references` entry `{citation_purpose: "counterparty_half", digest}` |

Roots are label digests and no consistency proof is carried, so these vectors do not check the
card's consistency. `pins.service_history` holds the relying party's log, witness and peer keys,
which IP's trust policy does not name.

## Files

- `vectors.json`: the corpus (`count` cases), with the test keys, the contract and the period
  policy.
- `manifest.json`: the files and their digests.
- `SHA256SUMS`: every file in this directory.
