# Changelog

## Unreleased

### Added

- **Each ask is recorded (loop step 7).** Every evidence request this node sends is sealed as an
  `evidence_request` record, holding the request exactly as sent, before it is sent; a request
  that is not well formed, or reuses a nonce, is refused and never sent. A reply inside the
  waiting window (the later of the request's deadline and 60 s) is sealed as `evidence_response`
  citing the request; none by the close is sealed as `recorded_absence`. A late reply never
  replaces an absence. A node that restarts seals the absences it owes and closes the windows
  still open. The records are evidencebook's (`evidencebook::ask`) and never leave the node in an
  answer. `mesh_commitment_fetch` now holds a peer's commitment that passed every check; an ask
  records the commitment held for the peer, and a signed refusal is checked against the policy
  it pins (`policy_check`: `MISMATCH` when the policy answers it to any asker and the refusal
  withholds it, `MATCH` when the refusal blames the request or the policy does not answer that
  subject, `NOT_CHECKED` with no commitment held, for `policy_declined` or `not_authorized`,
  which honest responders also send for load, size and signature limits, or where the answer
  depends on who asks). Mesh-LLM/capsules-plugin#56.
- **The Service History (`service_history/1`), a Standard History under the inference-service
  history profile.** A requester asks for it by the digest of
  `derivations/service-history-1.json` (`cbc96d80…`), for `full_history`, pinned to a checkpoint
  whose time is a period boundary: Mondays 00:00 UTC from 2026-01-05. The answer embeds this node's
  `history_card/1` artifact byte for byte, with its SHA-256, and counts the exchanges it served in
  each closed week, per model it states and in total. A count under 5 is withheld, and so is the
  smallest other model when the total would give a withheld one away. Latency is never counted.
  Any other subject, coverage or anchor is refused `policy_declined`, the same for every
  requester. The checkpoint cadence now appends one padding record and cuts a checkpoint
  at each boundary. It is Standard History
  (`share_standard_history`), and this node checks a Service History it is sent, the card as a
  direct one and every period rule one History shows. The definition follows
  action-state-group/agent-action-capsule#315 at f8c946ed and the period policy Steven ruled under
  action-state-group/evidencebook#46; `served_summary/1` is unchanged. Ported from
  Mesh-LLM/mesh-llm#2506 (Steven's M2). Mesh-LLM/capsules-plugin#39.
- **`settlement_check` and the Lightning adapter declaration (loop step 6).** The new read-only tool
  checks the Lightning settlement records this node holds for a paid exchange, under
  `adapters/lightning-v0.md`. Each check (object held, invoice join, amount, finality, preimage,
  payee credit) reports `PASS`, `FAIL`, `NOT_PRESENT`, `NOT_CHECKED` or `INCONCLUSIVE` with its
  method. A `finality` `PASS` is the wallet's own report (`wallet_reported`), not a proof, and
  `preimage` is `NOT_PRESENT` because the host never passes one. Each side of an exchange also gets
  the declared predicate `settled` and one value band, `BTC` with a signed decade. The tool reports
  the disclosed count (distinct settlements by payment hash), and the public-ledger count reads
  `NOT_CHECKED`, since Lightning has none. `adapters/x402-v0.md` re-declares x402 under the same
  five items. The tool seals nothing and contacts nobody. Mesh-LLM/capsules-plugin#57.
- **`doctor` and `join` (loop step 12).** `doctor` lists what this node's evidence is: what is
  self-attested, unwitnessed, unchecked, unbound or not shared, one finding each with
  evidencebook's check names and states (`Book.Doctor`), never a score. With `probe`, it asks the
  node's own responder `checkpoints`, then `history_card/1`, as a stranger, in process, and checks
  that each answer verifies under the key the node's commitment advertises (its own key when it
  serves no commitment yet) and that the node answers under the policy that commitment signs. `join` checks that the node is ready to join:
  the key, the book, the first checkpoint, the commitment served on `commitment/1` and both
  probes, listing what is in place and what is not; it is idempotent. Listing the node is still a
  pull request to the evidence network's commitment list. Neither seals, writes or contacts anything; a fresh node's
  first checkpoint follows its first exchange. The quickstart in INSTALL.md is printed by
  `capsules --print-join-quickstart`, and a test holds the two together.
  Mesh-LLM/capsules-plugin#53.
- **The join switch (`join_network`, off by default).** Turned on in the capsules configuration
  pane, under the statement the evidence network publishes (shown word for word), the node signs
  one `join/1` with its plugin key, exactly as evidence-network/loop's `joins/README.md` defines
  it, with no handle or operator name, and sends it to the network's reporter node over the new
  `join/1` plugin channel. Turned off, it sends a signed `leave/1`. It joins once, and again only
  when the statement, the key or the reporter changes. A join that fails is tried again after
  each of the reporter's waits, then not until the switch changes or the plugin restarts; a leave
  is tried again at the last wait until the reporter takes it. The
  reporter is the node loop's `reporter/reporter.json` names (`CAPSULES_JOIN_REPORTER`
  overrides it); while that is all zeros, as now, nothing is sent. A node that is the reporter
  checks each record as loop's `check_join.py` does and keeps each node's latest join and the
  leave that ends it. `join` now shows under `network` the switch, what the reporter
  acknowledged and what it has not yet. Mesh-LLM/capsules-plugin#53.

### Changed

- **Evidence answers, the served summary and the received log come from the `evidencebook` crate
  (0.0.9).** The plugin's own copies are deleted. evidencebook builds and signs every artifact
  answer over the plugin's ledger index, and never opens the MMR node store the checkpointer
  writes. The plugin keeps how a ledger line is read, which requests it answers to whom, and the
  witness keys.
  Every answer is byte for byte what it was, except one change for readers of
  `served_summary/1`. A witness receipt now counts toward `coverage.witnessed` and
  `coverage.witnesses` only if it verifies under the key this node configures for that witness.
  Each receipt is also listed in `coverage.witness_receipts` with `PASS`, `NOT_CHECKED` or
  `FAIL`, and the overall result is in `coverage.witness_check`. A receipt the node cannot check,
  such as one with no configured key, now reads `NOT_CHECKED` instead of counting as witnessed.
  Refusals are still signed by `evidence-request`. The build now carries a second
  `agent-action-capsule` (0.4.1, evidencebook's witness verifier) beside the 0.1.0 the plugin
  already had. action-state-group/evidencebook#35, Mesh-LLM/capsules-plugin#84, #87, #89, #90,
  #91, #92, #93.
- **`share_record_at_completion` is on by default (`counterparty`), reversing the 0.1.3 default.**
  Every node now pushes its sealed record of a completed exchange to the counterparty and accepts
  the counterparty's push, with no setting; `off` still does neither. The record goes only to the
  other side of that exchange; the public checkpoint list shows when exchanges ended.
  `share_adjudications`, `adjudicate_differing_twins`, `share_standard_history` and
  `share_history_segments` keep their defaults. Mesh-LLM/capsules-plugin#68.
- **Pushes and evidence requests are accepted on the sender's evidence key, not the peer id they
  arrive under (D-34).** A half signed by a key this node knows is held whatever peer id the push
  declares, and a push under a known peer id signed by an unknown key is refused
  `signature_unverified`; that refusal now names the refused key (`refused_key_id`) under the
  node's signature. A signed request's asker is every node its key is bound to, so a counterparty
  whose transport id rotated still gets its records. A key is known when a host announced it for
  some peer, when `CAPSULES_PEER_KEYS` lists it under any name (a stopgap for a node with no stable
  peer id, such as a client-only node; it now authenticates requests too), or when the sender
  carries a controller declaration: a `controller-binding/0` record (Controller Binding v0,
  `same_controller_asserted` under `dual_signature/0`, inside its window) binding its key to a key
  known one of the other two ways, in a push bundle's or a signed request's `controller_binding`
  member. A key that a carried declaration binds to the receiving node's own key is refused,
  however else it is known. A served half's named server must be a peer its key is bound to.
  The `counterparty_half` citing record names the sender's key and how it was accepted
  (`sender_key_id`, `accepted_via`: `host_announced`, `operator_stopgap` or
  `controller_declaration`, with the binding's digest); nothing decides on it. A receiver on an
  earlier release refuses a bundle that carries a declaration `bundle_malformed`. Fixtures for each
  case are in `vectors/evidence-key-acceptance/`. Mesh-LLM/capsules-plugin#69.

## 0.1.5

**Milestone M1: who asks for evidence is proven, and a node gets back the record of the exchange it
asked for** (PRD-SERVICE-EVIDENCE §6, R-7 to R-14). **Upgrade both nodes.** Evidence answers are now
the interop profile's signed envelope, which a node on 0.1.4 cannot read, and anchor pins taken from
0.1.4 no longer reproduce. A node on 0.1.4 also sends unsigned requests, which this version refuses
for records (under every setting) and for `served_summary/1` under the default settings. Checkpoints
and `history_card/1` are still answered to anyone.

**Signing needs a host that announces plugin keys (`plugin_keys.v1`, Mesh-LLM/mesh-llm#2299).** No mesh-llm
release has it yet: it is on mesh-llm main and is expected in 0.79.0. On 0.78.1 or older, this
version's requests go out unsigned, so two upgraded nodes answer each other no record, and with the
default settings no `served_summary/1`. Only `share_standard_history = on` keeps answering unsigned
requests for `served_summary/1`; records need a signed request. The records status
(`requests_signed`) shows which case a node is in.

**Updating from mesh-llm 0.78.x:** upgrade mesh-llm to the release that pins capsules 0.1.5, then
run `mesh-llm plugins install-defaults`. It installs from that release's bundled copy and never
downloads; a node whose `capsules` the operator installed themselves (with `mesh-llm plugins
install`, as INSTALL.md describes, or a `[[plugin]]` `command` or `url`) is left as it is and
installs the 0.1.5 package from INSTALL.md.

### Verified on live hosts, and not

- **T3 and T7 passed at PR commit 3902731, whose code is this release's (later commits changed only
  docs), on a lab host built from mesh-llm main
  (b5ed6bd8) plus Mesh-LLM/mesh-llm#2620, not on a stock release.** The signed counterparty record
  came back verified; a node that signed for itself while stating another node's id got a signed
  refusal, with 0 ledger reads; and T7 answers were the same for the counterparty and a stranger.
- **An earlier run, on 2026-10-22, passed on three nodes built from mesh-llm main (95f9b48),** with
  an earlier plugin build (265ede5) and default settings. It predates Mesh-LLM/capsules#50, so its T7 result (a
  signed `policy_declined` for checkpoints and `history_card/1`) no longer describes this version.
- **Not run on a stock mesh-llm release.** No release has `plugin_keys.v1` yet (see above), so a
  stock 0.78.1 host cannot run T3.
- **A referee verdict on live hosts,** which 0.1.4 said would wait on 0.1.5, has still not run. It is
  covered by tests only.
- **Exchange corroboration and the payer's delivered leg for a deposit-covered bill** are covered by
  tests only. Matching both halves of a host-served exchange by client nonce also needs the host to
  pass the nonce on its served terminal event (Mesh-LLM/mesh-llm#2536, on mesh-llm main and in no
  release yet).

### Changed

- **Strangers get no record under `share_history_segments = peers`, and nobody gets an underived
  range or full history.** Under `peers`, a record now goes only to a node whose signature proves
  it, on both `evidence-request/1` and `ledger-fetch/1`. An unsigned request, or one signed by a key
  no host binds, is refused `not_authorized` before the ledger is read, for every subject that
  carries records (`record`, `correlation`, `exchange`, and a fetch by id). Under `peers`, an
  unsigned "Ask them for their record" was answered before and is refused now: the asking node's
  host must announce its key. A `range` or `full_history`
  subject with no derivation is refused `not_authorized` under every setting, to every asker,
  including a counterparty that every record in it names. Checkpoints, `history_card/1`, Standard
  History and `exchange_corroboration/1` are unchanged. This applies evidencebook#114's ruling to
  the plugin.

- **Strangers no longer crowd counterparties out of the evidence answer cap.** A node answers at
  most 8 evidence requests at once from requesters whose signature proves a node, and at most 2
  at once from anyone else (unsigned, or signed by a key no host binds). Each group has its own
  pool, so a full stranger pool declines only strangers, with the same signed `policy_declined`
  as before.

- **A record of an exchange this node served for a peer now names the peer that asked, so that peer
  gets its record back. Operators on `share_history_segments = peers`: your records now show which
  node asked.** mesh-llm reports the node that asked for a host-served exchange
  (`requested_by_node_id`, from the mesh connection, never from the request), but the plugin
  sealed `requesting_party: "unknown"`, so under the default `counterparties` no node could get the
  record of an exchange it asked for.
  - **Now, under the default settings,** the node that asked is that record's counterparty: it gets
    the record (by evidence request or ledger fetch), and it counts as a counterparty for Standard
    History (`served_summary/1`).
  - **Behaviour change under `peers`,** which already serves records to any peer: those records now
    also say which node asked. Nothing named the asker before, so this changes what a node on
    `peers` shares without any setting changing.
  - A node that signs for itself while stating another node's id is still refused `not_authorized`
    before anything is looked up. A record of an exchange this node asked for, one that reached its
    local API, or one from a host that does not report the field still names `"unknown"`.

- **An evidence answer is now the interop profile's signed envelope. Upgrade both nodes.** The
  protocol crate is `evidence-request` `=0.2.0` (what `capsule-emit-evidence-request` became when it
  moved to agent-action-capsule), which signs and checks the envelope of agent-action-capsule's
  `spec/interop-profile-v0.md` §6.2 (`evidence-interop/0`), as the Go, Python and evidencebook
  implementations do. Before, the answer was a pre-profile `{artifact, material, envelope}` that
  no other implementation signed. A node on an older version cannot read the new answer, and this
  node cannot read the old one.
  - **What an anchor is.** A checkpoint is pinned by the SHA-256 of its COSE wire statement (the
    `checkpoint_cose` the checkpointer already writes beside each checkpoint), not by the digest of
    its JSON form. A checkpoint line without its own statement ends the evidence chain there, as
    any checkpoint the index cannot take does: nothing after it is served.
  - **Earlier digests and pins no longer reproduce.** The artifact octets and the anchor both
    changed, so every `artifact_digest` and every anchor pin taken from an earlier version stops
    reproducing. An old anchor names none of this node's checkpoints, so a request pinned to one,
    which would otherwise have been answered, is refused `coverage_unsatisfiable`.
  - **A record answer** is now the record's ledger line itself, with the profile's Checkpointed
    Local Log material for its `capsule_id` (the anchor's statement, the inclusion proof, and the
    consistency proof when the checkpoint extends another). The line is not the `capsule_id`
    preimage, so a profile verifier reports that check `NOT_CHECKED`, never `FAIL`; this node's
    requester recomputes the `capsule_id` and checks the proofs, and also accepts a record served as
    its own octets, which the profile's check passes. The line keeps the producer's signature, which
    the page's "Ask them for their record" checks. The page reads the artifact as the profile
    carries it, unpadded base64url. Before, a record answer was the canonical JSON (RFC 8785) of
    `{anchor, evidence_stream, records, subject}`.
  - **The other answers** take evidencebook's artifact forms (record sets, the checkpoint list,
    `history_card/1`) and `served_summary/1` the same shape. The profile has no material for them
    and no carrier for witness receipts, so this node also sends, where a profile verifier reads
    nothing: the anchor's statement and one inclusion proof per record for a record set, and the
    witness receipts of the checkpoints it carries in a `witness_receipts` member beside the
    envelope. The requester checks all of it as before.
  - The builder stays in the plugin (`evidence_artifact`): evidencebook's builder works over its
    own `CllSubstrate`, which would open the node store the checkpointer owns.
  - A `served_summary/1` answer's verification now reports `records: []`, like every other
    answer, not `0`.
- **`capsule-emit` 0.0.8 and `checkpointed-local-log` 0.3.1**, one CLL line in the build, and no
  `evidencebook`. capsule-emit 0.0.8 turns on `serde_json`'s `arbitrary_precision` for the whole
  binary; the strict parser for pushed bodies (`strict_json`) now reads numbers in that form, still
  refuses a float that overflows, and refuses a key that spells `serde_json`'s private number
  token.
- **The evidence-request parity run is judged by agent-action-capsule's vectors.** The
  self-generated corpus and golden answers are gone from `vectors/parity/evidence_request/`; the
  draft's conformance vectors are copied into `vectors/aac-evidence-request/` (tag
  `crates/evidence-request-v0.2.0`), and the responder and requester are run against them. The
  sharing-policy cases, which no vector states, keep their reviewed expected answers in the
  runner.
- **Who asks for evidence is now proven, not stated. Upgrade both nodes.** Each evidence request
  this node sends is signed with the key its host announces for it. The request carries
  `requester_auth` (`key_id`, `sig`), an `audience` (the node it is sent to), a `nonce` and a
  `deadline`.
  - **Before it looks anything up, a node answering checks:**
    - the signature;
    - that the request is addressed to it;
    - that the nonce is new;
    - that a host announced the key for the node the request comes from.
  - Records and `served_summary/1` are then answered only to that node. The id a request states is
    no longer trusted; if several nodes announced the same key, it picks between them.
  - **Refused:**
    - a request stating one node's id while signed by another;
    - a request addressed to another node, so a node cannot forward a request it received and
      read the answer;
    - a replayed nonce;
    - a deadline more than 5 minutes ahead.
  - **An unsigned request now gets a signed refusal wherever the answer depends on who asks:**
    `not_authorized` for a record, `policy_declined` for `served_summary/1`. It never gets
    silence.
  - **One setting still answers unsigned requests:** `share_standard_history = on`, for
    `served_summary/1`. Under it, a valid signature under a key no host announced is answered as an
    unsigned request, and nothing more. Any other failed check is still refused. No setting answers
    an unsigned request for a record.
  - **A node on 0.1.4 or older sends unsigned requests,** so after you upgrade, its requests for
    your records or `served_summary/1` are refused until it upgrades too.
  - **A node signs only once its host has taken its key.** On a host without `plugin_keys.v1` its
    requests go out unsigned, so an upgraded node no longer answers it any record, and with the
    default settings no `served_summary/1`.
  - **A node that no record names is refused a record before the subject is looked up,** with the
    same refusal for any subject, so the refusal no longer shows how large the log is.
  - **The replay check is held in memory,** so a restart forgets it: a request can be repeated to
    the same node, before its deadline, across a restart.
  - **Keys no host announced share one replay pool** of 16,384 nonces, each held until its
    deadline, and their replay check is best-effort. While the pool is full of live nonces, their
    signed requests are answered as unsigned requests would be, not refused, and logged as
    `replay` `unchecked`; a replay that is detected is still refused. Keys a host announced each
    have their own room, and their replays are always refused.
  - **The "asked of you" log records each request's digest,** the key and node it was proven to
    come from (or `unbound`), the audience it named, and whether its nonce was checked for
    replay.
- **Fetching a record by id (`ledger-fetch/1`) is proven the same way.** The asker signs the
  fetch, and the node answering checks it before it looks the record up. Unless records go to
  any peer (`peers`), a record goes only to the node the signature proves, never to the id the
  fetch states. Under the default
  `share_history_segments` an unsigned fetch, from a node on 0.1.4 or older, is now refused
  `not_authorized`, and so is one under `peers` (see the entry on strangers under `peers`). With
  sharing `off`, a fetch is refused
  before the lookup, so the refusal no longer shows whether the record exists.
- **A referee checks the signature on an `adjudicate` request** before it reads anything. A
  request addressed to another node, changed after signing, past its deadline or replayed is
  refused `not_authorized`. A verdict does not depend on who asks, so an unsigned request is
  answered as before.
- **Each kind of signed request has its own domain tag:** `ledger-fetch/1/requester-auth` for a
  fetch and `referee-adjudicate/1/requester-auth` for an `adjudicate` request, so a signature
  made for one is refused on any other, even where its body would be read there. An evidence
  request's tag is unchanged (`evidence-request/1/requester-auth`).
- **The records status (`evidence_records_status`) says whether this node's requests are
  signed** (`requests_signed`). They are not when its host refused its key or lacks
  `plugin_keys.v1`; its requests then go out unsigned.
- **Standard History is no longer answered to every node that asks; checkpoints and
  `history_card/1` are.** Checkpoints and `history_card/1` are answered to any requester, signed or
  not (Mesh-LLM/capsules#50); `share_standard_history` now governs only `served_summary/1` and other derivations.
  With record push and the checkpoint cadence on, checkpoint times can show when exchanges ended.
  `served_summary/1` goes only to a counterparty (a node one of its records names as the other side
  of an exchange); every other node gets a signed `policy_declined` that carries nothing about the
  asker: it is signed over the request's digest, the reason and the time, so the same request gets
  the same refusal whoever sends it. Before 0.1.5 any node could read it. **After upgrading, a node
  you have never exchanged with can no longer read your served summary** until you set the new
  `share_standard_history` switch to `on` (console: Sharing policy › Standard history; or
  `CAPSULES_SHARE_STANDARD_HISTORY=on`). Your records are unaffected: they stay under
  `share_history_segments`. A counterparty is the node a signed request proves it came from
  (see above).
- **`share_history_segments` defaults to `counterparties`.** `prospective`, the old default, is
  deprecated and read as `counterparties`: it always served exactly the same nodes, so nothing
  changes for a node using it. A log line says when it is read. Set `counterparties` instead.
- **Evidence requests use `capsule-emit-evidence-request` 0.0.4 (was 0.0.3), and witness receipts
  are checked by `scitt-cose-receipt` 0.1.1 from crates.io instead of a git pin.** 0.0.4 changes
  only how a request sent as CBOR is read. This plugin reads requests as JSON, so its answers do not
  change. The receipt check now tries every well-formed inclusion proof in a receipt, not only the
  first, so a receipt that was refused only because of the order of its proofs can now count as
  witnessed on the Evidence page. A proof with an impossible tree size, index or path is refused
  as malformed before any is tried.

### Added

- **Exchange corroboration (`exchange_corroboration/1`), behind a new switch that is off by
  default.** A node can ask whether this node holds a half of one earlier exchange, named by the
  SHA-256 of its client nonce. The answer carries each matching half's id, role and two digests,
  never the record or who was on the other side, and is the same for every node it is given to.
  The new `historical_reference` operation uses it to compare two nodes' halves of one exchange.
  `share_exchange_corroboration` (`CAPSULES_SHARE_EXCHANGE_CORROBORATION`) releases it to a node
  no record names as a counterparty; turning on Standard History does not. See
  `docs/SHARING-POLICY.md`.
- **Witness receipts on an answer are checked under the witness keys you configured:** when this
  node asks another for evidence, each witness receipt carried on the answer's checkpoints is
  checked under the key set for that witness's URL in `CAPSULES_CHECKPOINT_WITNESS_KEYS` (URLs
  matched as for your own checkpoints; only keys you set, not keys pinned on first contact). A
  receipt that does not verify under its witness's key makes the answer not evidence, with reason
  `witness_receipt_unverified`. Receipts on a `served_summary/1` answer are not checked yet. With
  keys set, the result also says how many receipts were verified and each receipt's status. A
  key set for one witness is never used for another. With no keys set, nothing changes: receipts
  are checked for form and for the checkpoint they are on, and none counts as witnessed.
- **`advertise_evidence_requests`, off by default.** Whether this node tells other nodes that it
  answers evidence requests. This version advertises nothing, so nothing reads it yet. A node
  with it off still answers a node that asks.
- The plugin's records status (`sharing`) reports both new switches. The Evidence page does not
  show them yet.
- **A TDX quote in the record, on a TDX host:** when the plugin can take a quote (the kernel's
  configfs-tsm report interface, writable by the plugin's user), each record's `tee_attestation`
  slot carries the quote, its SHA-256 and the 64-byte REPORT_DATA. REPORT_DATA is
  `SHA-512("x-mesh-poc-v1/tee-binding/v1" || 0x00 || request digest || answer digest ||
  SHA-256(client nonce) || the record's signing key)`, each input 32 bytes, the nonce hashed
  exactly as recorded. A quote is taken only for a real client nonce (a host-forwarded one or one
  the client sent to capsules' own `/v1`), never for a placeholder; otherwise the slot says "no
  client nonce". The context says the quote is bound to the exchange's nonce, and fresh against
  the client's challenge only when the record shows the client chose that nonce. A host whose report interface is not TDX, or not usable by the
  plugin's user, records the slot empty exactly as before (the latter is said once in the log).
- **What the node checks before it calls a quote bound, all offline:** the quote's SHA-256; that
  it parses as a TDX DCAP v4 quote; that its REPORT_DATA is the one recomputed from the record; that
  the bound key signs the record; the quote's signature by its attestation key; the QE report's
  signature by the PCK key; that the QE report binds the attestation key; and the PCK certificate
  chain to the Intel SGX Root CA, pinned in the code by its SHA-256, at the record's own time. Any
  failure shows as failed. The Evidence page then says "Quote signed by a TDX quoting enclave and
  bound to this exchange (checked here)", and on its own line that platform status, revocation and
  measurements are not checked here. The checks use `p256` 0.13 (ECDSA P-256) and `x509-cert` 0.2.
- **Each node's key is announced by capsules itself:** on a host that lists `plugin_keys.v1`,
  capsules asks the host at start to announce the public key its records are signed with, so a
  peer verifies this node's pushed records without `CAPSULES_PEER_KEYS` naming it. On an older
  host nothing is sent, and the log says the key was not announced. `CAPSULES_PEER_KEYS` stays the fallback; a peer
  the two sources give different keys still verifies nothing until the stale entry is removed.
- **Built against mesh-llm-plugin from mesh-llm main (a39211e),** which has the announce call;
  no published release has it yet.

### Fixed

- **A paid exchange's CLOSED row no longer reads "served by: not recorded" on the payer's
  Evidence page when the payer's own record names the provider.** The row read the node id the
  page is sent only while the other side's record is still to be fetched, so once that record was
  held the row lost it. It now reads the payer's own record (`served_by_node_id`, the same rule the
  plugin uses), and says "not recorded" only when the record names no server.
- **A half from a model served by a Hugging Face reference is no longer refused `model_mismatch`.**
  The digest inside a `local-gguf/sha256-…` model id is the file's own SHA-256 only for a single
  local file. For a Hugging Face GGUF it hashes the repository, revision and file list, so it was
  read as a second, different weights claim. Weights fields are now held to weights fields and
  model ids to model ids. A half whose two weights fields disagree, or that names another model id
  than the one asked for, is still refused, and the Evidence page applies the same rule.
- **Two providers that gave the same answer to one request are no longer crossed.** Their halves
  were paired by answer alone, so when one provider's half arrived first it could close the record
  of the other, and both exchanges showed as open. A half now first closes the record of its own
  serving node, and the result is the same whatever order the halves arrive in.
- **A ledger fetch reads at most 1 MiB each way.** The node answering read a whole request into
  memory before checking it, and the node asking read a whole answer. An oversized request is now
  dropped unanswered, and an oversized answer is an error.
- **A start that stopped while moving the ledger to a new history finishes the same move next
  time.** It used to pick the next archive slot and seal `history_started` with the wrong archive
  path and a prior record count of zero.
- **A `served_summary/1` answer no longer changes as the log grows past its checkpoint.**
  `adjudications_received` counted every verdict in the log, and took a record as this node's own
  wherever it sat, so a verdict appended after the newest checkpoint changed the summary answered
  for that checkpoint. It now counts only verdicts the checkpoint covers that name a record it
  covers, as the Python reference does. Its note also now reads as the reference's does, so the
  two answer the same bytes.
- **A paid exchange whose deposit covers the bill now gets the payer's delivered settlement leg,**
  citing the deposit invoice (action-state-group/evidencebook#83). The deposit is cited only when
  the bill the host accounted is within it, so a final invoice whose event was lost is never
  replaced by the deposit; that exchange gets no delivered leg.

## 0.1.4

### Verified on live hosts, and not

- **Paid exchanges across two nodes: verified.** Four paid exchanges between two nodes built from
  this release, the requesting node serving no model. In each, the response's `x-mesh-served-by`
  and the record's `served_by` named the serving node, and each node sealed its own half.
- **Peers' keys announced by the host:** exercised only against a test build of the host, not on a
  stock mesh-llm release. `CAPSULES_PEER_KEYS` remains the fallback.
- **The referee with texts the client supplies:** stock hosts now name the node that asked
  (`requested_by_node_id`, from mesh-llm a39211e), so nothing is missing on the host side. A
  referee verdict on live hosts waits on 0.1.5; until then it is covered by tests only.

### Added

- **Each paid exchange on the Evidence page shows what it charged and who paid, from the records
  this node sealed:** the wallet's amount and fee on each settlement (and what it credited, on the
  provider side), the payer's own recorded total, and the provider's delivered-token watermark.
  Each value says who stated it; nothing is summed, and no balance is shown.
- **An exchange this node served for pay shows its own book as the provider,** joined by the
  exchange id the host names a provider's payment events with: who paid, what its wallet reported
  receiving, and what it delivered.
- **"Outcome not reported":** an invoice with no settlement the wallet reported and no final amount
  says so. The host emits no event when a payment's outcome is uncertain or it failed, so the page
  doesn't say which, and never says "unpaid". A paid request refused before any payment (for
  example a payment protocol version the other node doesn't speak) leaves no payment records,
  and the page says that this can happen.
- **Settlement records carry the wallet's `credited_msat` and `fee_msat`** when the host's event
  does; a record from an event without them is unchanged.
- **The referee can take a twin pair's texts from the client** (`referee_supply_twin_texts`: the
  request and both answers), since stock mesh-llm passes no exchange text to plugins. They are
  kept only when the referee is on, the request and each answer are the bodies this node's own
  records sealed, and the answers differ.
- **Peers' keys from the host:** when mesh-llm lists `plugin_keys.v1`, the keys it announces for
  this plugin (`GET /api/plugin-keys`) are merged with `CAPSULES_PEER_KEYS`, which stays the
  fallback. A peer the two give different keys verifies nothing until the stale entry is removed.
- **Twin pairs on Peers:** each peer row states its twin pairs as facts ("Twin pairs: N · answers
  differed: M · not adjudicated"), so a peer whose twin answers differed no longer reads clean
  there.

### Changed

- **The plugin reads and hashes its own executable once per process**, at the first record it
  seals, instead of for every record. Each record still carries that measurement, signed with the
  node key and stamped with the record's own time, so records are unchanged. On macOS the kernel's
  code-signing status is still asked for every record, because it can change while the process
  runs. Replacing the plugin's executable on disk while it runs is measured only after a restart,
  which is also when the new binary starts running.
- **A served exchange with no other side reads LOCAL** ("this node only"), not OPEN, and the state
  filter counts it under "This node only".
- **Each choice setting lists its default first,** so mesh-llm 0.78's console, which does not
  receive declared defaults, shows what the plugin actually does for an unset setting.
- **`capsule-emit-evidence-request` is pinned to `=0.0.3`** from crates.io. An answer to an
  evidence request this node sent is now refused when a witness receipt it carries is malformed or
  not bound to its checkpoint, or when an exchange answer's anchor is not the earliest checkpoint
  covering it. This node holds no witness keys for this check, so no receipt in an answer is
  counted as witnessed. 0.0.3 also signs a refusal over a deterministic encoding, so a refusal
  from a 0.1.3 node may not verify on 0.1.4: upgrade both nodes.

### Fixed

- **The console's top navigation stays on the Evidence page.** The page's stylesheet applies only
  to the page's own elements; a global `.hidden` rule had hidden the console's nav.
- **An exchange this node served for pay is not shown as local.** With no payer recorded, its row
  read "Local — no other side"; it now reads "Served for pay — payer not recorded" and counts as
  open. With no payer recorded there is no node to ask for its record, so such a row may stay open
  until the payer sends its own, and its (i) says so.

## 0.1.3

### Changed

- **Nothing reaches a peer on its own by default.** `share_record_at_completion` (push this node's
  record to the counterparty), `share_adjudications` (deliver verdicts) and
  `adjudicate_differing_twins` (ask a referee, which sends the twins' request to a third node) are
  **off by default**; each turns on only on its explicit value. Answering a peer that asks for a
  record (`share_history_segments`) is unchanged.
- **The stop-routing rule asks the host through the plugin protocol** (`PeerBlockRequest`), so the
  host records the block as this plugin's and refuses it unless the operator set
  `allow_peer_blocks = true` for this plugin. The plugin no longer calls the console's
  `/api/peer-blocks` route (as the operator) for this or for choosing a referee; it learns blocks
  from the host's `routing.choice.v1` publications, and seals its own record of a rule block.
- **The twin pair says what happened:** "A client marked these two requests as one pair", not that
  a comparison ran automatically.
- **Renamed to `capsules`** (plugin id, repository `Mesh-LLM/capsules`, release assets
  `capsules-<version>-<target>.tar.gz`, page `/plugins/capsules/evidence`). Settings are
  `CAPSULES_*`; the old `CAPSULE_EMIT_MESH_*` names are read for this release, with a warning. The
  `ADMISSION_POLICY_*` names are no longer read.
- **An upgraded node keeps its data directory in place** under the old name
  (`capsule-emit-mesh`); nothing is moved, so an upgrade never races a writer that is still
  running. A node with both directories refuses to start and says why. Existing logs keep their
  log id. On Linux the plugin refuses a log another process has open.

### Added

- **A list of witnesses.** The console's `witness` setting is a list of `{ endpoint, public_key }`
  rows, the key optional (the environment's `CAPSULES_CHECKPOINT_WITNESS_URLS` stays a comma list,
  with keys in `CAPSULES_CHECKPOINT_WITNESS_KEYS`, a JSON object from URL to key). There is still no default witness, and no
  witness is contacted until one is named. The Evidence page lists each witness by name with what
  it holds.
- **Receipts are checked before they count.** A witness's receipt counts only when it verifies
  offline: the entry recomputed from the checkpoint's signed fields, and the receipt's inclusion
  proof and signature under the witness's key: the one configured, else one fetched once from that
  witness and kept, which the page labels "pinned on first contact, not configured". An
  unchecked or failing receipt is shown, with the reason, and never counted. A witness that does
  not hold the latest checkpoint (or whose receipt for it does not check) says why: timed out,
  refused, an HTTP error, or a different key.
- **The Evidence page can be a primary tab** (mesh-llm 0.78 and later). The page asks for primary
  placement; the operator turns it on in the console's plugin settings ("Primary tab"), and with it
  off the page stays a navigation item. The page draws its own header, so the host's header is
  turned off for it.
- **Under a chat answer and in the Logs request inspector** (mesh-llm 0.78 and later): whether
  this node sealed that exchange, with a link to its record on the Evidence page. The lookup is
  local (`GET /lookup?exchange_id=` or `?client_nonce=`); nothing is shown when it fails or finds
  no record. It works on the node that asked a peer for the answer. For an exchange this node
  served itself, mesh-llm 0.78 does not give the plugin the ids those views hold, so nothing is
  shown there. On mesh-llm 0.77 the plugin installs and runs as before, without these.

### Fixed

- **The log of requests made of this node never stops the plugin starting.** It is written only to
  a directory that exists when the plugin starts (`CAPSULES_RECEIVED_LOG_DIR`, else
  `<data dir>/received-log`) and that this process holds a lock on; never the ledger directory. A
  directory another node holds, or one that cannot be locked, turns that log off for the run, with
  a warning.
- **A witness is dialled at the URL given.** With capsule-emit 0.0.4, one public witness URL
  (`https://witness.agentactioncapsule.org`) was sent to a different host
  (`anchor.agentactioncapsule.org`). capsule-emit 0.0.6, now required, dials every witness exactly as configured and
  follows no redirect, and the plugin's own witness reads do the same.
- **Settings saved in the console reach the plugin.** The plugin reads its `[plugin.settings]`
  from mesh-llm's config file (`MESH_LLM_CONFIG`, or `~/.mesh-llm/config.toml`); the environment
  still wins. The console's `witness` is the checkpoint witness, and the witness client uses it.
- **One plugin process per data directory.** A second process on the same directory refuses to
  start instead of interleaving appends and breaking the chain.

## 0.1.2

### Fixed

- **The plugin serves no models unless asked.** 0.1.1 registered an OpenAI-compatible inference
  provider on every node and, with `CAPSULE_EMIT_MESH_BLOCKED_MODELS` unset or empty, advertised
  `blocked-test-model` through it. That model always answers 403, so a client that takes the first
  model `/v1/models` lists, or "Mesh automatic" routing, could pick it. From 0.1.2 the admission
  endpoint is opt-in: only when `CAPSULE_EMIT_MESH_BLOCKED_MODELS` names models does the plugin
  register the provider and declare `admission_policy.v1`. Unset, empty, `none` or `off`: no
  provider, no admission capability, no models. The plugin seals records and serves the Evidence
  page.

## 0.1.1

### Added

- **Settlement-record legs for paid exchanges** (draft-mih-agent-settlement-records-00). For each
  invoice of a paid exchange, both sides now seal the draft's legs beside the existing payment
  lifecycle trail. The payer seals the terms leg (invoice amount, `ln.payment_hash`) and pushes it
  to the serving peer, then seals `payer_observed` (the amount, plus `routing_fee` when the host
  passes the wallet's fee) and a delivered leg with the response digest. The provider seals
  `payee_observed` (`received`, `receive_fee`), citing the payer's terms leg.
  - **Host requirement:** the provider's leg needs a mesh-llm host whose settlement events carry
    the wallet's credited amount and fee (Mesh-LLM/mesh-llm#2169). On a host without it, the
    provider seals no payee leg; the payer's legs and pushed terms work either way.
  - `routing_fee` and `receive_fee` are new on ledger records. Peers may read them back under the
    default share policy, like the amounts the trail already carried.

### Fixed

- **A node-unique default log id.** Every node's checkpoints used the same log id, so a witness
  accepted the first node and refused the rest as a fork. The default is now
  `capsule-emit-mesh/<key id>`, chosen at first start and kept in `<data dir>/log_id`;
  `CAPSULE_EMIT_MESH_LOG_ID` overrides it. A log that already holds checkpoints keeps its id, and
  starting a new log moves the node to its own id (see INSTALL.md, "The log's id").
- **Finding a served half by its digests.** When the host forwarded no nonce, the serving node's
  half couldn't be found by the requester's nonce, so the exchange showed as open. The responder
  now also indexes each record by its exchange's two effect digests, and the page asks by those
  after a signed "no such record". Both nodes need 0.1.1 for this.
- **The witness indicator.** The Evidence page could say "witness off" on a node whose checkpoints
  carried witness receipts. It now reads how many checkpoints a witness holds and whether a
  witness is configured, and says "off" only when no witness is set.

## 0.1.0

- First release.
