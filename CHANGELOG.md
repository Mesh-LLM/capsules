# Changelog

## Unreleased

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
