use super::*;

/// loop's fixtures (`tests/fixtures/join/`), signed with its rehearsal TEST
/// keys at 2026-10-27T20:00:00Z (the leave an hour later).
fn fixture(name: &str) -> Value {
    let raw = match name {
        "good-join" => include_str!("../../../../loop/tests/fixtures/join/good-join.json"),
        "good-leave" => include_str!("../../../../loop/tests/fixtures/join/good-leave.json"),
        "forged-join" => include_str!("../../../../loop/tests/fixtures/join/forged-join.json"),
        "forged-join-own-key" => {
            include_str!("../../../../loop/tests/fixtures/join/forged-join-own-key.json")
        }
        "stale-consent-join" => {
            include_str!("../../../../loop/tests/fixtures/join/stale-consent-join.json")
        }
        "nodes-consent-join" => {
            include_str!("../../../../loop/tests/fixtures/join/nodes-consent-join.json")
        }
        "handle-join" => include_str!("../../../../loop/tests/fixtures/join/handle-join.json"),
        other => panic!("no fixture {other}"),
    };
    serde_json::from_str(raw).unwrap()
}

fn time(s: &str) -> DateTime<Utc> {
    parse_at(s).unwrap()
}

const FIXTURE_NOW: &str = "2026-10-28T00:00:00Z";

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn node(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

#[test]
fn the_statement_is_loops_byte_for_byte() {
    // sha256 of loop's joins/SWITCH_CONSENT.txt at LOOP_REVISION, and the
    // digest loop's own fixtures sign.
    assert_eq!(
        consent_sha256(),
        "86c106c3080912e6b6e6a25fb86f804621ffd82c91dab1db8119b69fb72f5be6"
    );
    assert_eq!(
        fixture("good-join")["consent_sha256"],
        consent_sha256().as_str()
    );
    assert!(SWITCH_CONSENT.ends_with(
        "To leave, turn this switch off: the asks stop on the next run, and past reports stay."
    ));
    assert!(include_str!("../../../../loop/README.md").contains(LOOP_REVISION));
}

#[test]
fn the_check_judges_loops_fixtures_as_check_join_does() {
    let now = time(FIXTURE_NOW);
    for good in ["good-join", "good-leave"] {
        assert_eq!(
            problems(&fixture(good), now),
            Vec::<String>::new(),
            "{good}"
        );
    }
    for (bad, why) in [
        ("forged-join", "signature does not verify under spki"),
        ("forged-join-own-key", "key_id is not the key in spki"),
        ("stale-consent-join", "consent_sha256 is not the digest"),
        ("nodes-consent-join", "consent_sha256 is not the digest"),
        ("handle-join", "unknown field handle"),
    ] {
        let errs = problems(&fixture(bad), now);
        assert!(errs.iter().any(|e| e.starts_with(why)), "{bad}: {errs:?}");
    }
}

#[test]
fn a_signed_join_passes_and_any_change_to_it_does_not() {
    let now = time("2026-10-28T12:00:00Z");
    let doc = record(KIND_JOIN, &node(1), &key(1), "2026-10-28T12:00:00Z");
    assert_eq!(problems(&doc, now), Vec::<String>::new());
    assert_eq!(doc["key_id"], commitment::key_id(&key(1)).as_str());
    assert!(doc.get("handle").is_none() && doc.as_object().unwrap().len() == 7);

    let mut moved = doc.clone();
    moved["node_id"] = json!(node(2));
    assert_eq!(
        problems(&moved, now),
        ["signature does not verify under spki"]
    );
    let mut missing = doc.clone();
    missing.as_object_mut().unwrap().remove("at");
    assert_eq!(problems(&missing, now), ["missing at"]);
    let mut kind = record("hello/1", &node(1), &key(1), "2026-10-28T12:00:00Z");
    assert_eq!(
        problems(&kind, now),
        ["kind must be one of join/1, leave/1"]
    );
    kind["at"] = json!("2026-02-30T00:00:00Z");
    assert!(problems(&kind, now)
        .iter()
        .any(|e| e.starts_with("at must be")));
    assert_eq!(problems(&json!([]), now), ["not a JSON object"]);
}

#[test]
fn a_record_more_than_five_minutes_ahead_is_refused() {
    let now = time("2026-10-28T12:00:00Z");
    let edge = record(KIND_JOIN, &node(1), &key(1), "2026-10-28T12:05:00Z");
    assert!(problems(&edge, now).is_empty());
    let ahead = record(KIND_JOIN, &node(1), &key(1), "2026-10-28T12:05:01Z");
    assert_eq!(
        problems(&ahead, now),
        ["at 2026-10-28T12:05:01Z is in the future"]
    );
}

#[test]
fn nothing_is_sent_while_the_reporter_is_all_zeros() {
    // The pinned file names no reporter yet.
    assert_eq!(reporter_from(None), None);
    assert_eq!(reporter_from(Some("  ")), None);
    assert_eq!(reporter_from(Some(&"0".repeat(64))), None);
    assert_eq!(reporter_from(Some("not-a-node")), None);
    let id = node(0xab);
    assert_eq!(reporter_from(Some(&id.to_ascii_uppercase())), Some(id));
    assert_eq!(retry_after(), [3600, 10800, 21600]);
}

fn acked(kind: &str, key: &SigningKey, reporter: &str) -> Acked {
    Acked {
        record: record(kind, &node(1), key, "2026-10-28T12:00:00Z"),
        reporter: reporter.into(),
        acknowledged: true,
    }
}

#[test]
fn a_node_joins_once_and_leaves_only_after_a_join() {
    let (k, r) = (key(1), node(9));
    let key_id = commitment::key_id(&k);
    let me = node(1);
    let join = Due::Join(r.clone());
    // Off and never joined: nothing. On: a join, until one is acknowledged.
    assert_eq!(due(false, None, &key_id, &me, Some(&r)), Due::Nothing);
    assert_eq!(due(true, None, &key_id, &me, Some(&r)), join);
    assert_eq!(due(true, None, &key_id, &me, None), Due::Nothing);
    let joined = acked(KIND_JOIN, &k, &r);
    assert_eq!(
        due(true, Some(&joined), &key_id, &me, Some(&r)),
        Due::Nothing
    );
    // Again when the key or the reporter changes.
    assert_eq!(
        due(
            true,
            Some(&joined),
            &commitment::key_id(&key(2)),
            &me,
            Some(&r)
        ),
        join
    );
    assert_eq!(
        due(true, Some(&joined), &key_id, &me, Some(&node(8))),
        Due::Join(node(8))
    );
    // Off after a join: a leave, to the reporter that took it.
    assert_eq!(
        due(false, Some(&joined), &key_id, &me, Some(&node(8))),
        Due::Leave(r.clone())
    );
    assert_eq!(
        due(false, Some(&joined), &key_id, &me, None),
        Due::Leave(r.clone())
    );
    let left = acked(KIND_LEAVE, &k, &r);
    assert_eq!(
        due(false, Some(&left), &key_id, &me, Some(&r)),
        Due::Nothing
    );
    assert_eq!(due(true, Some(&left), &key_id, &me, Some(&r)), join);
    // A join under another statement is joined again.
    let mut stale = joined.clone();
    stale.record["consent_sha256"] = json!("0".repeat(64));
    assert_eq!(due(true, Some(&stale), &key_id, &me, Some(&r)), join);
}

#[test]
fn a_failed_send_is_tried_after_each_wait_and_then_no_more() {
    let start = std::time::Instant::now();
    let join = Due::Join(node(9));
    let mut tries = Tries::default();
    let mut at = start;
    let mut sent = 0;
    for wait in retry_after() {
        assert!(tries.may_send(&join, at));
        sent += 1;
        assert!(tries.failed(at));
        assert!(!tries.may_send(&join, at + Duration::from_secs(wait - 1)));
        at += Duration::from_secs(wait);
    }
    assert!(tries.may_send(&join, at));
    sent += 1;
    assert!(!tries.failed(at));
    assert!(!tries.may_send(&join, at + Duration::from_secs(10 * 86_400)));
    assert_eq!(sent, 1 + retry_after().len());
    // Turning the switch off starts the leave's own tries.
    assert!(tries.may_send(&Due::Leave(node(9)), at));
}

#[test]
fn a_leave_is_never_given_up() {
    // The statement promises that turning the switch off stops the asks.
    let leave = Due::Leave(node(9));
    let waits = retry_after();
    let last = Duration::from_secs(*waits.last().unwrap());
    let mut tries = Tries::default();
    let mut at = std::time::Instant::now();
    for wait in waits
        .iter()
        .map(|s| Duration::from_secs(*s))
        .chain([last; 5])
    {
        assert!(tries.may_send(&leave, at));
        assert!(tries.failed(at));
        assert!(!tries.may_send(&leave, at + wait - Duration::from_secs(1)));
        at += wait;
    }
    assert!(tries.may_send(&leave, at));
}

#[test]
fn join_shows_what_the_reporter_has_not_acknowledged() {
    let dir = tempfile::tempdir().unwrap();
    let key_id = commitment::key_id(&key(1));
    // The switch is off in tests and nothing was ever joined.
    assert_eq!(
        status(dir.path(), &key_id, None)["unacknowledged"],
        Value::Null
    );
    save(dir.path(), &acked(KIND_JOIN, &key(1), &node(9))).unwrap();
    let status = status(dir.path(), &key_id, None);
    assert_eq!(status["switch"], "off");
    assert_eq!(status["unacknowledged"], KIND_LEAVE);
    assert_eq!(status["acknowledged"]["kind"], KIND_JOIN);
}

#[test]
fn the_acknowledged_record_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(load(dir.path()), None);
    let joined = acked(KIND_JOIN, &key(1), &node(9));
    save(dir.path(), &joined).unwrap();
    assert_eq!(load(dir.path()), Some(joined));
}

struct Reporter {
    dir: tempfile::TempDir,
}

impl Reporter {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn take_with(&self, doc: &Value, registry: Option<&str>) -> Result<(), String> {
        let me = node(9);
        intake(
            &serde_json::to_vec(doc).unwrap(),
            Some(&me),
            Some(&me),
            registry,
            self.dir.path(),
            time("2026-10-29T00:00:00Z"),
        )
    }

    fn take(&self, doc: &Value) -> Result<(), String> {
        self.take_with(doc, None)
    }

    fn files(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(self.dir.path().join(JOINS_DIR))
            .map(|d| {
                d.map(|e| e.unwrap().file_name().into_string().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn held(&self, name: &str) -> Value {
        serde_json::from_slice(&std::fs::read(self.dir.path().join(JOINS_DIR).join(name)).unwrap())
            .unwrap()
    }
}

fn signed(kind: &str, key: &SigningKey, at: &str) -> Value {
    record(kind, &node(1), key, at)
}

#[test]
fn only_the_reporter_takes_a_join() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = serde_json::to_vec(&signed(KIND_JOIN, &key(1), "2026-10-28T12:00:00Z")).unwrap();
    let now = time("2026-10-29T00:00:00Z");
    let r = node(9);
    for (me, reporter) in [
        (None, Some(r.as_str())),
        (Some(node(8)), Some(r.as_str())),
        (Some(r.clone()), None),
    ] {
        assert_eq!(
            intake(&bytes, me.as_deref(), reporter, None, dir.path(), now),
            Err("this node is not the reporter".into())
        );
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn the_reporter_keeps_the_latest_join_and_the_leave_that_ends_it() {
    let reporter = Reporter::new();
    let join = signed(KIND_JOIN, &key(1), "2026-10-28T12:00:00Z");
    let leave = signed(KIND_LEAVE, &key(1), "2026-10-28T13:00:00Z");
    assert_eq!(reporter.take(&join), Ok(()));
    // The same join again changes nothing.
    assert_eq!(reporter.take(&join), Ok(()));
    let n = node(1);
    assert_eq!(reporter.files(), [format!("{n}.join.json")]);
    assert_eq!(reporter.held(&format!("{n}.join.json")), join);

    assert_eq!(reporter.take(&leave), Ok(()));
    assert_eq!(reporter.take(&leave), Ok(()));
    assert_eq!(
        reporter.files(),
        [format!("{n}.join.json"), format!("{n}.leave.json")]
    );
    // A join older than the leave held is a replay.
    assert_eq!(
        reporter.take(&signed(KIND_JOIN, &key(1), "2026-10-28T12:30:00Z")),
        Err("a later leave of this node is held".into())
    );
    // Rejoining drops the leave.
    let rejoin = signed(KIND_JOIN, &key(1), "2026-10-28T14:00:00Z");
    assert_eq!(reporter.take(&rejoin), Ok(()));
    assert_eq!(reporter.files(), [format!("{n}.join.json")]);
    assert_eq!(reporter.held(&format!("{n}.join.json")), rejoin);
    assert_eq!(
        reporter.take(&join),
        Err("a later join of this node is held".into())
    );
}

#[test]
fn a_leave_must_follow_its_join_under_its_key() {
    let reporter = Reporter::new();
    reporter
        .take(&signed(KIND_JOIN, &key(1), "2026-10-28T12:00:00Z"))
        .unwrap();
    assert_eq!(
        reporter.take(&signed(KIND_LEAVE, &key(1), "2026-10-28T11:00:00Z")),
        Err("the leave at 2026-10-28T11:00:00Z is older than its join".into())
    );
    assert_eq!(
        reporter.take(&signed(KIND_LEAVE, &key(2), "2026-10-28T13:00:00Z")),
        Err("the leave is signed by another key than its join".into())
    );
    assert_eq!(reporter.files().len(), 1);
}

#[test]
fn the_reporter_refuses_a_record_the_check_refuses_or_another_key_than_announced() {
    let reporter = Reporter::new();
    let forged = fixture("forged-join");
    assert_eq!(
        reporter.take(&forged),
        Err("signature does not verify under spki".into())
    );
    assert!(reporter
        .take_with(&json!({"kind": "join/1"}), None)
        .unwrap_err()
        .contains("missing node_id"));
    let join = signed(KIND_JOIN, &key(1), "2026-10-28T12:00:00Z");
    let announced = |key_id: String| json!({ node(1): key_id }).to_string();
    assert_eq!(
        reporter.take_with(&join, Some(&announced(commitment::key_id(&key(2))))),
        Err("key_id is not the key the host announced for node_id".into())
    );
    assert!(reporter.files().is_empty());
    assert_eq!(
        reporter.take_with(&join, Some(&announced(commitment::key_id(&key(1))))),
        Ok(())
    );
}

#[test]
fn a_directory_the_reporter_keeps_passes_loops_order_check() {
    // check_join.py's order rule over the directory: every leave has a join
    // of its node at or before it, under the same key.
    let reporter = Reporter::new();
    for (k, kind, at) in [
        (1, KIND_JOIN, "2026-10-28T10:00:00Z"),
        (1, KIND_LEAVE, "2026-10-28T11:00:00Z"),
        (1, KIND_JOIN, "2026-10-28T12:00:00Z"),
        (1, KIND_LEAVE, "2026-10-28T13:00:00Z"),
    ] {
        reporter.take(&signed(kind, &key(k), at)).unwrap();
    }
    let n = node(1);
    let (join, leave) = (
        reporter.held(&format!("{n}.join.json")),
        reporter.held(&format!("{n}.leave.json")),
    );
    assert_eq!(join["at"], "2026-10-28T12:00:00Z");
    assert!(at_of(&join) <= at_of(&leave) && join["key_id"] == leave["key_id"]);
}

#[test]
fn a_held_node_moves_to_another_key_only_when_the_host_announced_it() {
    let reporter = Reporter::new();
    reporter
        .take(&signed(KIND_JOIN, &key(1), "2026-10-28T12:00:00Z"))
        .unwrap();
    let other = signed(KIND_JOIN, &key(2), "2026-10-28T13:00:00Z");
    assert_eq!(
        reporter.take(&other),
        Err("this node is held under another key, and the host announced none for it".into())
    );
    // A leave under the other key is refused too, so it cannot end the join.
    assert!(reporter
        .take(&signed(KIND_LEAVE, &key(2), "2026-10-28T13:00:00Z"))
        .is_err());
    let announced = json!({ node(1): commitment::key_id(&key(2)) }).to_string();
    assert_eq!(reporter.take_with(&other, Some(&announced)), Ok(()));
    assert_eq!(reporter.held(&format!("{}.join.json", node(1))), other);
}

#[test]
fn the_reporter_holds_at_most_max_nodes() {
    let reporter = Reporter::new();
    let joins = reporter.dir.path().join(JOINS_DIR);
    std::fs::create_dir_all(&joins).unwrap();
    for n in 0..MAX_NODES {
        std::fs::write(joins.join(format!("{n:064x}.join.json")), b"{}").unwrap();
    }
    assert_eq!(
        reporter.take(&signed(KIND_JOIN, &key(1), "2026-10-28T12:00:00Z")),
        Err(format!(
            "the reporter holds {MAX_NODES} nodes, the most it takes"
        ))
    );
}

#[test]
fn a_new_mesh_id_leaves_the_old_one_first_then_joins() {
    // A client node's mesh id is new each start.
    let (k, r) = (key(1), node(9));
    let key_id = commitment::key_id(&k);
    let joined = acked(KIND_JOIN, &k, &r);
    assert_eq!(
        due(true, Some(&joined), &key_id, &node(2), Some(&r)),
        Due::Leave(r.clone())
    );
    assert_eq!(
        due(false, Some(&joined), &key_id, &node(2), Some(&r)),
        Due::Leave(r.clone())
    );
    // A former reporter is not chased: the new id joins the one in force.
    assert_eq!(
        due(true, Some(&joined), &key_id, &node(2), Some(&node(8))),
        Due::Join(node(8))
    );
}

fn now(utc: &str) -> Now {
    Now {
        instant: std::time::Instant::now(),
        utc: time(utc),
    }
}

/// Ticks of a node that is its own reporter: every record goes through
/// the reporter's own intake, never `send`.
async fn tick_self(
    node_id: &str,
    dir: &Path,
    on: bool,
    at: &str,
    tries: &mut Tries,
) -> Option<Result<(), String>> {
    let k = key(1);
    let this = Node {
        key: &k,
        node_id,
        data_dir: dir,
    };
    let reporter = node(9);
    tick_once(
        &this,
        on,
        Some(&reporter),
        None,
        tries,
        now(at),
        |_, _| async { panic!("a node that is the reporter sends nothing over the mesh") },
    )
    .await
}

#[tokio::test]
async fn a_node_that_is_the_reporter_takes_its_own_join_and_leave() {
    let dir = tempfile::tempdir().unwrap();
    let mut tries = Tries::default();
    let me = node(9);
    assert_eq!(
        tick_self(&me, dir.path(), true, "2026-10-28T12:00:00Z", &mut tries).await,
        Some(Ok(()))
    );
    assert_eq!(load(dir.path()).unwrap().record["kind"], KIND_JOIN);
    // Joined: nothing more is due while the switch stays on.
    assert_eq!(
        tick_self(&me, dir.path(), true, "2026-10-28T12:01:00Z", &mut tries).await,
        None
    );
    assert_eq!(
        tick_self(&me, dir.path(), false, "2026-10-28T12:02:00Z", &mut tries).await,
        Some(Ok(()))
    );
    let leave = load(dir.path()).unwrap().record;
    assert_eq!(
        (leave["kind"].as_str(), leave["node_id"].as_str()),
        (Some(KIND_LEAVE), Some(me.as_str()))
    );
    assert!(dir
        .path()
        .join(JOINS_DIR)
        .join(format!("{me}.leave.json"))
        .is_file());
}

#[tokio::test]
async fn a_leave_names_the_joined_id_and_is_never_older_than_the_join() {
    let dir = tempfile::tempdir().unwrap();
    let r = node(9);
    let k = key(1);
    // The reporter took a join of node(1) at 12:00.
    save(dir.path(), &acked(KIND_JOIN, &k, &r)).unwrap();
    let this = Node {
        key: &k,
        node_id: &node(2),
        data_dir: dir.path(),
    };
    let sent = std::sync::Mutex::new(None);
    let mut tries = Tries::default();
    // A clock behind the join, and a new mesh id: the leave still names the
    // joined id, at the join's time.
    let outcome = tick_once(
        &this,
        true,
        Some(&r),
        None,
        &mut tries,
        now("2026-10-28T11:00:00Z"),
        |to, doc| {
            *sent.lock().unwrap() = Some((to, doc));
            async { Ok(()) }
        },
    )
    .await;
    assert_eq!(outcome, Some(Ok(())));
    let (to, doc) = sent.into_inner().unwrap().unwrap();
    assert_eq!(to, r);
    assert_eq!(doc["kind"], KIND_LEAVE);
    assert_eq!(doc["node_id"], node(1).as_str());
    assert_eq!(doc["at"], "2026-10-28T12:00:00Z");
    assert!(problems(&doc, time("2026-10-28T12:00:00Z")).is_empty());
    assert_eq!(load(dir.path()).unwrap().record, doc);
}

#[tokio::test]
async fn turning_the_switch_off_and_on_starts_a_join_over() {
    let dir = tempfile::tempdir().unwrap();
    let k = key(1);
    let r = node(9);
    let this = Node {
        key: &k,
        node_id: &node(1),
        data_dir: dir.path(),
    };
    let mut tries = Tries::default();
    let at = now("2026-10-28T12:00:00Z");
    let fail = |_: String, _: Value| async { Err::<(), String>("down".into()) };
    for _ in 0..=retry_after().len() {
        tries.next = None; // as if each wait had passed
        assert!(tick_once(&this, true, Some(&r), None, &mut tries, at, fail)
            .await
            .is_some());
    }
    assert_eq!(
        tick_once(&this, true, Some(&r), None, &mut tries, at, fail).await,
        None,
        "given up"
    );
    // Off: the join may have arrived, so a leave is tried (its own tries).
    assert_eq!(
        tick_once(&this, false, Some(&r), None, &mut tries, at, fail).await,
        Some(Err("down".into()))
    );
    // On again: the join's tries start over.
    assert!(tick_once(&this, true, Some(&r), None, &mut tries, at, fail)
        .await
        .is_some());
}

#[tokio::test]
async fn a_join_whose_reply_was_lost_is_still_left() {
    let dir = tempfile::tempdir().unwrap();
    let (k, r) = (key(1), node(9));
    let this = Node {
        key: &k,
        node_id: &node(1),
        data_dir: dir.path(),
    };
    let mut tries = Tries::default();
    let at = now("2026-10-28T12:00:00Z");
    // The reporter kept the join, but its reply never came back.
    let lost = tick_once(&this, true, Some(&r), None, &mut tries, at, |_, _| async {
        Err::<(), String>("the reporter did not reply in time".into())
    })
    .await;
    assert!(matches!(lost, Some(Err(_))));
    let kept = load(dir.path()).unwrap();
    assert_eq!(
        (kept.record["kind"].as_str(), kept.acknowledged),
        (Some(KIND_JOIN), false)
    );
    assert_eq!(
        status(dir.path(), &commitment::key_id(&k), Some(&node(1)))["acknowledged"],
        Value::Null
    );
    // Switched off (after a restart, too): the leave goes.
    let mut tries = Tries::default();
    let sent = std::sync::Mutex::new(None);
    let left = tick_once(&this, false, Some(&r), None, &mut tries, at, |_, doc| {
        *sent.lock().unwrap() = Some(doc);
        async { Ok(()) }
    })
    .await;
    assert_eq!(left, Some(Ok(())));
    assert_eq!(sent.into_inner().unwrap().unwrap()["kind"], KIND_LEAVE);
    assert!(load(dir.path()).unwrap().acknowledged);
    // A leave that was not acknowledged is sent again.
    let mut unacked = load(dir.path()).unwrap();
    unacked.acknowledged = false;
    assert_eq!(
        due(
            false,
            Some(&unacked),
            &commitment::key_id(&k),
            &node(1),
            Some(&r)
        ),
        Due::Leave(r.clone())
    );
    assert_eq!(
        due(
            true,
            Some(&unacked),
            &commitment::key_id(&k),
            &node(1),
            Some(&r)
        ),
        Due::Join(r)
    );
}

#[test]
fn keys_that_disagree_are_not_no_key() {
    let reporter = Reporter::new();
    let join = signed(KIND_JOIN, &key(1), "2026-10-28T12:00:00Z");
    // `peer_keys::merged` gives a peer an empty key when the host's
    // announcement and the configured key disagree.
    let conflict = json!({ node(1): "" }).to_string();
    assert_eq!(
        reporter.take_with(&join, Some(&conflict)),
        Err("the keys this node holds for node_id disagree".into())
    );
    assert_eq!(
        reporter.take_with(&join, Some("not json")),
        Err("the keys this node holds cannot be read".into())
    );
    let others_only = json!({ node(2): commitment::key_id(&key(2)) }).to_string();
    assert_eq!(reporter.take_with(&join, Some(&others_only)), Ok(()));
}

#[test]
fn a_leave_before_any_join_refuses_the_join_it_ends_and_is_never_listed() {
    let reporter = Reporter::new();
    let n = node(1);
    let join = signed(KIND_JOIN, &key(1), "2026-10-28T12:00:00Z");
    let leave = signed(KIND_LEAVE, &key(1), "2026-10-28T13:00:00Z");
    // The leave arrives first: taken, kept apart from the list.
    assert_eq!(reporter.take(&leave), Ok(()));
    assert_eq!(reporter.take(&leave), Ok(()));
    assert!(reporter.files().is_empty());
    assert!(reporter
        .dir
        .path()
        .join(ENDED_DIR)
        .join(format!("{n}.json"))
        .is_file());
    // The join it ends, late or replayed, is refused; another key's is not
    // ended by it.
    assert_eq!(
        reporter.take(&join),
        Err("a later leave of this node is held".into())
    );
    let other = signed(KIND_JOIN, &key(2), "2026-10-28T12:30:00Z");
    assert_eq!(reporter.take(&other), Ok(()));
    // A later join of the same key is a rejoin.
    let reporter = Reporter::new();
    reporter.take(&leave).unwrap();
    let rejoin = signed(KIND_JOIN, &key(1), "2026-10-28T14:00:00Z");
    assert_eq!(reporter.take(&rejoin), Ok(()));
    assert_eq!(reporter.files(), [format!("{n}.join.json")]);
}
