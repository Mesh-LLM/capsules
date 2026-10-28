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
    }
}

#[test]
fn a_node_joins_once_and_leaves_only_after_a_join() {
    let (k, r) = (key(1), node(9));
    let key_id = commitment::key_id(&k);
    let join = Due::Join(r.clone());
    // Off and never joined: nothing. On: a join, until one is acknowledged.
    assert_eq!(due(false, None, &key_id, Some(&r)), Due::Nothing);
    assert_eq!(due(true, None, &key_id, Some(&r)), join);
    assert_eq!(due(true, None, &key_id, None), Due::Nothing);
    let joined = acked(KIND_JOIN, &k, &r);
    assert_eq!(due(true, Some(&joined), &key_id, Some(&r)), Due::Nothing);
    // Again when the key or the reporter changes.
    assert_eq!(
        due(true, Some(&joined), &commitment::key_id(&key(2)), Some(&r)),
        join
    );
    assert_eq!(
        due(true, Some(&joined), &key_id, Some(&node(8))),
        Due::Join(node(8))
    );
    // Off after a join: a leave, to the reporter that took it.
    assert_eq!(
        due(false, Some(&joined), &key_id, Some(&node(8))),
        Due::Leave(r.clone())
    );
    assert_eq!(
        due(false, Some(&joined), &key_id, None),
        Due::Leave(r.clone())
    );
    let left = acked(KIND_LEAVE, &k, &r);
    assert_eq!(due(false, Some(&left), &key_id, Some(&r)), Due::Nothing);
    assert_eq!(due(true, Some(&left), &key_id, Some(&r)), join);
    // A join under another statement is joined again.
    let mut stale = joined.clone();
    stale.record["consent_sha256"] = json!("0".repeat(64));
    assert_eq!(due(true, Some(&stale), &key_id, Some(&r)), join);
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
        let mut names: Vec<String> = std::fs::read_dir(self.dir.path())
            .map(|d| {
                d.map(|e| e.unwrap().file_name().into_string().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn held(&self, name: &str) -> Value {
        serde_json::from_slice(&std::fs::read(self.dir.path().join(name)).unwrap()).unwrap()
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
    // A leave with no join is refused.
    assert_eq!(
        reporter.take(&leave),
        Err("a leave with no join for its node_id".into())
    );
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
    std::fs::create_dir_all(reporter.dir.path()).unwrap();
    for n in 0..MAX_NODES {
        std::fs::write(
            reporter.dir.path().join(format!("{n:064x}.join.json")),
            b"{}",
        )
        .unwrap();
    }
    assert_eq!(
        reporter.take(&signed(KIND_JOIN, &key(1), "2026-10-28T12:00:00Z")),
        Err(format!(
            "the reporter holds {MAX_NODES} nodes, the most it takes"
        ))
    );
}
