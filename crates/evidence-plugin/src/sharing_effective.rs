//! `<data_dir>/sharing-effective.json`: the `share_record_at_completion`
//! value this node is acting on, readable from its data directory by a
//! verifier that reads nothing else (#136).
//!
//! It is the node's own report, unsigned: a reader labels it
//! "node-reported, unsigned". It is local to the operator's disk and never
//! sent to a peer. The value is resolved by the resolver the push path uses
//! (`share_policy::record_at_completion_is_off_for`), so the file cannot
//! disagree with behavior. mesh's console value live-reloads, so the file is
//! rewritten when the effective value changes (`keep_current`).

use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};

pub const FILE: &str = "sharing-effective.json";
const KEY: &str = "share_record_at_completion";
const CHECK_EVERY: Duration = Duration::from_secs(30);

/// What the node acts on. `raw_value` is the operator's value when it is not
/// one this plugin knows (so `off` there is a fallback, not a choice).
fn document(
    read: Result<String, std::env::VarError>,
    source: Option<&str>,
    written_at: &str,
) -> Value {
    let (raw, not_unicode) = match &read {
        Ok(raw) => (Some(raw.as_str()), false),
        Err(std::env::VarError::NotPresent) => (None, false),
        Err(std::env::VarError::NotUnicode(_)) => (None, true),
    };
    let off = crate::share_policy::record_at_completion_is_off_from(read.clone());
    let mut doc = json!({
        "v": 1,
        KEY: if off { "off" } else { "counterparty" },
        "source": source.unwrap_or("default"),
        "written_at": written_at,
    });
    let known = matches!(
        crate::share_policy::normalized(raw).as_deref(),
        None | Some("counterparty") | Some("off")
    );
    if not_unicode {
        doc["raw_value"] = json!("<not valid unicode>");
    } else if !known {
        doc["raw_value"] = json!(raw.unwrap_or_default());
    }
    doc
}

fn current() -> Value {
    // One read of the live console value: the source is derived from it, not
    // read again, so the two cannot come from different config files.
    let read = crate::settings::var(crate::share_policy::ENV_RECORD_AT_COMPLETION);
    let source = source_of(
        crate::settings::set_in_env(crate::share_policy::ENV_RECORD_AT_COMPLETION),
        read.is_ok(),
    );
    document(
        read,
        source,
        &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    )
}

/// Where a value that was read came from: the environment wins over the console.
fn source_of(in_env: bool, read_ok: bool) -> Option<&'static str> {
    match (in_env, read_ok) {
        (true, _) => Some("env"),
        (false, true) => Some("console"),
        (false, false) => None,
    }
}

/// The document minus its timestamp: what changing means.
fn same_state(a: &Value, b: &Value) -> bool {
    let strip = |v: &Value| {
        let mut v = v.clone();
        if let Some(o) = v.as_object_mut() {
            o.remove("written_at");
        }
        v
    };
    strip(a) == strip(b)
}

fn write(dir: &Path, doc: &Value) -> std::io::Result<()> {
    let tmp = dir.join(format!("{FILE}.tmp"));
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(doc).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(&tmp, dir.join(FILE))
}

/// Write the file if it is missing or states something else. Returns the
/// document now on disk.
fn refresh(dir: &Path, doc: Value) -> std::io::Result<Value> {
    let on_disk = std::fs::read(dir.join(FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    match on_disk {
        Some(old) if same_state(&old, &doc) => Ok(old),
        _ => write(dir, &doc).map(|()| doc),
    }
}

/// Write the file now (a failure is logged, never fatal) and keep it
/// current while the process runs.
pub fn keep_current(dir: std::path::PathBuf) {
    let check = move || {
        if let Err(error) = refresh(&dir, current()) {
            tracing::warn!(%error, file = FILE, "could not write the effective sharing setting");
        }
    };
    check();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CHECK_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            check();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::VarError;

    fn doc(read: Result<&str, VarError>, source: Option<&str>) -> Value {
        document(read.map(String::from), source, "T")
    }

    #[test]
    fn unset_is_counterparty_from_default() {
        let d = doc(Err(VarError::NotPresent), None);
        assert_eq!(d[KEY], "counterparty");
        assert_eq!(d["source"], "default");
        assert!(d.get("raw_value").is_none());
    }

    #[test]
    fn known_values_carry_their_source_and_no_raw_value() {
        let d = doc(Ok(" OFF "), Some("console"));
        assert_eq!(
            (d[KEY].as_str(), d["source"].as_str()),
            (Some("off"), Some("console"))
        );
        assert!(d.get("raw_value").is_none());
        let d = doc(Ok("counterparty"), Some("env"));
        assert_eq!(
            (d[KEY].as_str(), d["source"].as_str()),
            (Some("counterparty"), Some("env"))
        );
    }

    #[test]
    fn an_unknown_value_is_off_with_the_raw_value_beside_it() {
        let d = doc(Ok("counterparties"), Some("env"));
        assert_eq!(d[KEY], "off");
        assert_eq!(d["raw_value"], "counterparties");
    }

    #[test]
    fn a_non_unicode_value_is_off_as_on_the_push_path() {
        let read = Err(VarError::NotUnicode(std::ffi::OsString::from("x")));
        assert!(crate::share_policy::record_at_completion_is_off_from(
            read.clone()
        ));
        let d = document(read, Some("env"), "T");
        assert_eq!(d[KEY], "off");
        assert_eq!(d["raw_value"], "<not valid unicode>");
    }

    #[test]
    fn source_follows_the_one_read() {
        assert_eq!(source_of(true, true), Some("env"));
        assert_eq!(source_of(false, true), Some("console"));
        assert_eq!(source_of(false, false), None);
    }

    #[test]
    fn agrees_with_the_push_path_resolver() {
        for raw in [
            None,
            Some(""),
            Some("off"),
            Some("counterparty"),
            Some("Counterparty "),
            Some("x"),
        ] {
            let read = raw
                .map(|r| Ok(r.to_string()))
                .unwrap_or(Err(VarError::NotPresent));
            let d = document(read.clone(), None, "T");
            assert_eq!(
                d[KEY] == "off",
                crate::share_policy::record_at_completion_is_off_from(read),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn rewritten_only_when_the_state_changes() {
        let dir = tempfile::tempdir().unwrap();
        let a = refresh(dir.path(), document(Err(VarError::NotPresent), None, "T1")).unwrap();
        let b = refresh(dir.path(), document(Err(VarError::NotPresent), None, "T2")).unwrap();
        assert_eq!(
            b["written_at"], a["written_at"],
            "same state keeps the file"
        );
        let c = refresh(
            dir.path(),
            document(Ok("off".into()), Some("console"), "T3"),
        )
        .unwrap();
        assert_eq!(c[KEY], "off");
        let read: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join(FILE)).unwrap()).unwrap();
        assert_eq!(read, c);
        assert!(!dir.path().join(format!("{FILE}.tmp")).exists());
    }
}
