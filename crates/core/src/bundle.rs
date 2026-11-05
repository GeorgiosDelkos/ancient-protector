//! The folder an agent works in for one target: prompt, inventory, advisories and schema.
//!
//! `advisories.jsonl` is an index, one compact line per advisory, so a product with hundreds of
//! CVEs still fits in the agent's context; each line names `records/<id>.json`, the full record
//! as the source served it, for when the agent needs detail. Layout: spec, "Bundle and
//! findings".

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use serde_json::Value;
use serde_json::json;

use crate::feeds::Advisory;
use crate::feeds::Kev;
use crate::feeds::Source;
use crate::findings::Known;
use crate::findings::SCHEMA;
use crate::inventory::Component;

/// The longest summary kept in the index, in characters. Arbitrary: enough for the first
/// sentence or two; the full text is in the record.
const SUMMARY_LIMIT: usize = 400;

/// One advisory and the ids of the components it was fetched for.
#[derive(Debug)]
pub(crate) struct Entry<'a> {
    pub(crate) advisory: &'a Advisory,
    pub(crate) components: Vec<String>,
}

/// Writes the bundle into `dir` (created if needed) and returns what findings may refer to.
///
/// Components get ids `c1`, `c2`, ... in `components` order. `kev` is `None` when the catalog
/// could not be read; `known_exploited` is then `null` in the index.
pub(crate) fn write(
    dir: &Path,
    prompt: &str,
    components: &[Component],
    entries: &[Entry<'_>],
    kev: Option<&Kev>,
) -> Result<Known, BundleError> {
    let io_err = |path: &Path| {
        let path = path.to_owned();
        move |source| BundleError { path, source }
    };
    let records = dir.join("records");
    fs::create_dir_all(&records).map_err(io_err(&records))?;

    let mut known = Known::default();
    let mut inventory = String::new();
    for (i, component) in components.iter().enumerate() {
        let id = component_id(i);
        let mut line = serde_json::to_value(component)
            .expect("components hold strings and paths checked by the caller");
        line["id"] = Value::String(id.clone());
        inventory.push_str(&line.to_string());
        inventory.push('\n');
        known.components.insert(id);
    }

    let mut index = String::new();
    for entry in entries {
        let advisory = entry.advisory;
        let record_name = format!("records/{}.json", advisory.id);
        let record_path = dir.join(&record_name);
        fs::write(&record_path, advisory.record.get()).map_err(io_err(&record_path))?;

        let exploited = kev.map(|kev| advisory.is_known_exploited(kev));
        if exploited == Some(true) {
            known.exploited.insert(advisory.id.clone());
        }
        let mut line = compact(advisory);
        line["known_exploited"] = json!(exploited);
        line["components"] = json!(entry.components);
        line["record"] = json!(record_name);
        index.push_str(&line.to_string());
        index.push('\n');
        known.advisories.insert(advisory.id.clone());
    }

    for (name, text) in [
        ("PROMPT.md", prompt),
        ("inventory.jsonl", &inventory),
        ("advisories.jsonl", &index),
        ("findings.schema.json", SCHEMA),
    ] {
        let path = dir.join(name);
        fs::write(&path, text).map_err(io_err(&path))?;
    }
    Ok(known)
}

/// The id of the `i`th component in a bundle.
pub(crate) fn component_id(i: usize) -> String {
    format!("c{}", i + 1)
}

/// The index line for one advisory: the fields that decide whether it applies.
fn compact(advisory: &Advisory) -> Value {
    let record: Value = serde_json::from_str(advisory.record.get()).unwrap_or(Value::Null);
    let source = match advisory.source {
        Source::Osv => "osv",
        Source::Nvd => "nvd",
    };
    let (summary, severity, affected) = match advisory.source {
        Source::Osv => osv_fields(&record),
        Source::Nvd => nvd_fields(&record),
    };
    json!({
        "id": advisory.id,
        "source": source,
        "aliases": advisory.aliases,
        "summary": truncate(&summary),
        "severity": severity,
        "affected": affected,
    })
}

/// OSV: `summary` (or the start of `details`), `severity` (CVSS vectors) or the GitHub
/// `database_specific.severity`, and each `affected` package with its version ranges. The
/// explicit `versions` lists are left out: they can run to thousands of entries and the ranges
/// say the same thing; the record has them.
fn osv_fields(record: &Value) -> (String, Value, Value) {
    let summary = record["summary"]
        .as_str()
        .or_else(|| record["details"].as_str())
        .unwrap_or_default()
        .to_owned();
    let severity = if record["severity"].is_array() {
        record["severity"].clone()
    } else {
        record["database_specific"]["severity"].clone()
    };
    let affected = record["affected"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|a| json!({"package": a["package"], "ranges": a["ranges"]}))
                .collect()
        })
        .unwrap_or_default();
    (summary, severity, Value::Array(affected))
}

/// NVD: the English description, the newest CVSS metric present (v4.0, v3.1, v3.0, then v2),
/// and every vulnerable CPE match with its version bounds.
fn nvd_fields(record: &Value) -> (String, Value, Value) {
    let summary = record["descriptions"]
        .as_array()
        .and_then(|list| list.iter().find(|d| d["lang"] == "en"))
        .and_then(|d| d["value"].as_str())
        .unwrap_or_default()
        .to_owned();
    let metrics = &record["metrics"];
    let severity = [
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ]
    .iter()
    .find_map(|key| metrics[key].as_array().and_then(|list| list.first()))
    .map_or(Value::Null, |metric| {
        let data = &metric["cvssData"];
        json!({
            "version": data["version"],
            "score": data["baseScore"],
            "severity": data["baseSeverity"].as_str().or(metric["baseSeverity"].as_str()),
            "vector": data["vectorString"],
        })
    });
    let mut matches = Vec::new();
    for config in record["configurations"].as_array().into_iter().flatten() {
        for node in config["nodes"].as_array().into_iter().flatten() {
            for cpe in node["cpeMatch"].as_array().into_iter().flatten() {
                if cpe["vulnerable"] == true {
                    let mut kept = serde_json::Map::new();
                    for key in [
                        "criteria",
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    ] {
                        if !cpe[key].is_null() {
                            kept.insert(key.to_owned(), cpe[key].clone());
                        }
                    }
                    matches.push(Value::Object(kept));
                }
            }
        }
    }
    (summary, severity, Value::Array(matches))
}

fn truncate(text: &str) -> String {
    let text = text.trim();
    if text.chars().count() <= SUMMARY_LIMIT {
        return text.to_owned();
    }
    let cut: String = text.chars().take(SUMMARY_LIMIT).collect();
    format!("{cut}...")
}

/// A bundle file could not be written.
#[derive(Debug, thiserror::Error)]
#[error("cannot write the agent bundle file {}", path.display())]
pub struct BundleError {
    /// The file or folder.
    pub path: PathBuf,
    /// The underlying error.
    #[source]
    pub source: io::Error,
}

#[cfg(test)]
mod tests {
    use serde_json::value::RawValue;

    use super::*;
    use crate::inventory::FoundIn;
    use crate::inventory::Lookup;

    fn advisory(source: Source, id: &str, aliases: &[&str], record: &Value) -> Advisory {
        Advisory {
            source,
            id: id.to_owned(),
            aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
            record: RawValue::from_string(record.to_string()).unwrap(),
        }
    }

    fn osv_record() -> Value {
        json!({
            "id": "GHSA-1",
            "summary": "Prototype pollution in lodash",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "lodash"},
                "ranges": [{"type": "SEMVER", "events": [
                    {"introduced": "0"}, {"fixed": "4.17.21"}
                ]}],
                "versions": ["1.0.0", "2.0.0"]
            }]
        })
    }

    fn nvd_record() -> Value {
        json!({
            "id": "CVE-2",
            "descriptions": [
                {"lang": "es", "value": "No"},
                {"lang": "en", "value": "Overflow in openssl"}
            ],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N"
            }}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": true, "criteria": "cpe:2.3:a:openssl:openssl:*",
                 "versionEndExcluding": "3.0.8", "matchCriteriaId": "x"},
                {"vulnerable": false, "criteria": "cpe:2.3:o:linux:linux_kernel:*"}
            ]}]}]
        })
    }

    #[test]
    fn osv_and_nvd_index_lines() {
        let osv = compact(&advisory(Source::Osv, "GHSA-1", &["CVE-1"], &osv_record()));
        assert_eq!(osv["summary"], "Prototype pollution in lodash");
        assert_eq!(osv["severity"], "HIGH");
        assert_eq!(osv["aliases"], json!(["CVE-1"]));
        assert_eq!(osv["affected"][0]["package"]["name"], "lodash");
        assert!(
            osv["affected"][0].get("versions").is_none(),
            "versions lists are left out"
        );

        let nvd = compact(&advisory(Source::Nvd, "CVE-2", &[], &nvd_record()));
        assert_eq!(nvd["summary"], "Overflow in openssl");
        assert_eq!(nvd["severity"]["score"], 9.8);
        assert_eq!(nvd["severity"]["severity"], "CRITICAL");
        assert_eq!(
            nvd["affected"],
            json!([{"criteria": "cpe:2.3:a:openssl:openssl:*", "versionEndExcluding": "3.0.8"}])
        );
    }

    #[test]
    fn missing_fields_become_empty() {
        let line = compact(&advisory(
            Source::Nvd,
            "CVE-3",
            &[],
            &json!({"id": "CVE-3"}),
        ));
        assert_eq!(line["summary"], "");
        assert!(line["severity"].is_null());
        assert_eq!(line["affected"], json!([]));
        let line = compact(&advisory(
            Source::Osv,
            "X-1",
            &[],
            &json!({"details": "Long text"}),
        ));
        assert_eq!(line["summary"], "Long text");
    }

    #[test]
    fn long_summaries_are_cut() {
        let long = "a".repeat(SUMMARY_LIMIT + 10);
        assert_eq!(truncate(&long).chars().count(), SUMMARY_LIMIT + 3);
        assert_eq!(truncate("  short  "), "short");
    }

    #[test]
    fn writes_every_file_and_returns_the_known_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("bundle");
        let components = vec![Component {
            lookup: Lookup::Package("npm:lodash".parse().unwrap()),
            version: "4.17.20".into(),
            found_in: FoundIn::NpmGlobal,
        }];
        let osv = advisory(Source::Osv, "GHSA-1", &["CVE-1"], &osv_record());
        let entries = [Entry {
            advisory: &osv,
            components: vec!["c1".into()],
        }];

        let known = write(&dir, "Do the sweep", &components, &entries, None).unwrap();
        assert_eq!(known.advisories, ["GHSA-1".to_owned()].into());
        assert_eq!(known.components, ["c1".to_owned()].into());
        assert!(known.exploited.is_empty());

        assert_eq!(
            fs::read_to_string(dir.join("PROMPT.md")).unwrap(),
            "Do the sweep"
        );
        assert_eq!(
            fs::read_to_string(dir.join("findings.schema.json")).unwrap(),
            SCHEMA
        );
        let inventory: Value = serde_json::from_str(
            fs::read_to_string(dir.join("inventory.jsonl"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert_eq!(inventory["id"], "c1");
        assert_eq!(inventory["version"], "4.17.20");
        let index: Value = serde_json::from_str(
            fs::read_to_string(dir.join("advisories.jsonl"))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert_eq!(index["components"], json!(["c1"]));
        assert_eq!(index["record"], "records/GHSA-1.json");
        assert!(
            index["known_exploited"].is_null(),
            "unknown without a KEV catalog"
        );
        let record: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("records/GHSA-1.json")).unwrap())
                .unwrap();
        assert_eq!(record, osv_record());
    }

    #[test]
    fn known_exploited_comes_from_the_catalog() {
        let tmp = tempfile::tempdir().unwrap();
        let exploited = advisory(Source::Osv, "GHSA-1", &["CVE-1"], &osv_record());
        let other = advisory(Source::Nvd, "CVE-2", &[], &nvd_record());
        let entries = [
            Entry {
                advisory: &exploited,
                components: vec![],
            },
            Entry {
                advisory: &other,
                components: vec![],
            },
        ];
        let kev = Kev::from_ids(&["CVE-1"]);
        let known = write(tmp.path(), "p", &[], &entries, Some(&kev)).unwrap();
        assert_eq!(known.exploited, ["GHSA-1".to_owned()].into());
        let index = fs::read_to_string(tmp.path().join("advisories.jsonl")).unwrap();
        let lines: Vec<Value> = index
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines[0]["known_exploited"], true);
        assert_eq!(lines[1]["known_exploited"], false);
    }

    #[test]
    fn unwritable_dir_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("file");
        fs::write(&blocker, "").unwrap();
        let err = write(&blocker.join("bundle"), "p", &[], &[], None).unwrap_err();
        assert!(
            err.to_string().contains("cannot write the agent bundle"),
            "{err}"
        );
    }
}
