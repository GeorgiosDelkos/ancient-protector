//! The agent's verdict: `findings.json`, and the strict checks it must pass.
//!
//! The agent lists only advisories it judges to affect an installed version. Everything it
//! names must exist in the bundle: an advisory id it did not receive or a component id that is
//! not in the inventory is an error, so a hallucinated finding cannot reach the user. The app
//! then raises any known-exploited finding to at least `high`.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;

/// The JSON Schema of `findings.json`, written into each bundle for the agent.
pub(crate) const SCHEMA: &str = include_str!("findings.schema.json");

/// What the agent wrote, after validation.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Findings {
    /// One entry per advisory that affects an installed component.
    pub findings: Vec<Finding>,
}

/// One advisory that affects one installed component.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// The advisory ids this finding is about; the first is the primary one.
    pub advisories: Vec<String>,
    /// The id of the affected component in `inventory.jsonl` (`c12`).
    pub component: String,
    /// How bad it is on this machine.
    pub severity: Severity,
    /// Whether the issue is exploited in the wild (CISA KEV).
    pub known_exploited: bool,
    /// How sure the agent is that the installed version is affected.
    pub confidence: Confidence,
    /// What the agent checked: the installed version against the affected range, a config.
    pub evidence: String,
    /// What the issue means for the user, in plain language.
    pub explanation: String,
    /// How to fix it. Never run during a sweep.
    pub fix: Fix,
}

/// A suggested fix.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fix {
    /// One line: what the fix does.
    pub summary: String,
    /// The steps, in order.
    pub steps: Vec<String>,
    /// The exact shell commands, in order; may be empty when the fix is manual.
    pub commands: Vec<String>,
}

/// Severity on this machine, most severe first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Exploitable for serious harm now.
    Critical,
    /// Serious; fix soon.
    High,
    /// Fix when convenient.
    Medium,
    /// Little risk here.
    Low,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        })
    }
}

/// How sure the agent is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// The installed version is in the affected range, or the agent verified the issue.
    Confirmed,
    /// Probably affected, but the agent could not be sure (a missing range, a vendor build).
    Likely,
}

/// What a finding may refer to: the bundle's advisory and component ids, and which advisories
/// are known exploited.
#[derive(Debug, Default)]
pub(crate) struct Known {
    pub(crate) advisories: BTreeSet<String>,
    pub(crate) components: BTreeSet<String>,
    pub(crate) exploited: BTreeSet<String>,
}

/// Parses and checks `findings.json` against what the bundle offered, and applies the
/// known-exploited floor. Every problem is reported, not only the first.
pub(crate) fn validate(text: &str, known: &Known) -> Result<Findings, Vec<String>> {
    let mut findings: Findings =
        serde_json::from_str(text).map_err(|e| vec![format!("findings.json: {e}")])?;

    let mut problems = Vec::new();
    for (i, finding) in findings.findings.iter_mut().enumerate() {
        let at = format!("findings[{i}]");
        if finding.advisories.is_empty() {
            problems.push(format!("{at}.advisories is empty"));
        }
        for id in &finding.advisories {
            if !known.advisories.contains(id) {
                problems.push(format!(
                    "{at}.advisories: {id:?} is not in advisories.jsonl"
                ));
            }
        }
        if !known.components.contains(&finding.component) {
            let id = &finding.component;
            problems.push(format!("{at}.component: {id:?} is not in inventory.jsonl"));
        }
        for (field, value) in [
            ("evidence", &finding.evidence),
            ("explanation", &finding.explanation),
            ("fix.summary", &finding.fix.summary),
        ] {
            if value.trim().is_empty() {
                problems.push(format!("{at}.{field} is empty"));
            }
        }
        // The catalog is authoritative: an exploited advisory is marked so whatever the agent
        // said, and is never below high.
        if finding
            .advisories
            .iter()
            .any(|a| known.exploited.contains(a))
        {
            finding.known_exploited = true;
        }
        if finding.known_exploited {
            finding.severity = finding.severity.min(Severity::High);
        }
    }
    if problems.is_empty() {
        Ok(findings)
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> Known {
        Known {
            advisories: ["GHSA-1", "CVE-2", "CVE-KEV"].map(String::from).into(),
            components: ["c1", "c2"].map(String::from).into(),
            exploited: ["CVE-KEV"].map(String::from).into(),
        }
    }

    fn finding(advisories: &[&str], component: &str, severity: &str, kev: bool) -> String {
        serde_json::json!({
            "advisories": advisories,
            "component": component,
            "severity": severity,
            "known_exploited": kev,
            "confidence": "confirmed",
            "evidence": "4.17.20 < 4.17.21",
            "explanation": "Prototype pollution.",
            "fix": {
                "summary": "Upgrade",
                "steps": ["Upgrade lodash"],
                "commands": ["npm i lodash@4.17.21"]
            }
        })
        .to_string()
    }

    #[test]
    fn accepts_valid_findings() {
        let text = format!(
            r#"{{"findings": [{}]}}"#,
            finding(&["GHSA-1", "CVE-2"], "c1", "medium", false)
        );
        let findings = validate(&text, &known()).unwrap();
        assert_eq!(findings.findings[0].severity, Severity::Medium);
        assert!(
            validate(r#"{"findings": []}"#, &known())
                .unwrap()
                .findings
                .is_empty()
        );
    }

    #[test]
    fn known_exploited_is_forced_and_at_least_high() {
        let text = format!(
            r#"{{"findings": [{}]}}"#,
            finding(&["CVE-KEV"], "c1", "low", false)
        );
        let f = &validate(&text, &known()).unwrap().findings[0];
        assert!(f.known_exploited);
        assert_eq!(f.severity, Severity::High);

        let text = format!(
            r#"{{"findings": [{}]}}"#,
            finding(&["GHSA-1"], "c1", "medium", true)
        );
        assert_eq!(
            validate(&text, &known()).unwrap().findings[0].severity,
            Severity::High
        );

        let text = format!(
            r#"{{"findings": [{}]}}"#,
            finding(&["CVE-KEV"], "c1", "critical", true)
        );
        assert_eq!(
            validate(&text, &known()).unwrap().findings[0].severity,
            Severity::Critical
        );
    }

    #[test]
    fn reports_every_unknown_id_and_empty_field() {
        let bad = serde_json::json!({
            "advisories": ["GHSA-1", "CVE-MADE-UP"],
            "component": "c9",
            "severity": "high",
            "known_exploited": false,
            "confidence": "likely",
            "evidence": " ",
            "explanation": "x",
            "fix": {"summary": "", "steps": [], "commands": []}
        });
        let empty = serde_json::json!({
            "advisories": [],
            "component": "c1",
            "severity": "low",
            "known_exploited": false,
            "confidence": "likely",
            "evidence": "e",
            "explanation": "x",
            "fix": {"summary": "s", "steps": [], "commands": []}
        });
        let text = serde_json::json!({"findings": [bad, empty]}).to_string();
        let problems = validate(&text, &known()).unwrap_err();
        assert_eq!(
            problems,
            [
                r#"findings[0].advisories: "CVE-MADE-UP" is not in advisories.jsonl"#,
                r#"findings[0].component: "c9" is not in inventory.jsonl"#,
                "findings[0].evidence is empty",
                "findings[0].fix.summary is empty",
                "findings[1].advisories is empty",
            ]
        );
    }

    #[test]
    fn rejects_bad_shapes() {
        for text in [
            "not json",
            r#"{"findings": [{"advisories": []}]}"#,
            r#"{"findings": [], "extra": 1}"#,
        ] {
            let problems = validate(text, &known()).unwrap_err();
            assert_eq!(problems.len(), 1, "{text}");
            assert!(problems[0].starts_with("findings.json: "), "{problems:?}");
        }
        let text = format!(
            r#"{{"findings": [{}]}}"#,
            finding(&["GHSA-1"], "c1", "severe", false)
        );
        assert!(validate(&text, &known()).is_err());
    }

    #[test]
    fn schema_is_valid_json_naming_every_field() {
        let schema: serde_json::Value = serde_json::from_str(SCHEMA).unwrap();
        let item = &schema["properties"]["findings"]["items"];
        let required: Vec<_> = item["required"].as_array().unwrap().iter().collect();
        for field in [
            "advisories",
            "component",
            "severity",
            "known_exploited",
            "confidence",
            "evidence",
            "explanation",
            "fix",
        ] {
            assert!(required.iter().any(|r| *r == field), "{field}");
        }
        assert_eq!(item["additionalProperties"], false);
    }
}
