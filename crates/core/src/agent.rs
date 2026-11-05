//! The coding agents a sweep can run.

use std::fmt;

use serde::Deserialize;

/// A coding-agent CLI that Ancient Protector can drive headless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentKind {
    /// Claude Code (`claude`).
    Claude,
    /// Grok CLI (`grok`).
    Grok,
    /// OpenAI Codex CLI (`codex`).
    Codex,
    /// Gemini CLI (`gemini`).
    Gemini,
    /// opencode (`opencode`).
    Opencode,
}

impl AgentKind {
    /// Returns the executable name looked up on `PATH`.
    pub fn binary(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Grok => "grok",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::Opencode => "opencode",
        }
    }
}

impl fmt::Display for AgentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.binary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The config name, the binary and the display name are the same word, so a user who
    /// writes `agent = "x"` knows the app runs `x`.
    #[test]
    fn config_name_is_binary_name() {
        for (name, kind) in [
            ("claude", AgentKind::Claude),
            ("grok", AgentKind::Grok),
            ("codex", AgentKind::Codex),
            ("gemini", AgentKind::Gemini),
            ("opencode", AgentKind::Opencode),
        ] {
            let parsed: AgentKind = toml::Value::String(name.into()).try_into().unwrap();
            assert_eq!(parsed, kind);
            assert_eq!(kind.binary(), name);
            assert_eq!(kind.to_string(), name);
        }
    }
}
