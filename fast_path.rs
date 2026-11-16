use regex::Regex;
use std::sync::LazyLock;

struct Rule {
    id: &'static str,
    re: Regex,
}

// shortcut: static heuristics on normalized path + raw query + body; tune with the phase-8 corpus when false positives show up
static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        Rule {
            id: "sqli",
            re: Regex::new(
                r"(?i)union[\s+]*select|'\s*(or|and)\s*'|;\s*(drop|delete|insert|update|create|alter)\b|sleep\s*\(|benchmark\s*\(|information_schema",
            )
            .unwrap(),
        },
        Rule {
            id: "xss",
            re: Regex::new(
                r"(?i)<\s*script|on(error|load|click|mouseover|focus|submit|input|keyup|keydown)\s*=|javascript\s*:|<\s*iframe|document\.cookie|alert\s*\(",
            )
            .unwrap(),
        },
        Rule {
            id: "lfi",
            re: Regex::new(r"\.\./|/etc/(passwd|shadow|hosts)|/proc/self|php\s*://|file\s*://").unwrap(),
        },
    ]
});

/// First rule id that matches, or None if the input looks benign.
pub fn check(input: &str) -> Option<&'static str> {
    RULES.iter().find(|r| r.re.is_match(input)).map(|r| r.id)
}

/// Does the rule with this id match the input?
pub fn check_rule(id: &str, input: &str) -> bool {
    RULES.iter().any(|r| r.id == id && r.re.is_match(input))
}

#[cfg(test)]
mod tests {
    use super::check;

    #[test]
    fn catches_basic_attacks() {
        assert_eq!(check("unionselect"), Some("sqli"));
        assert_eq!(check("a=1' or '1'='1"), Some("sqli"));
        assert_eq!(check("x=<ScRiPt>alert(1)</script>"), Some("xss"));
        assert_eq!(check("p=../../etc/passwd"), Some("lfi"));
    }

    #[test]
    fn benign_input_passes() {
        assert_eq!(check("/index.html?name=hello&only=1"), None);
    }
}
