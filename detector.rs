use serde_json::Value;

use crate::fast_path;

pub struct Match {
    pub rule_id: u32,
    pub score: u32,
    pub location: String,
}

pub trait Detector {
    fn detect(&self, response: &Value, state: &Value) -> Option<Match>;
}

pub struct JevDetector;

impl Detector for JevDetector {
    fn detect(&self, response: &Value, state: &Value) -> Option<Match> {
        from_jev(response, state)
    }
}

/// Maps Jev's typed answers to a Match. None when benign.
/// rule_id: sqli=1, xss=2, lfi=3; score: threat_level 0..2.
pub fn from_jev(response: &Value, state: &Value) -> Option<Match> {
    let rule_id = match response
        .pointer("/answers/attack_type/choice")
        .and_then(Value::as_str)
    {
        Some("sqli") => 1,
        Some("xss") => 2,
        Some("lfi") => 3,
        _ => return None,
    };
    let score = response
        .pointer("/answers/threat_level/score")
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;
    Some(Match {
        rule_id,
        score,
        location: locate(state, rule_id),
    })
}

/// Jev doesn't say where the attack is, so scan the state fields with the fast-path regex.
fn locate(state: &Value, rule_id: u32) -> String {
    let name = match rule_id {
        1 => "sqli",
        2 => "xss",
        3 => "lfi",
        _ => return "unknown".into(),
    };
    let fields = [
        ("path", state["path"].as_str().unwrap_or("")),
        ("query", state["query"].as_str().unwrap_or("")),
        ("body", state["body"].as_str().unwrap_or("")),
    ];
    for (field, value) in fields {
        if fast_path::check_rule(name, value) {
            return field.to_string();
        }
    }
    if let Some(headers) = state["headers"].as_object() {
        for (k, v) in headers {
            if v.as_str().is_some_and(|s| fast_path::check_rule(name, s)) {
                return format!("headers:{k}");
            }
        }
    }
    "unknown".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_typed_answers_to_match() {
        let j: Value = serde_json::from_str(
            r#"{"answers":{"attack_type":{"choice":"xss"},"is_malicious":{"noul":0.9},"threat_level":{"score":2}}}"#,
        )
        .unwrap();
        let st: Value = serde_json::json!({
            "method": "GET",
            "path": "/x",
            "query": "?a=<script>",
            "body": null,
            "headers": {}
        });
        let m = from_jev(&j, &st).unwrap();
        assert_eq!((m.rule_id, m.score, m.location.as_str()), (2, 2, "query"));
    }

    #[test]
    fn benign_returns_none() {
        let j: Value =
            serde_json::from_str(r#"{"answers":{"attack_type":{"choice":"benign"}}}"#).unwrap();
        let st: Value = serde_json::json!({
            "method": "GET",
            "path": "/",
            "query": "",
            "body": null,
            "headers": {}
        });
        assert!(from_jev(&j, &st).is_none());
    }
}
