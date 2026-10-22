use std::time::Duration;

use axum::http::HeaderMap;
use serde_json::{json, Value};

const JEV_URL: &str = "https://jev-api.com/v1/systemone";
const MODEL: &str = "jev-latest";

/// Mismas preguntas que el playground (QUESTIONS en playground.html)
pub const QUESTIONS: &str = r#"{
  "attack_type": {
    "type": "choice",
    "instructions": "Classify this HTTP request.",
    "criteria": {
      "benign": "Normal web traffic, nothing suspicious",
      "sqli": "SQL injection attempt",
      "xss": "Cross-site scripting attempt",
      "lfi": "Path traversal / local file inclusion attempt"
    }
  },
  "is_malicious": { "type": "noul", "instructions": "Is this request malicious?" },
  "threat_level": {
    "type": "score",
    "instructions": "How likely is this a real attack?",
    "criteria": ["Benign or accidental", "Suspicious, likely probing", "Clear intentional attack"]
  }
}"#;

/// State del request con la misma forma que stateFor() del playground
pub fn state(method: &str, path: &str, query: &str, headers: &HeaderMap, body: Option<&str>) -> Value {
    let h: serde_json::Map<String, Value> = headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_string(), Value::String(s.to_string()))))
        .collect();
    json!({ "method": method, "path": path, "query": query, "headers": h, "body": body })
}

/// Pregunta a Jev y devuelve la respuesta tipada completa
pub async fn ask(client: &reqwest::Client, key: &str, st: &Value) -> Result<Value, String> {
    let payload = json!({
        "model": MODEL,
        "state": st.to_string(),
        "questions": serde_json::from_str::<Value>(QUESTIONS).unwrap(),
    });
    let res = client
        .post(JEV_URL)
        .header("Authorization", format!("Bearer {key}"))
        .json(&payload)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let status = res.status();
    let j: Value = res.json().await.map_err(|e| e.to_string())?;
    if !status.is_success() {
        let msg = j.pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or_else(|| status.as_str())
            .to_string();
        return Err(msg);
    }
    Ok(j)
}

/// Veredicto de una línea para logging detect-only
pub fn verdict(j: &Value) -> String {
    let a = j.pointer("/answers").unwrap_or(&Value::Null);
    let atk = a.pointer("/attack_type/choice").and_then(Value::as_str).unwrap_or("?");
    let mal = a.pointer("/is_malicious/noul").and_then(Value::as_f64);
    let lvl = a.pointer("/threat_level/score").and_then(Value::as_u64);
    format!("attack_type={atk} is_malicious={mal:?} threat_level={lvl:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_parses_typed_answers() {
        let j: Value = serde_json::from_str(
            r#"{"model":"jev-latest","answers":{
              "attack_type":{"type":"choice","choice":"xss","confidence":0.95,"probabilities":{}},
              "is_malicious":{"type":"noul","noul":0.9},
              "threat_level":{"type":"score","score":2,"legend":{},"probabilities":{}}}}"#
        )
        .unwrap();
        assert_eq!(verdict(&j), "attack_type=xss is_malicious=Some(0.9) threat_level=Some(2)");
    }

    #[test]
    fn state_shape_matches_playground() {
        let st = state("GET", "/", "?name=x", &HeaderMap::new(), None);
        assert_eq!(st["method"].as_str(), Some("GET"));
        assert_eq!(st["query"].as_str(), Some("?name=x"));
        assert!(st["body"].is_null());
        assert!(st["headers"].as_object().unwrap().is_empty());
    }
}
