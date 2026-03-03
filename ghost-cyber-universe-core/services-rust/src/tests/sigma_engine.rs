use super::super::sigma_engine::SigmaEngine;
use serde_json::json;

#[test]
fn basic_detection() {
    let mut engine = SigmaEngine::new();

    // build a simple rule manually
    let rule_yaml = r#"
        id: test-rule
        title: Test rule
        detection:
          selection:
            user: admin
          condition: selection
    "#;

    // load from string by writing to a temp file
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    use std::io::Write;
    write!(tmp, "{}", rule_yaml).unwrap();

    engine.load_rule(tmp.path()).unwrap();

    let event = json!({"user": "admin"});
    let results = engine.detect(&event);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].rule_id, "test-rule");
}
