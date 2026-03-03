use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use anyhow::Result;
use regex::Regex;

/// Sigma detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub level: Option<String>,
    pub status: Option<String>,
    pub detection: serde_yaml::Value,
    pub tags: Vec<String>,
    pub author: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    pub rule_id: String,
    pub rule_title: String,
    pub matched: bool,
    pub event_data: serde_json::Value,
    pub timestamp: f64,
    pub latency_ms: f64,
}

pub struct SigmaEngine {
    rules: HashMap<String, SigmaRule>,
    pub detections: Vec<DetectionResult>,
}

impl SigmaEngine {
    pub fn new() -> Self {
        SigmaEngine {
            rules: HashMap::new(),
            detections: Vec::new(),
        }
    }

    pub fn load_rule<P: AsRef<std::path::Path>>(&mut self, path: P) -> Result<()> {
        let data = fs::read_to_string(path)?;
        let rule: SigmaRule = serde_yaml::from_str(&data)?;
        let id = rule.id.clone();
        self.rules.insert(id.clone(), rule);
        log::info!("Loaded rule {}", id);
        Ok(())
    }

    pub fn detect(&mut self, event: &serde_json::Value) -> Vec<DetectionResult> {
        use std::time::Instant;
        let start = Instant::now();
        let mut results = Vec::new();

        for (rule_id, rule) in &self.rules {
            if self.match_rule(rule, event) {
                let latency = start.elapsed().as_secs_f64() * 1000.0;
                let res = DetectionResult {
                    rule_id: rule_id.clone(),
                    rule_title: rule.title.clone(),
                    matched: true,
                    event_data: event.clone(),
                    timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
                    latency_ms: latency,
                };
                results.push(res.clone());
                self.detections.push(res);
                log::warn!("[DETECTION] rule {} matched (latency {:.2}ms)", rule.title, latency);
            }
        }

        let total_latency = start.elapsed().as_secs_f64() * 1000.0;
        if total_latency > 200.0 {
            log::warn!("Detection latency {:.2}ms exceeds target", total_latency);
        }

        results
    }

    fn match_rule(&self, rule: &SigmaRule, event: &serde_json::Value) -> bool {
        // simplified parser: look at `condition` key in rule.detection
        if let Some(cond) = rule.detection.get("condition") {
            if let Some(cond_str) = cond.as_str() {
                if cond_str == "selection" {
                    if let Some(sel) = rule.detection.get("selection") {
                        return self.match_selection(sel, event);
                    }
                }
                if cond_str.contains("and not") {
                    let parts: Vec<&str> = cond_str.split(" and not ").collect();
                    if parts.len() == 2 {
                        if let (Some(sel), Some(filt)) = (
                            rule.detection.get(parts[0].trim()),
                            rule.detection.get(parts[1].trim()),
                        ) {
                            return self.match_selection(sel, event)
                                && !self.match_selection(filt, event);
                        }
                    }
                }
                if cond_str.contains(" or ") {
                    for part in cond_str.split(" or ") {
                        if let Some(sel) = rule.detection.get(part.trim()) {
                            if self.match_selection(sel, event) {
                                return true;
                            }
                        }
                    }
                    return false;
                }
            }
        }
        false
    }

    fn match_selection(&self, selection: &serde_yaml::Value, event: &serde_json::Value) -> bool {
        if let Some(map) = selection.as_mapping() {
            for (k, v) in map {
                let key = k.as_str().unwrap_or_default();
                if let Some(ev_val) = event.get(key) {
                    if let Some(pattern) = v.as_str() {
                        if pattern.starts_with('*') && pattern.ends_with('*') {
                            let pat = pattern.trim_matches('*');
                            if !ev_val.as_str().unwrap_or_default().contains(pat) {
                                return false;
                            }
                        } else if pattern.ends_with('*') {
                            let pat = pattern.trim_end_matches('*');
                            if !ev_val.as_str().unwrap_or_default().starts_with(pat) {
                                return false;
                            }
                        } else if pattern.starts_with('*') {
                            let pat = pattern.trim_start_matches('*');
                            if !ev_val.as_str().unwrap_or_default().ends_with(pat) {
                                return false;
                            }
                        } else {
                            if ev_val != &serde_json::Value::String(pattern.to_string()) {
                                return false;
                            }
                        }
                    }
                } else {
                    return false;
                }
            }
        }
        true
    }
}
