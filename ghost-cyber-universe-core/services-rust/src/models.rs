use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub enum MissionStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Paused,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CrawlerType {
    Http,
    Api,
    Javascript,
    SocialMedia,
    Forum,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkflowStatus {
    ToValidate,
    InProgress,
    Validated,
    Expired,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Mission {
    pub id: String,
    pub name: String,
    pub targets: Vec<String>,
    pub depth: u8,
    pub frequency: String,
    pub crawler_modules: Vec<CrawlerType>,
    pub status: MissionStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Vec<String>,
    pub results_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateMission {
    pub name: String,
    pub targets: Vec<String>,
    pub depth: u8,
    pub frequency: Option<String>,
    pub crawler_modules: Option<Vec<CrawlerType>>,
    pub tags: Option<Vec<String>>,
}

// Additional models (CrawlResult, RAGQuery, etc.) would follow similarly
