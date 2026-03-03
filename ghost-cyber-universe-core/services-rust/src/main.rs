use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde_json::json;

mod models;
mod sigma_engine;

use models::{CreateMission, Mission, MissionStatus};
use uuid::Uuid;
use chrono::Utc;

async fn create_mission(mission: web::Json<CreateMission>) -> impl Responder {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let m = Mission {
        id: id.clone(),
        name: mission.name.clone(),
        targets: mission.targets.clone(),
        depth: mission.depth,
        frequency: mission.frequency.clone().unwrap_or_else(|| "once".into()),
        crawler_modules: mission.crawler_modules.clone().unwrap_or_default(),
        status: MissionStatus::Pending,
        created_at: now,
        updated_at: now,
        tags: mission.tags.clone().unwrap_or_default(),
        results_count: 0,
    };

    HttpResponse::Created().json(m)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    HttpServer::new(|| {
        App::new()
            .route("/api/missions", web::post().to(create_mission))
            .route("/health", web::get().to(|| async { HttpResponse::Ok().body("ok") }))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
