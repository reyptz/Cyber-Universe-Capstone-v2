"""
Tâches Celery pour CyberRadar
"""

from celery import Celery
from celery.schedules import crontab
import logging

from config import settings

logger = logging.getLogger(__name__)

# Créer l'application Celery
celery_app = Celery(
    "cyberradar",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

# Configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 heure max
    worker_prefetch_multiplier=1,
)


# Tâches périodiques
celery_app.conf.beat_schedule = {
    # Collecte toutes les 30 minutes
    "collect-threats-every-30min": {
        "task": "app.tasks.collect_all_threats",
        "schedule": crontab(minute="*/30"),
    },
    
    # Analyse des tendances quotidienne
    "analyze-trends-daily": {
        "task": "app.tasks.analyze_daily_trends",
        "schedule": crontab(hour=1, minute=0),  # 1h du matin
    },
    
    # Mise à jour des trending toutes les heures
    "update-trending-hourly": {
        "task": "app.tasks.update_trending_threats",
        "schedule": crontab(minute=0),  # Toutes les heures
    },
}


@celery_app.task(name="app.tasks.collect_all_threats")
def collect_all_threats():
    """Collecte les menaces depuis toutes les sources"""
    import asyncio
    from app.collectors.collector_manager import collector_manager
    from app.database import async_session_maker
    from app.services.threat_service import ThreatService
    from sqlalchemy import select
    from app.models import Threat
    
    logger.info("Starting threat collection task")
    
    async def run_collection():
        # Collecter
        threats_by_source = await collector_manager.collect_all()
        
        saved_count = 0
        async with async_session_maker() as db:
            for source_name, threats in threats_by_source.items():
                for threat_data in threats:
                    try:
                        # Vérifier si déjà existant
                        if threat_data.external_id:
                            result = await db.execute(
                                select(Threat).where(
                                    Threat.external_id == threat_data.external_id
                                )
                            )
                            if result.scalar_one_or_none():
                                continue
                        
                        # Créer la menace
                        await ThreatService.create_threat(db, threat_data, analyze=True)
                        saved_count += 1
                    except Exception as e:
                        logger.error(f"Error saving threat: {e}")
        
        return saved_count
    
    # Exécuter
    count = asyncio.run(run_collection())
    logger.info(f"Collection task completed: {count} threats saved")
    
    return {"status": "success", "threats_saved": count}


@celery_app.task(name="app.tasks.analyze_daily_trends")
def analyze_daily_trends():
    """Analyse quotidienne des tendances"""
    import asyncio
    from app.database import async_session_maker
    from app.services.trend_service import TrendService
    
    logger.info("Starting daily trend analysis")
    
    async def run_analysis():
        async with async_session_maker() as db:
            analysis = await TrendService.analyze_trends(db, period_days=7)
            return analysis.id
    
    analysis_id = asyncio.run(run_analysis())
    logger.info(f"Trend analysis completed: ID {analysis_id}")
    
    return {"status": "success", "analysis_id": analysis_id}


@celery_app.task(name="app.tasks.update_trending_threats")
def update_trending_threats():
    """Met à jour les menaces trending"""
    import asyncio
    from app.database import async_session_maker
    from app.services.trend_service import TrendService
    
    logger.info("Updating trending threats")
    
    async def run_update():
        async with async_session_maker() as db:
            count = await TrendService.update_trending_flags(db)
            return count
    
    count = asyncio.run(run_update())
    logger.info(f"Trending update completed: {count} threats marked")
    
    return {"status": "success", "trending_count": count}


@celery_app.task(name="app.tasks.send_threat_notification")
def send_threat_notification(threat_id: int, user_tokens: list):
    """Envoie une notification pour une menace"""
    import asyncio
    from app.database import async_session_maker
    from app.services.threat_service import ThreatService
    from app.services.notification_service import notification_service
    
    logger.info(f"Sending notification for threat {threat_id}")
    
    async def run_notification():
        async with async_session_maker() as db:
            threat = await ThreatService.get_threat(db, threat_id)
            
            if not threat:
                return 0
            
            threat_dict = {
                "id": threat.id,
                "title": threat.title,
                "severity": threat.severity.value,
                "category": threat.category.value
            }
            
            result = await notification_service.send_batch_notifications(
                tokens=user_tokens,
                threat=threat_dict,
                language="fr"
            )
            
            return result["success"]
    
    success_count = asyncio.run(run_notification())
    logger.info(f"Notifications sent: {success_count}")
    
    return {"status": "success", "notifications_sent": success_count}


@celery_app.task(name="app.tasks.cleanup_old_data")
def cleanup_old_data(days: int = 180):
    """Nettoie les anciennes données"""
    import asyncio
    from datetime import datetime, timedelta
    from app.database import async_session_maker
    from sqlalchemy import delete
    from app.models import Threat, ChatHistory
    
    logger.info(f"Cleaning up data older than {days} days")
    
    async def run_cleanup():
        cutoff_date = datetime.now() - timedelta(days=days)
        
        async with async_session_maker() as db:
            # Supprimer les menaces inactives anciennes
            result1 = await db.execute(
                delete(Threat).where(
                    Threat.is_active == False,
                    Threat.detected_date < cutoff_date
                )
            )
            
            # Supprimer l'historique de chat ancien
            result2 = await db.execute(
                delete(ChatHistory).where(
                    ChatHistory.created_date < cutoff_date
                )
            )
            
            await db.commit()
            
            return result1.rowcount + result2.rowcount
    
    deleted_count = asyncio.run(run_cleanup())
    logger.info(f"Cleanup completed: {deleted_count} records deleted")
    
    return {"status": "success", "deleted_count": deleted_count}

