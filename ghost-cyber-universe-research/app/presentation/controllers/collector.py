from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, List

from app.collectors.collector_manager import collector_manager
from app.services.threat_service import ThreatService
from app.schemas import ThreatCreate

router = APIRouter(prefix="/collector", tags=["Collector"])


@router.post("/collect")
async def collect_threats(
    background_tasks: BackgroundTasks,
    source: str = None
):
    """
    Lance la collecte de menaces (en arrière-plan)
    """
    background_tasks.add_task(run_collection, source)
    
    return {
        "message": "Collection started in background",
        "source": source or "all"
    }


@router.get("/status")
async def get_collector_status():
    """
    Récupère le statut de tous les collecteurs
    """
    return {
        "collectors": collector_manager.get_collector_status(),
        "total_collectors": len(collector_manager.collectors)
    }


@router.post("/collect-sync")
async def collect_threats_sync(
    source: str = None
):
    """
    Lance la collecte de menaces (synchrone)
    """
    result = await run_collection(source)
    return result


async def run_collection(source: str = None):
    """Fonction de collecte"""
    try:
        if source:
            # Collecter depuis une source spécifique
            threats_data = await collector_manager.collect_from_source(source)
            threats_by_source = {source: threats_data}
        else:
            # Collecter depuis toutes les sources
            threats_by_source = await collector_manager.collect_all()
        
        # Sauvegarder dans la base de données
        saved_count = 0
        error_count = 0
        
        for source_name, threats in threats_by_source.items():
            for threat_data in threats:
                try:
                    # Vérifier si déjà existant (via external_id)
                    if threat_data.external_id:
                        from app.models import Threat
                        
                        existing = await Threat.find_one(
                            Threat.external_id == threat_data.external_id
                        )
                        
                        if existing:
                            continue  # Skip si déjà existant
                    
                    # Créer la menace avec analyse
                    await ThreatService.create_threat(threat_data, analyze=True)
                    saved_count += 1
                    
                except Exception as e:
                    error_count += 1
                    print(f"Error saving threat: {str(e)}")
        
        return {
            "message": "Collection completed",
            "sources_collected": len(threats_by_source),
            "threats_saved": saved_count,
            "errors": error_count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Collection error: {str(e)}")

