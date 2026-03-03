"""
Routes simplifiées pour la collecte de données
"""

from fastapi import APIRouter, BackgroundTasks
from typing import Optional

router = APIRouter(prefix="/collector", tags=["Collector"])


@router.post("/collect")
async def trigger_collection(
    background_tasks: BackgroundTasks,
    source: Optional[str] = None
):
    """
    Déclenche la collecte de données
    
    Sources: rss, cve, all (défaut)
    """
    background_tasks.add_task(run_collection_task, source)
    
    return {
        "message": "Collection started in background",
        "source": source or "all"
    }


@router.post("/collect-now")
async def collect_now(source: Optional[str] = None):
    """
    Collecte immédiate (synchrone) - pour tests
    """
    result = await run_collection_task(source)
    return result


async def run_collection_task(source: Optional[str] = None):
    """Tâche de collecte"""
    from app.collectors.rss_collector import run_rss_collection
    from app.collectors.cve_collector import run_cve_collection
    import logging
    
    logger = logging.getLogger(__name__)
    results = {}
    
    try:
        if source == "rss":
            results["rss"] = await run_rss_collection()
        elif source == "cve":
            results["cve"] = await run_cve_collection()
        else:
            # Tout collecter
            logger.info("Collecte RSS et CVE...")
            results["rss"] = await run_rss_collection()
            results["cve"] = await run_cve_collection()
        
        return {
            "status": "completed",
            "results": results
        }
    except Exception as e:
        logger.error(f"Erreur collecte: {e}", exc_info=True)
        return {
            "status": "error",
            "error": str(e)
        }

