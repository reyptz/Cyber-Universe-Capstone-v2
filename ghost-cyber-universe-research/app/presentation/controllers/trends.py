from fastapi import APIRouter, HTTPException, Query
from typing import List

from app.schemas import TrendAnalysisResponse
from app.services.trend_service import TrendService

router = APIRouter(prefix="/trends", tags=["Trends"])


@router.post("/analyze")
async def analyze_trends(
    period_days: int = Query(default=7, ge=1, le=90)
):
    """
    Effectue une nouvelle analyse des tendances
    """
    analysis = await TrendService.analyze_trends(period_days)
    return TrendAnalysisResponse.model_validate(analysis)


@router.get("/latest", response_model=TrendAnalysisResponse)
async def get_latest_analysis():
    """
    Récupère la dernière analyse de tendances
    """
    analysis = await TrendService.get_latest_analysis()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="No trend analysis found")
    
    return TrendAnalysisResponse.model_validate(analysis)


@router.get("/history", response_model=List[TrendAnalysisResponse])
async def get_analysis_history(
    limit: int = Query(default=30, ge=1, le=100)
):
    """
    Récupère l'historique des analyses de tendances
    """
    analyses = await TrendService.get_analysis_history(limit)
    return [TrendAnalysisResponse.model_validate(a) for a in analyses]


@router.post("/update-trending")
async def update_trending_flags():
    """
    Met à jour les flags 'is_trending' des menaces
    """
    count = await TrendService.update_trending_flags()
    return {
        "message": "Trending flags updated",
        "trending_count": count
    }

