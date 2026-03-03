from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional

from app.models import Threat, ThreatCategory, SeverityLevel
from app.schemas import (
    ThreatResponse,
    ThreatCreate,
    ThreatUpdate,
    ThreatListResponse,
    FilterParams,
    ThreatTranslated
)
from app.services.threat_service import ThreatService

router = APIRouter(prefix="/threats", tags=["Threats"])


@router.get("/", response_model=ThreatListResponse)
async def get_threats(
    category: Optional[ThreatCategory] = None,
    severity: Optional[SeverityLevel] = None,
    source: Optional[str] = None,
    sector: Optional[str] = None,
    region: Optional[str] = None,
    is_trending: Optional[bool] = None,
    is_active: Optional[bool] = True,
    search: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100)
):
    """
    Récupère la liste des menaces avec filtres et pagination
    """
    filters = FilterParams(
        category=category,
        severity=severity,
        source=source,
        sector=sector,
        region=region,
        is_trending=is_trending,
        is_active=is_active,
        search=search,
        page=page,
        page_size=page_size
    )
    
    threats, total = await ThreatService.get_threats(filters)
    
    return ThreatListResponse(
        threats=[ThreatResponse.model_validate({**t.model_dump(), 'id': str(t.id)}) for t in threats],
        total=total,
        page=page,
        page_size=page_size,
        has_more=(page * page_size) < total
    )


@router.get("/trending", response_model=List[ThreatResponse])
async def get_trending_threats(
    limit: int = Query(default=10, ge=1, le=50)
):
    """
    Récupère les menaces tendance
    """
    threats = await ThreatService.get_trending_threats(limit)
    return [ThreatResponse.model_validate({**t.model_dump(), 'id': str(t.id)}) for t in threats]


@router.get("/critical", response_model=List[ThreatResponse])
async def get_critical_threats(
    days: int = Query(default=7, ge=1, le=30),
    limit: int = Query(default=20, ge=1, le=100)
):
    """
    Récupère les menaces critiques récentes
    """
    threats = await ThreatService.get_critical_threats(days, limit)
    return [ThreatResponse.model_validate({**t.model_dump(), 'id': str(t.id)}) for t in threats]


@router.get("/statistics")
async def get_statistics():
    """
    Récupère les statistiques globales
    """
    stats = await ThreatService.get_statistics()
    return stats


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(
    threat_id: str
):
    """
    Récupère une menace par ID
    """
    threat = await ThreatService.get_threat(threat_id)
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return ThreatResponse.model_validate({**threat.model_dump(), 'id': str(threat.id)})


@router.get("/{threat_id}/translate", response_model=ThreatTranslated)
async def translate_threat(
    threat_id: str,
    target_language: str = Query(default="fr", pattern="^(fr|en|es|ar|de|it|pt|ru|zh-CN|ja)$")
):
    """
    Récupère une menace traduite dans la langue cible
    """
    threat = await ThreatService.get_threat(threat_id)
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    # Traduire
    translation = await ThreatService.translate_threat(threat, target_language)
    
    # Créer la réponse
    threat_dict = ThreatResponse.model_validate({**threat.model_dump(), 'id': str(threat.id)}).model_dump()
    threat_dict["translated_title"] = translation.get("title")
    threat_dict["translated_description"] = translation.get("description")
    threat_dict["translated_summary"] = translation.get("summary")
    threat_dict["translation_language"] = target_language
    
    return ThreatTranslated(**threat_dict)


@router.post("/", response_model=ThreatResponse)
async def create_threat(
    threat_data: ThreatCreate,
    analyze: bool = Query(default=True, description="Effectuer une analyse IA")
):
    """
    Crée une nouvelle menace (avec analyse IA optionnelle)
    """
    threat = await ThreatService.create_threat(threat_data, analyze)
    return ThreatResponse.model_validate({**threat.model_dump(), 'id': str(threat.id)})


@router.patch("/{threat_id}", response_model=ThreatResponse)
async def update_threat(
    threat_id: str,
    threat_data: ThreatUpdate
):
    """
    Met à jour une menace existante
    """
    threat = await ThreatService.update_threat(threat_id, threat_data)
    
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return ThreatResponse.model_validate({**threat.model_dump(), 'id': str(threat.id)})


@router.post("/{threat_id}/save")
async def save_threat(
    threat_id: str
):
    """
    Sauvegarde une menace dans les favoris (placeholder)
    """
    return {
        "message": "Threat saved",
        "threat_id": threat_id
    }


@router.post("/{threat_id}/mark-read")
async def mark_as_read(
    threat_id: str
):
    """
    Marque une menace comme lue (placeholder)
    """
    return {
        "message": "Marked as read",
        "threat_id": threat_id
    }


@router.delete("/{threat_id}")
async def delete_threat(
    threat_id: str
):
    """
    Supprime (désactive) une menace
    """
    success = await ThreatService.delete_threat(threat_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Threat not found")
    
    return {"message": "Threat deleted successfully"}

