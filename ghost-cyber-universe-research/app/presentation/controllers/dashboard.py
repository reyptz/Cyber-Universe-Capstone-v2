from fastapi import APIRouter

from app.schemas import DashboardStats, ThreatResponse
from app.services.threat_service import ThreatService

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """
    Récupère les statistiques pour le tableau de bord
    """
    # Statistiques de base
    stats = await ThreatService.get_statistics()
    
    # Menaces critiques récentes
    critical_threats = await ThreatService.get_critical_threats(days=7, limit=5)
    
    # Menaces tendance
    trending_threats = await ThreatService.get_trending_threats(limit=5)
    
    # Calculer la distribution de sévérité
    from app.models import SeverityLevel, Threat
    severity_distribution = {}
    for severity in SeverityLevel:
        count = await Threat.find(
            Threat.severity == severity,
            Threat.is_active == True
        ).count()
        severity_distribution[severity.value] = count
    
    # Top catégories tendance
    trending_categories = []
    for category, count in stats["category_distribution"].items():
        if count > 0:
            trending_categories.append({
                "category": category,
                "count": count,
                "percentage": (count / stats["threats_this_week"] * 100) if stats["threats_this_week"] > 0 else 0
            })
    
    trending_categories.sort(key=lambda x: x["count"], reverse=True)
    
    return DashboardStats(
        total_threats=stats["total_threats"],
        active_threats=stats["total_threats"],
        critical_threats=stats["critical_threats"],
        high_threats=stats["high_threats"],
        threats_today=stats["threats_today"],
        threats_this_week=stats["threats_this_week"],
        threats_this_month=stats["threats_this_month"],
        trending_categories=trending_categories[:5],
        recent_threats=[ThreatResponse.model_validate({**t.model_dump(), 'id': str(t.id)}) for t in critical_threats],
        severity_distribution=severity_distribution,
        category_distribution=stats["category_distribution"]
    )

