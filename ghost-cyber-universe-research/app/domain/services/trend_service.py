from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import Counter
import logging

from app.models import Threat, TrendAnalysis, ThreatCategory, SeverityLevel
from app.schemas import TrendAnalysisResponse

logger = logging.getLogger(__name__)


class TrendService:
    """Service pour l'analyse des tendances"""
    
    @staticmethod
    async def analyze_trends(
        period_days: int = 7
    ) -> TrendAnalysis:
        """
        Effectue une analyse des tendances sur une période
        
        Args:
            db: Session database
            period_days: Nombre de jours à analyser
            
        Returns:
            TrendAnalysis: Analyse des tendances
        """
        period_end = datetime.now()
        period_start = period_end - timedelta(days=period_days)
        
        # Récupérer toutes les menaces de la période
        threats = await Threat.find(
            Threat.is_active == True,
            Threat.detected_date >= period_start,
            Threat.detected_date <= period_end
        ).to_list()
        
        # Statistiques de base
        total_threats = len(threats)
        critical_threats = sum(1 for t in threats if t.severity == SeverityLevel.CRITICAL)
        high_threats = sum(1 for t in threats if t.severity == SeverityLevel.HIGH)
        
        # Distribution par catégorie
        category_distribution = {}
        for category in ThreatCategory:
            count = sum(1 for t in threats if t.category == category)
            if count > 0:
                category_distribution[category.value] = count
        
        # Distribution par secteur
        sector_distribution = TrendService._analyze_sectors(threats)
        
        # Distribution par région
        region_distribution = TrendService._analyze_regions(threats)
        
        # Menaces tendance (les plus vues)
        trending_threats = sorted(
            threats,
            key=lambda t: t.view_count,
            reverse=True
        )[:10]
        trending_threat_ids = [t.id for t in trending_threats]
        
        # Top tags
        top_tags = TrendService._extract_top_tags(threats, limit=15)
        
        # Top cibles
        top_targets = TrendService._extract_top_targets(threats, limit=10)
        
        # Insights IA
        ai_insights = TrendService._generate_insights(
            threats,
            category_distribution,
            sector_distribution,
            region_distribution
        )
        
        # Prédictions
        predictions = TrendService._generate_predictions(
            threats,
            category_distribution
        )
        
        # Créer l'analyse
        trend_analysis = TrendAnalysis(
            analysis_date=datetime.now(),
            period_start=period_start,
            period_end=period_end,
            total_threats=total_threats,
            critical_threats=critical_threats,
            high_threats=high_threats,
            category_distribution=category_distribution,
            sector_distribution=sector_distribution,
            region_distribution=region_distribution,
            trending_threats=trending_threat_ids,
            top_tags=top_tags,
            top_targets=top_targets,
            ai_insights=ai_insights,
            predictions=predictions
        )
        
        await trend_analysis.insert()
        
        logger.info(f"Created trend analysis for period {period_start} to {period_end}")
        
        return trend_analysis
    
    @staticmethod
    def _analyze_sectors(threats: List[Threat]) -> Dict[str, int]:
        """Analyse la distribution par secteur"""
        sectors = []
        for threat in threats:
            if threat.affected_sectors:
                sectors.extend(threat.affected_sectors)
        
        sector_counts = Counter(sectors)
        return dict(sector_counts.most_common(10))
    
    @staticmethod
    def _analyze_regions(threats: List[Threat]) -> Dict[str, int]:
        """Analyse la distribution par région"""
        regions = []
        for threat in threats:
            if threat.affected_regions:
                regions.extend(threat.affected_regions)
        
        region_counts = Counter(regions)
        return dict(region_counts.most_common())
    
    @staticmethod
    def _extract_top_tags(threats: List[Threat], limit: int = 15) -> List[str]:
        """Extrait les tags les plus fréquents"""
        tags = []
        for threat in threats:
            if threat.tags:
                tags.extend(threat.tags)
        
        tag_counts = Counter(tags)
        return [tag for tag, _ in tag_counts.most_common(limit)]
    
    @staticmethod
    def _extract_top_targets(threats: List[Threat], limit: int = 10) -> List[str]:
        """Extrait les cibles les plus fréquentes"""
        targets = []
        for threat in threats:
            if threat.affected_systems:
                targets.extend(threat.affected_systems)
        
        target_counts = Counter(targets)
        return [target for target, _ in target_counts.most_common(limit)]
    
    @staticmethod
    def _generate_insights(
        threats: List[Threat],
        category_dist: Dict[str, int],
        sector_dist: Dict[str, int],
        region_dist: Dict[str, int]
    ) -> str:
        """Génère des insights à partir des données"""
        insights = []
        
        total = len(threats)
        if total == 0:
            return "Aucune menace détectée durant cette période."
        
        # Insight sur la catégorie dominante
        if category_dist:
            top_category = max(category_dist.items(), key=lambda x: x[1])
            percentage = (top_category[1] / total) * 100
            insights.append(
                f"La catégorie dominante est '{top_category[0]}' avec {top_category[1]} menaces ({percentage:.1f}%)."
            )
        
        # Insight sur le secteur le plus ciblé
        if sector_dist:
            top_sector = max(sector_dist.items(), key=lambda x: x[1])
            insights.append(
                f"Le secteur le plus ciblé est '{top_sector[0]}' avec {top_sector[1]} menaces."
            )
        
        # Insight sur les menaces critiques
        critical_count = sum(1 for t in threats if t.severity == SeverityLevel.CRITICAL)
        if critical_count > 0:
            percentage = (critical_count / total) * 100
            insights.append(
                f"{critical_count} menaces critiques détectées ({percentage:.1f}% du total)."
            )
        
        # Insight sur les CVE
        cve_count = sum(1 for t in threats if t.external_id and t.external_id.startswith('CVE'))
        if cve_count > 0:
            insights.append(
                f"{cve_count} CVE identifiées durant cette période."
            )
        
        # Insight sur les tendances temporelles
        recent_threats = [t for t in threats if (datetime.now() - t.detected_date).days <= 1]
        if len(recent_threats) > total * 0.3:
            insights.append(
                f"Augmentation récente de l'activité : {len(recent_threats)} menaces détectées dans les dernières 24h."
            )
        
        return " ".join(insights)
    
    @staticmethod
    def _generate_predictions(
        threats: List[Threat],
        category_dist: Dict[str, int]
    ) -> Dict[str, Any]:
        """Génère des prédictions simples"""
        predictions = {
            "trend": "stable",
            "risk_level": "medium",
            "recommendations": []
        }
        
        total = len(threats)
        if total == 0:
            return predictions
        
        # Analyser la tendance
        recent_count = sum(1 for t in threats if (datetime.now() - t.detected_date).days <= 2)
        older_count = total - recent_count
        
        if recent_count > older_count * 1.5:
            predictions["trend"] = "increasing"
            predictions["recommendations"].append(
                "Augmentation de l'activité détectée. Renforcer la surveillance."
            )
        elif recent_count < older_count * 0.5:
            predictions["trend"] = "decreasing"
        
        # Niveau de risque
        critical_ratio = sum(1 for t in threats if t.severity == SeverityLevel.CRITICAL) / total
        
        if critical_ratio > 0.2:
            predictions["risk_level"] = "high"
            predictions["recommendations"].append(
                "Niveau de risque élevé. Actions immédiates recommandées."
            )
        elif critical_ratio > 0.1:
            predictions["risk_level"] = "medium-high"
        
        # Recommandations par catégorie
        if category_dist:
            top_category = max(category_dist.items(), key=lambda x: x[1])[0]
            
            category_recommendations = {
                "ransomware": "Vérifier les sauvegardes et former les utilisateurs.",
                "vulnerability": "Appliquer les patches de sécurité rapidement.",
                "phishing": "Renforcer la sensibilisation des utilisateurs.",
                "data_breach": "Auditer les contrôles d'accès aux données.",
                "zero_day": "Activer les systèmes de détection comportementale."
            }
            
            if top_category in category_recommendations:
                predictions["recommendations"].append(
                    category_recommendations[top_category]
                )
        
        return predictions
    
    @staticmethod
    async def get_latest_analysis() -> Optional[TrendAnalysis]:
        """Récupère la dernière analyse de tendances"""
        return await TrendAnalysis.find_all().sort(-TrendAnalysis.analysis_date).first_or_none()
    
    @staticmethod
    async def get_analysis_history(
        limit: int = 30
    ) -> List[TrendAnalysis]:
        """Récupère l'historique des analyses"""
        return await TrendAnalysis.find_all().sort(-TrendAnalysis.analysis_date).limit(limit).to_list()
    
    @staticmethod
    async def update_trending_flags() -> int:
        """
        Met à jour les flags 'is_trending' des menaces
        
        Returns:
            int: Nombre de menaces marquées comme trending
        """
        # Récupérer les menaces de la dernière semaine
        week_ago = datetime.now() - timedelta(days=7)
        
        threats = await Threat.find(
            Threat.is_active == True,
            Threat.detected_date >= week_ago
        ).to_list()
        
        # Calculer un score de trending
        # Facteurs: view_count, récence, sévérité
        scored_threats = []
        for threat in threats:
            days_old = (datetime.now() - threat.detected_date).days + 1
            recency_score = 7 / days_old
            
            severity_score = {
                SeverityLevel.CRITICAL: 5,
                SeverityLevel.HIGH: 4,
                SeverityLevel.MEDIUM: 3,
                SeverityLevel.LOW: 2,
                SeverityLevel.INFO: 1
            }.get(threat.severity, 1)
            
            total_score = (threat.view_count * 0.5) + (recency_score * 2) + severity_score
            
            scored_threats.append((threat, total_score))
        
        # Trier et prendre le top 20%
        scored_threats.sort(key=lambda x: x[1], reverse=True)
        trending_count = max(5, int(len(scored_threats) * 0.2))
        
        # Réinitialiser tous les flags
        for threat in threats:
            threat.is_trending = False
        
        # Marquer les trending et sauvegarder
        for threat, _ in scored_threats[:trending_count]:
            threat.is_trending = True
            await threat.save()
        
        logger.info(f"Updated trending flags: {trending_count} threats marked as trending")
        
        return trending_count

