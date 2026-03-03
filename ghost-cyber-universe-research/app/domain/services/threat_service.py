from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import logging
from beanie import PydanticObjectId
from beanie.operators import In, And, Or, RegEx

from app.models import Threat, ThreatCategory, SeverityLevel
from app.schemas import ThreatCreate, ThreatUpdate, FilterParams
from app.ai.nlp_analyzer import nlp_analyzer
from app.ai.translator import translator

logger = logging.getLogger(__name__)


class ThreatService:
    """Service pour la gestion des menaces"""
    
    @staticmethod
    async def create_threat(
        threat_data: ThreatCreate,
        analyze: bool = True
    ) -> Threat:
        """
        Crée une nouvelle menace avec analyse IA optionnelle
        
        Args:
            threat_data: Données de la menace
            analyze: Effectuer une analyse IA
            
        Returns:
            Threat: Menace créée
        """
        try:
            # Analyse IA si demandée
            analysis = None
            if analyze:
                analysis = await nlp_analyzer.analyze_threat(
                    threat_data.title,
                    threat_data.description,
                    threat_data.category.value if threat_data.category else None,
                    threat_data.severity.value if threat_data.severity else None
                )
                
                # Enrichir les données avec l'analyse
                if not threat_data.category:
                    threat_data.category = ThreatCategory(analysis["category"])
                
                if not threat_data.severity:
                    threat_data.severity = SeverityLevel(analysis["severity"])
            
            # Détecter la langue
            detected_lang = translator.detect_language(
                threat_data.title + " " + threat_data.description
            )
            
            # Créer la menace
            threat_dict = threat_data.model_dump()
            
            # Ajouter les données d'analyse
            if analysis:
                threat_dict["summary"] = analysis.get("summary")
                threat_dict["affected_sectors"] = analysis.get("affected_sectors", [])
                threat_dict["affected_regions"] = analysis.get("affected_regions", [])
                threat_dict["iocs"] = analysis.get("iocs", {})
                
                # Merger les tags
                existing_tags = set(threat_dict.get("tags", []))
                new_tags = set(analysis.get("tags", []))
                threat_dict["tags"] = list(existing_tags | new_tags)[:20]
            
            threat_dict["detected_language"] = detected_lang
            threat_dict["source_type"] = "api"
            
            # Créer l'objet
            threat = Threat(**threat_dict)
            await threat.insert()
            
            logger.info(f"Created threat: {threat.id} - {threat.title}")
            
            return threat
            
        except Exception as e:
            logger.error(f"Error creating threat: {str(e)}")
            raise
    
    @staticmethod
    async def get_threat(threat_id: str) -> Optional[Threat]:
        """Récupère une menace par ID"""
        try:
            threat = await Threat.get(PydanticObjectId(threat_id))
            
            # Incrémenter le compteur de vues
            if threat:
                threat.view_count += 1
                await threat.save()
            
            return threat
        except Exception as e:
            logger.error(f"Error getting threat: {e}")
            return None
    
    @staticmethod
    async def get_threats(
        filters: FilterParams
    ) -> Tuple[List[Threat], int]:
        """
        Récupère les menaces avec filtres et pagination
        
        Returns:
            tuple: (liste de menaces, total)
        """
        # Construire les critères de recherche
        criteria = []
        
        if filters.category:
            criteria.append(Threat.category == filters.category)
        
        if filters.severity:
            criteria.append(Threat.severity == filters.severity)
        
        if filters.source:
            criteria.append(Threat.source_name == filters.source)
        
        if filters.sector:
            criteria.append(In(filters.sector, Threat.affected_sectors))
        
        if filters.region:
            criteria.append(In(filters.region, Threat.affected_regions))
        
        if filters.is_trending is not None:
            criteria.append(Threat.is_trending == filters.is_trending)
        
        if filters.is_active is not None:
            criteria.append(Threat.is_active == filters.is_active)
        
        if filters.date_from:
            criteria.append(Threat.detected_date >= filters.date_from)
        
        if filters.date_to:
            criteria.append(Threat.detected_date <= filters.date_to)
        
        if filters.search:
            # Recherche textuelle
            search_criteria = Or(
                RegEx(Threat.title, filters.search, "i"),
                RegEx(Threat.description, filters.search, "i"),
                RegEx(Threat.external_id, filters.search, "i") if filters.search else None
            )
            criteria.append(search_criteria)
        
        if filters.tags:
            for tag in filters.tags:
                criteria.append(In(tag, Threat.tags))
        
        # Construire la requête
        if criteria:
            query = Threat.find(And(*criteria))
        else:
            query = Threat.find_all()
        
        # Compter le total
        total = await query.count()
        
        # Tri par date (plus récent en premier)
        query = query.sort(-Threat.detected_date)
        
        # Pagination
        skip = (filters.page - 1) * filters.page_size
        threats = await query.skip(skip).limit(filters.page_size).to_list()
        
        return threats, total
    
    @staticmethod
    async def update_threat(
        threat_id: str,
        threat_data: ThreatUpdate
    ) -> Optional[Threat]:
        """Met à jour une menace"""
        threat = await ThreatService.get_threat(threat_id)
        
        if not threat:
            return None
        
        # Mettre à jour les champs fournis
        update_data = threat_data.model_dump(exclude_unset=True)
        
        for field, value in update_data.items():
            setattr(threat, field, value)
        
        threat.updated_date = datetime.now()
        await threat.save()
        
        logger.info(f"Updated threat: {threat_id}")
        
        return threat
    
    @staticmethod
    async def delete_threat(threat_id: str) -> bool:
        """Supprime (désactive) une menace"""
        threat = await ThreatService.get_threat(threat_id)
        
        if not threat:
            return False
        
        threat.is_active = False
        await threat.save()
        
        logger.info(f"Deleted threat: {threat_id}")
        
        return True
    
    @staticmethod
    async def get_trending_threats(limit: int = 10) -> List[Threat]:
        """Récupère les menaces tendance"""
        threats = await Threat.find(
            Threat.is_trending == True,
            Threat.is_active == True
        ).sort(-Threat.view_count).limit(limit).to_list()
        
        return threats
    
    @staticmethod
    async def get_critical_threats(
        days: int = 7,
        limit: int = 20
    ) -> List[Threat]:
        """Récupère les menaces critiques récentes"""
        since_date = datetime.now() - timedelta(days=days)
        
        threats = await Threat.find(
            Threat.severity == SeverityLevel.CRITICAL,
            Threat.is_active == True,
            Threat.detected_date >= since_date
        ).sort(-Threat.detected_date).limit(limit).to_list()
        
        return threats
    
    @staticmethod
    async def get_statistics() -> Dict[str, Any]:
        """Récupère les statistiques globales"""
        now = datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = now - timedelta(days=7)
        month_start = now - timedelta(days=30)
        
        # Totaux
        total_threats = await Threat.find(Threat.is_active == True).count()
        
        # Par période
        threats_today = await Threat.find(
            Threat.is_active == True,
            Threat.detected_date >= today_start
        ).count()
        
        threats_week = await Threat.find(
            Threat.is_active == True,
            Threat.detected_date >= week_start
        ).count()
        
        threats_month = await Threat.find(
            Threat.is_active == True,
            Threat.detected_date >= month_start
        ).count()
        
        # Par sévérité
        critical_count = await Threat.find(
            Threat.is_active == True,
            Threat.severity == SeverityLevel.CRITICAL
        ).count()
        
        high_count = await Threat.find(
            Threat.is_active == True,
            Threat.severity == SeverityLevel.HIGH
        ).count()
        
        # Par catégorie (dernière semaine)
        category_stats = {}
        for category in ThreatCategory:
            count = await Threat.find(
                Threat.is_active == True,
                Threat.category == category,
                Threat.detected_date >= week_start
            ).count()
            category_stats[category.value] = count
        
        return {
            "total_threats": total_threats,
            "threats_today": threats_today,
            "threats_this_week": threats_week,
            "threats_this_month": threats_month,
            "critical_threats": critical_count,
            "high_threats": high_count,
            "category_distribution": category_stats
        }
    
    @staticmethod
    async def translate_threat(
        threat: Threat,
        target_language: str
    ) -> Dict[str, str]:
        """Traduit une menace"""
        return await translator.translate_threat(
            title=threat.title,
            description=threat.description,
            summary=threat.summary,
            target_language=target_language,
            source_language=threat.detected_language
        )
