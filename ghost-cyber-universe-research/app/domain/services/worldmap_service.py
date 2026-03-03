from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
import logging
import random
import uuid
from collections import defaultdict

from app.models import (
    CyberAttackEvent, GeoStatistics, GeoLocation,
    ThreatCategory, SeverityLevel
)

logger = logging.getLogger(__name__)


class WorldMapService:
    """Service pour la carte mondiale des cyberattaques"""
    
    # Coordonnées des pays (centres approximatifs)
    COUNTRY_COORDINATES = {
        "US": {"lat": 37.0902, "lon": -95.7129, "name": "United States", "continent": "North America"},
        "CN": {"lat": 35.8617, "lon": 104.1954, "name": "China", "continent": "Asia"},
        "RU": {"lat": 61.5240, "lon": 105.3188, "name": "Russia", "continent": "Europe"},
        "FR": {"lat": 46.2276, "lon": 2.2137, "name": "France", "continent": "Europe"},
        "DE": {"lat": 51.1657, "lon": 10.4515, "name": "Germany", "continent": "Europe"},
        "GB": {"lat": 55.3781, "lon": -3.4360, "name": "United Kingdom", "continent": "Europe"},
        "JP": {"lat": 36.2048, "lon": 138.2529, "name": "Japan", "continent": "Asia"},
        "KR": {"lat": 35.9078, "lon": 127.7669, "name": "South Korea", "continent": "Asia"},
        "IN": {"lat": 20.5937, "lon": 78.9629, "name": "India", "continent": "Asia"},
        "BR": {"lat": -14.2350, "lon": -51.9253, "name": "Brazil", "continent": "South America"},
        "CA": {"lat": 56.1304, "lon": -106.3468, "name": "Canada", "continent": "North America"},
        "AU": {"lat": -25.2744, "lon": 133.7751, "name": "Australia", "continent": "Oceania"},
        "IL": {"lat": 31.0461, "lon": 34.8516, "name": "Israel", "continent": "Asia"},
        "NL": {"lat": 52.1326, "lon": 5.2913, "name": "Netherlands", "continent": "Europe"},
        "SE": {"lat": 60.1282, "lon": 18.6435, "name": "Sweden", "continent": "Europe"},
        "SG": {"lat": 1.3521, "lon": 103.8198, "name": "Singapore", "continent": "Asia"},
        "AE": {"lat": 23.4241, "lon": 53.8478, "name": "UAE", "continent": "Asia"},
        "TR": {"lat": 38.9637, "lon": 35.2433, "name": "Turkey", "continent": "Asia"},
        "PL": {"lat": 51.9194, "lon": 19.1451, "name": "Poland", "continent": "Europe"},
        "IT": {"lat": 41.8719, "lon": 12.5674, "name": "Italy", "continent": "Europe"},
        "ES": {"lat": 40.4637, "lon": -3.7492, "name": "Spain", "continent": "Europe"},
        "MX": {"lat": 23.6345, "lon": -102.5528, "name": "Mexico", "continent": "North America"},
        "ZA": {"lat": -30.5595, "lon": 22.9375, "name": "South Africa", "continent": "Africa"},
        "NG": {"lat": 9.0820, "lon": 8.6753, "name": "Nigeria", "continent": "Africa"},
        "EG": {"lat": 26.8206, "lon": 30.8025, "name": "Egypt", "continent": "Africa"},
        "SA": {"lat": 23.8859, "lon": 45.0792, "name": "Saudi Arabia", "continent": "Asia"},
        "IR": {"lat": 32.4279, "lon": 53.6880, "name": "Iran", "continent": "Asia"},
        "PK": {"lat": 30.3753, "lon": 69.3451, "name": "Pakistan", "continent": "Asia"},
        "ID": {"lat": -0.7893, "lon": 113.9213, "name": "Indonesia", "continent": "Asia"},
        "TH": {"lat": 15.8700, "lon": 100.9925, "name": "Thailand", "continent": "Asia"},
        "VN": {"lat": 14.0583, "lon": 108.2772, "name": "Vietnam", "continent": "Asia"},
        "MY": {"lat": 4.2105, "lon": 101.9758, "name": "Malaysia", "continent": "Asia"},
        "PH": {"lat": 12.8797, "lon": 121.7740, "name": "Philippines", "continent": "Asia"},
        "AR": {"lat": -38.4161, "lon": -63.6167, "name": "Argentina", "continent": "South America"},
        "CL": {"lat": -35.6751, "lon": -71.5430, "name": "Chile", "continent": "South America"},
        "CO": {"lat": 4.5709, "lon": -74.2973, "name": "Colombia", "continent": "South America"},
        "UA": {"lat": 48.3794, "lon": 31.1656, "name": "Ukraine", "continent": "Europe"},
        "RO": {"lat": 45.9432, "lon": 24.9668, "name": "Romania", "continent": "Europe"},
        "CZ": {"lat": 49.8175, "lon": 15.4730, "name": "Czech Republic", "continent": "Europe"},
        "GR": {"lat": 39.0742, "lon": 21.8243, "name": "Greece", "continent": "Europe"},
        "PT": {"lat": 39.3999, "lon": -8.2245, "name": "Portugal", "continent": "Europe"},
        "NO": {"lat": 60.4720, "lon": 8.4689, "name": "Norway", "continent": "Europe"},
        "FI": {"lat": 61.9241, "lon": 25.7482, "name": "Finland", "continent": "Europe"},
        "DK": {"lat": 56.2639, "lon": 9.5018, "name": "Denmark", "continent": "Europe"},
        "BE": {"lat": 50.5039, "lon": 4.4699, "name": "Belgium", "continent": "Europe"},
        "AT": {"lat": 47.5162, "lon": 14.5501, "name": "Austria", "continent": "Europe"},
        "CH": {"lat": 46.8182, "lon": 8.2275, "name": "Switzerland", "continent": "Europe"},
        "IE": {"lat": 53.4129, "lon": -8.2439, "name": "Ireland", "continent": "Europe"},
        "NZ": {"lat": -40.9006, "lon": 174.8860, "name": "New Zealand", "continent": "Oceania"},
    }
    
    @staticmethod
    async def create_attack_event(
        source_country: str,
        target_country: str,
        attack_type: ThreatCategory,
        severity: SeverityLevel,
        source_name: str = "CyberRadar",
        title: Optional[str] = None,
        **kwargs
    ) -> CyberAttackEvent:
        """
        Crée un événement d'attaque géolocalisé
        
        Args:
            source_country: Code pays source (ISO alpha-2)
            target_country: Code pays cible
            attack_type: Type d'attaque
            severity: Niveau de gravité
            source_name: Source de données
            title: Titre de l'attaque
            **kwargs: Paramètres additionnels
            
        Returns:
            CyberAttackEvent: Événement créé
        """
        # Récupérer les coordonnées
        source_coords = WorldMapService.COUNTRY_COORDINATES.get(
            source_country.upper(),
            {"lat": 0, "lon": 0, "name": source_country, "continent": "Unknown"}
        )
        target_coords = WorldMapService.COUNTRY_COORDINATES.get(
            target_country.upper(),
            {"lat": 0, "lon": 0, "name": target_country, "continent": "Unknown"}
        )
        
        # Créer les localisations
        source_location = GeoLocation(
            latitude=source_coords["lat"],
            longitude=source_coords["lon"],
            country=source_coords["name"],
            country_code=source_country.upper(),
            continent=source_coords["continent"]
        )
        
        target_location = GeoLocation(
            latitude=target_coords["lat"],
            longitude=target_coords["lon"],
            country=target_coords["name"],
            country_code=target_country.upper(),
            continent=target_coords["continent"]
        )
        
        # Générer un ID unique
        event_id = str(uuid.uuid4())
        
        # Titre par défaut
        if not title:
            title = f"{attack_type.value.title()} attack from {source_coords['name']} to {target_coords['name']}"
        
        # Timestamp d'attaque (maintenant ou fourni)
        attack_timestamp = kwargs.get("attack_timestamp", datetime.now())
        
        # TTL : expiration après 24h
        expires_at = datetime.now() + timedelta(hours=24)
        
        # Créer l'événement
        event = CyberAttackEvent(
            event_id=event_id,
            source_location=source_location,
            target_location=target_location,
            attack_type=attack_type,
            severity=severity,
            title=title,
            description=kwargs.get("description"),
            protocol=kwargs.get("protocol"),
            port=kwargs.get("port"),
            source_ip=kwargs.get("source_ip"),
            target_ip=kwargs.get("target_ip"),
            source_name=source_name,
            attack_timestamp=attack_timestamp,
            packet_count=kwargs.get("packet_count"),
            data_volume_bytes=kwargs.get("data_volume_bytes"),
            duration_seconds=kwargs.get("duration_seconds"),
            is_active=kwargs.get("is_active", True),
            is_blocked=kwargs.get("is_blocked", False),
            expires_at=expires_at
        )
        
        await event.insert()
        
        logger.info(f"Created cyber attack event: {event_id} - {title}")
        
        return event
    
    @staticmethod
    async def get_live_attacks(
        minutes: int = 60,
        attack_type: Optional[ThreatCategory] = None,
        severity: Optional[SeverityLevel] = None,
        source_country: Optional[str] = None,
        target_country: Optional[str] = None,
        continent: Optional[str] = None,
        limit: int = 1000
    ) -> List[CyberAttackEvent]:
        """
        Récupère les attaques récentes (temps réel)
        
        Args:
            minutes: Nombre de minutes dans le passé
            attack_type: Filtrer par type
            severity: Filtrer par gravité
            source_country: Filtrer par pays source
            target_country: Filtrer par pays cible
            continent: Filtrer par continent
            limit: Nombre maximum d'événements
            
        Returns:
            List[CyberAttackEvent]: Liste d'événements
        """
        # Calculer la période
        since = datetime.now() - timedelta(minutes=minutes)
        
        # Construire les filtres
        criteria = [
            CyberAttackEvent.is_active == True,
            CyberAttackEvent.attack_timestamp >= since
        ]
        
        if attack_type:
            criteria.append(CyberAttackEvent.attack_type == attack_type)
        
        if severity:
            criteria.append(CyberAttackEvent.severity == severity)
        
        if source_country:
            criteria.append(CyberAttackEvent.source_location.country_code == source_country.upper())
        
        if target_country:
            criteria.append(CyberAttackEvent.target_location.country_code == target_country.upper())
        
        if continent:
            from beanie.operators import Or
            criteria.append(
                Or(
                    CyberAttackEvent.source_location.continent == continent,
                    CyberAttackEvent.target_location.continent == continent
                )
            )
        
        # Exécuter la requête
        from beanie.operators import And
        events = await CyberAttackEvent.find(
            And(*criteria)
        ).sort(-CyberAttackEvent.attack_timestamp).limit(limit).to_list()
        
        return events
    
    @staticmethod
    async def get_realtime_statistics(minutes: int = 60) -> Dict[str, Any]:
        """
        Statistiques en temps réel
        
        Args:
            minutes: Période en minutes
            
        Returns:
            Dict: Statistiques agrégées
        """
        since = datetime.now() - timedelta(minutes=minutes)
        
        # Récupérer tous les événements de la période
        events = await CyberAttackEvent.find(
            CyberAttackEvent.is_active == True,
            CyberAttackEvent.attack_timestamp >= since
        ).to_list()
        
        # Agréger les stats
        total_attacks = len(events)
        
        # Par type
        attacks_by_type = defaultdict(int)
        for event in events:
            attacks_by_type[event.attack_type.value] += 1
        
        # Par gravité
        attacks_by_severity = defaultdict(int)
        for event in events:
            attacks_by_severity[event.severity.value] += 1
        
        # Top pays sources
        source_countries = defaultdict(int)
        for event in events:
            source_countries[event.source_location.country_code] += 1
        
        top_source_countries = sorted(
            source_countries.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # Top pays cibles
        target_countries = defaultdict(int)
        for event in events:
            target_countries[event.target_location.country_code] += 1
        
        top_target_countries = sorted(
            target_countries.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]
        
        # Top continents
        continents = defaultdict(int)
        for event in events:
            continents[event.source_location.continent] += 1
            continents[event.target_location.continent] += 1
        
        # Attaques par heure (dernières 24h si demandé)
        attacks_per_hour = defaultdict(int)
        for event in events:
            hour = event.attack_timestamp.strftime("%Y-%m-%d %H:00")
            attacks_per_hour[hour] += 1
        
        return {
            "period_minutes": minutes,
            "total_attacks": total_attacks,
            "attacks_by_type": dict(attacks_by_type),
            "attacks_by_severity": dict(attacks_by_severity),
            "top_source_countries": [
                {
                    "country_code": code,
                    "country_name": WorldMapService.COUNTRY_COORDINATES.get(code, {}).get("name", code),
                    "count": count
                }
                for code, count in top_source_countries
            ],
            "top_target_countries": [
                {
                    "country_code": code,
                    "country_name": WorldMapService.COUNTRY_COORDINATES.get(code, {}).get("name", code),
                    "count": count
                }
                for code, count in top_target_countries
            ],
            "attacks_by_continent": dict(continents),
            "attacks_per_hour": dict(sorted(attacks_per_hour.items()))
        }
    
    @staticmethod
    async def generate_simulated_attacks(count: int = 50) -> List[CyberAttackEvent]:
        """
        Génère des attaques simulées pour démo
        
        Args:
            count: Nombre d'attaques à générer
            
        Returns:
            List[CyberAttackEvent]: Attaques générées
        """
        events = []
        countries = list(WorldMapService.COUNTRY_COORDINATES.keys())
        
        attack_types = list(ThreatCategory)
        severities = list(SeverityLevel)
        protocols = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "FTP", "DNS", "SMTP"]
        
        for _ in range(count):
            # Choisir aléatoirement
            source = random.choice(countries)
            target = random.choice([c for c in countries if c != source])
            attack_type = random.choice(attack_types)
            severity = random.choice(severities)
            protocol = random.choice(protocols)
            
            # Timestamp aléatoire dans les dernières heures
            minutes_ago = random.randint(0, 180)  # 0-3h
            attack_time = datetime.now() - timedelta(minutes=minutes_ago)
            
            event = await WorldMapService.create_attack_event(
                source_country=source,
                target_country=target,
                attack_type=attack_type,
                severity=severity,
                source_name="Simulated",
                protocol=protocol,
                port=random.randint(1, 65535),
                attack_timestamp=attack_time,
                packet_count=random.randint(100, 100000),
                data_volume_bytes=random.randint(1024, 1024*1024*100)
            )
            
            events.append(event)
        
        logger.info(f"Generated {count} simulated cyber attacks")
        
        return events
    
    @staticmethod
    async def cleanup_old_events(hours: int = 24) -> int:
        """
        Nettoie les événements anciens
        
        Args:
            hours: Âge maximum en heures
            
        Returns:
            int: Nombre d'événements supprimés
        """
        cutoff = datetime.now() - timedelta(hours=hours)
        
        result = await CyberAttackEvent.find(
            CyberAttackEvent.attack_timestamp < cutoff
        ).delete()
        
        logger.info(f"Cleaned up {result.deleted_count} old attack events")
        
        return result.deleted_count
    
    @staticmethod
    async def get_country_heatmap() -> Dict[str, int]:
        """
        Génère une heatmap des pays par nombre d'attaques
        
        Returns:
            Dict: {country_code: attack_count}
        """
        # Dernières 24h
        since = datetime.now() - timedelta(hours=24)
        
        events = await CyberAttackEvent.find(
            CyberAttackEvent.is_active == True,
            CyberAttackEvent.attack_timestamp >= since
        ).to_list()
        
        heatmap = defaultdict(int)
        
        for event in events:
            # Compter source ET cible
            heatmap[event.source_location.country_code] += 1
            heatmap[event.target_location.country_code] += 1
        
        return dict(heatmap)

