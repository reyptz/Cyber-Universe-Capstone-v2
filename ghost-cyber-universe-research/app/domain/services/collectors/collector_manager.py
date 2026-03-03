import asyncio
from typing import List, Dict
from datetime import datetime
import logging

from app.collectors.rss_collector import (
    CISAFeedCollector,
    CERTFRCollector,
    TheHackerNewsCollector,
    BleepingComputerCollector,
    KrebsSecurityCollector
)
from app.collectors.api_collector import NVDCollector, CISAKEVCollector
from app.schemas import ThreatCreate
from config import settings

logger = logging.getLogger(__name__)


class CollectorManager:
    """Gestionnaire central pour tous les collecteurs de données"""
    
    def __init__(self):
        self.collectors = []
        self._init_collectors()
    
    def _init_collectors(self):
        """Initialise tous les collecteurs actifs"""
        
        # Collecteurs RSS
        if settings.ENABLE_CISA_FEED:
            self.collectors.append(CISAFeedCollector())
        
        if settings.ENABLE_CERT_FEED:
            self.collectors.append(CERTFRCollector())
        
        if settings.ENABLE_HACKERNEWS_FEED:
            self.collectors.append(TheHackerNewsCollector())
            self.collectors.append(BleepingComputerCollector())
            self.collectors.append(KrebsSecurityCollector())
        
        # Collecteurs API
        if settings.ENABLE_CVE_FEED:
            self.collectors.append(NVDCollector())
            self.collectors.append(CISAKEVCollector())
        
        logger.info(f"Initialized {len(self.collectors)} collectors")
    
    async def collect_all(self) -> Dict[str, List[ThreatCreate]]:
        """
        Collecte depuis toutes les sources en parallèle
        
        Returns:
            Dict[str, List[ThreatCreate]]: Menaces par source
        """
        logger.info("Starting collection from all sources...")
        
        # Collecter en parallèle
        tasks = []
        for collector in self.collectors:
            tasks.append(self._collect_with_error_handling(collector))
        
        results = await asyncio.gather(*tasks)
        
        # Organiser par source
        threats_by_source = {}
        total_threats = 0
        
        for i, threats in enumerate(results):
            collector = self.collectors[i]
            threats_by_source[collector.source_name] = threats
            total_threats += len(threats)
            
            logger.info(
                f"Collected {len(threats)} threats from {collector.source_name}"
            )
        
        logger.info(f"Total threats collected: {total_threats}")
        
        return threats_by_source
    
    async def collect_from_source(self, source_name: str) -> List[ThreatCreate]:
        """
        Collecte depuis une source spécifique
        
        Args:
            source_name: Nom de la source
            
        Returns:
            List[ThreatCreate]: Menaces collectées
        """
        for collector in self.collectors:
            if collector.source_name == source_name:
                return await self._collect_with_error_handling(collector)
        
        logger.warning(f"Collector not found for source: {source_name}")
        return []
    
    async def _collect_with_error_handling(self, collector) -> List[ThreatCreate]:
        """
        Collecte avec gestion d'erreurs
        
        Args:
            collector: Instance du collecteur
            
        Returns:
            List[ThreatCreate]: Menaces collectées (vide si erreur)
        """
        try:
            return await collector.collect()
        except Exception as e:
            logger.error(
                f"Error collecting from {collector.source_name}: {str(e)}"
            )
            return []
    
    def get_collector_status(self) -> List[Dict]:
        """
        Retourne le statut de tous les collecteurs
        
        Returns:
            List[Dict]: Statut de chaque collecteur
        """
        status = []
        for collector in self.collectors:
            status.append({
                "name": collector.source_name,
                "type": collector.source_type.value,
                "url": collector.source_url,
                "last_update": collector.last_update,
                "errors": collector.errors[-5:] if collector.errors else []
            })
        
        return status


# Instance globale
collector_manager = CollectorManager()

