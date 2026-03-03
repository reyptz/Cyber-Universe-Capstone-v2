from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging
from app.schemas import ThreatCreate
from app.models import SourceType

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Classe de base pour tous les collecteurs de données"""
    
    def __init__(self, source_name: str, source_url: str, source_type: SourceType):
        self.source_name = source_name
        self.source_url = source_url
        self.source_type = source_type
        self.last_update: Optional[datetime] = None
        self.errors: List[str] = []
    
    @abstractmethod
    async def collect(self) -> List[ThreatCreate]:
        """
        Collecte les données depuis la source
        
        Returns:
            List[ThreatCreate]: Liste des menaces collectées
        """
        pass
    
    @abstractmethod
    async def parse_item(self, item: Any) -> Optional[ThreatCreate]:
        """
        Parse un item de la source en ThreatCreate
        
        Args:
            item: Item brut de la source
            
        Returns:
            Optional[ThreatCreate]: Menace parsée ou None si échec
        """
        pass
    
    def _categorize_threat(self, title: str, description: str) -> str:
        """
        Catégorise une menace basé sur les mots-clés
        
        Args:
            title: Titre de la menace
            description: Description de la menace
            
        Returns:
            str: Catégorie de la menace
        """
        text = (title + " " + description).lower()
        
        # Règles de catégorisation basiques
        if any(word in text for word in ["ransomware", "lockbit", "conti", "revil"]):
            return "ransomware"
        elif any(word in text for word in ["breach", "leak", "stolen data", "data theft"]):
            return "data_breach"
        elif any(word in text for word in ["cve-", "vulnerability", "exploit", "patch"]):
            return "vulnerability"
        elif any(word in text for word in ["apt", "advanced persistent", "nation-state", "espionage"]):
            return "apt"
        elif any(word in text for word in ["phishing", "spear phishing", "credential", "social engineering"]):
            return "phishing"
        elif any(word in text for word in ["ddos", "denial of service", "botnet"]):
            return "ddos"
        elif any(word in text for word in ["zero-day", "0-day", "unknown vulnerability"]):
            return "zero_day"
        elif any(word in text for word in ["supply chain", "third-party", "vendor compromise"]):
            return "supply_chain"
        elif any(word in text for word in ["malware", "trojan", "virus", "worm", "backdoor"]):
            return "malware"
        elif any(word in text for word in ["ai security", "machine learning", "deepfake", "llm"]):
            return "ai_security"
        else:
            return "other"
    
    def _calculate_severity(self, cvss_score: Optional[float] = None, text: str = "") -> str:
        """
        Calcule le niveau de gravité
        
        Args:
            cvss_score: Score CVSS si disponible
            text: Texte pour analyse contextuelle
            
        Returns:
            str: Niveau de gravité
        """
        # Si CVSS disponible, l'utiliser
        if cvss_score is not None:
            if cvss_score >= 9.0:
                return "critical"
            elif cvss_score >= 7.0:
                return "high"
            elif cvss_score >= 4.0:
                return "medium"
            elif cvss_score >= 0.1:
                return "low"
            else:
                return "info"
        
        # Sinon, analyse de mots-clés
        text_lower = text.lower()
        
        critical_keywords = ["critical", "urgent", "emergency", "exploit in the wild", "zero-day", "actively exploited"]
        high_keywords = ["high", "severe", "important", "ransomware", "breach"]
        medium_keywords = ["medium", "moderate", "warning"]
        low_keywords = ["low", "minor", "informational"]
        
        if any(keyword in text_lower for keyword in critical_keywords):
            return "critical"
        elif any(keyword in text_lower for keyword in high_keywords):
            return "high"
        elif any(keyword in text_lower for keyword in medium_keywords):
            return "medium"
        elif any(keyword in text_lower for keyword in low_keywords):
            return "low"
        else:
            return "info"
    
    def _extract_tags(self, title: str, description: str) -> List[str]:
        """
        Extrait des tags depuis le titre et la description
        
        Args:
            title: Titre
            description: Description
            
        Returns:
            List[str]: Liste de tags
        """
        tags = []
        text = (title + " " + description).lower()
        
        # Technologies
        tech_keywords = ["windows", "linux", "macos", "android", "ios", "chrome", "firefox", 
                        "safari", "microsoft", "google", "apple", "adobe", "oracle", "cisco"]
        tags.extend([tech for tech in tech_keywords if tech in text])
        
        # Types d'attaque
        attack_keywords = ["ransomware", "phishing", "malware", "ddos", "apt", "exploit", 
                          "vulnerability", "zero-day", "supply chain"]
        tags.extend([attack for attack in attack_keywords if attack.replace(" ", "") in text.replace(" ", "")])
        
        return list(set(tags))[:10]  # Max 10 tags uniques
    
    def log_error(self, error: str):
        """Enregistre une erreur"""
        logger.error(f"[{self.source_name}] {error}")
        self.errors.append(f"{datetime.now()}: {error}")
    
    def log_info(self, message: str):
        """Enregistre une information"""
        logger.info(f"[{self.source_name}] {message}")

