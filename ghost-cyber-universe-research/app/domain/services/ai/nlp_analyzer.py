from typing import Dict, List, Optional, Tuple
import re
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Imports conditionnels pour les modèles (optionnels)
try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    logger.warning("Transformers not available. Using rule-based NLP only.")


class NLPAnalyzer:
    """Analyseur NLP pour classification et analyse des menaces"""
    
    def __init__(self, use_ml_models: bool = False):
        self.use_ml_models = use_ml_models and TRANSFORMERS_AVAILABLE
        
        if self.use_ml_models:
            try:
                # Initialiser le modèle de classification (léger)
                # Note: En production, utiliser un modèle fine-tuné sur des données cyber
                self.classifier = pipeline(
                    "zero-shot-classification",
                    model="facebook/bart-large-mnli",
                    device=-1  # CPU
                )
                
                # Modèle de summarization
                self.summarizer = pipeline(
                    "summarization",
                    model="facebook/bart-large-cnn",
                    device=-1
                )
                
                logger.info("ML models loaded successfully")
            except Exception as e:
                logger.error(f"Error loading ML models: {e}")
                self.use_ml_models = False
    
    async def analyze_threat(
        self,
        title: str,
        description: str,
        existing_category: Optional[str] = None,
        existing_severity: Optional[str] = None
    ) -> Dict:
        """
        Analyse complète d'une menace
        
        Args:
            title: Titre de la menace
            description: Description de la menace
            existing_category: Catégorie existante (optionnelle)
            existing_severity: Sévérité existante (optionnelle)
            
        Returns:
            Dict: Résultats de l'analyse
        """
        text = f"{title}. {description}"
        
        # Classification si non fournie
        category = existing_category
        if not category and self.use_ml_models:
            category = await self._classify_ml(text)
        elif not category:
            category = self._classify_rule_based(text)
        
        # Évaluation de sévérité
        severity = existing_severity
        if not severity:
            severity = self._evaluate_severity(text)
        
        # Génération du résumé
        summary = await self.generate_summary(description)
        
        # Extraction d'entités
        entities = self._extract_entities(text)
        
        # Tags avancés
        tags = self._extract_advanced_tags(text)
        
        # Secteurs affectés
        affected_sectors = self._identify_affected_sectors(text)
        
        # Régions géographiques
        affected_regions = self._identify_regions(text)
        
        # IOCs (Indicators of Compromise)
        iocs = self._extract_iocs(text)
        
        return {
            "category": category,
            "severity": severity,
            "summary": summary,
            "entities": entities,
            "tags": tags,
            "affected_sectors": affected_sectors,
            "affected_regions": affected_regions,
            "iocs": iocs,
            "confidence": self._calculate_confidence(text)
        }
    
    async def _classify_ml(self, text: str) -> str:
        """Classification par ML"""
        try:
            categories = [
                "ransomware attack",
                "data breach",
                "software vulnerability",
                "advanced persistent threat",
                "malware infection",
                "phishing campaign",
                "DDoS attack",
                "zero-day exploit",
                "supply chain attack",
                "AI security threat"
            ]
            
            result = self.classifier(text[:512], categories)
            
            # Mapper vers nos catégories
            label_map = {
                "ransomware attack": "ransomware",
                "data breach": "data_breach",
                "software vulnerability": "vulnerability",
                "advanced persistent threat": "apt",
                "malware infection": "malware",
                "phishing campaign": "phishing",
                "DDoS attack": "ddos",
                "zero-day exploit": "zero_day",
                "supply chain attack": "supply_chain",
                "AI security threat": "ai_security"
            }
            
            return label_map.get(result["labels"][0], "other")
        except:
            return self._classify_rule_based(text)
    
    def _classify_rule_based(self, text: str) -> str:
        """Classification basée sur des règles"""
        text_lower = text.lower()
        
        # Patterns de classification
        patterns = {
            "ransomware": [
                r"ransomware", r"lockbit", r"conti", r"revil", r"ryuk",
                r"encrypted files", r"ransom demand", r"pay.*bitcoin"
            ],
            "data_breach": [
                r"data breach", r"leaked", r"stolen.*data", r"exposed.*records",
                r"database.*dump", r"credentials.*leaked", r"personal information.*exposed"
            ],
            "vulnerability": [
                r"cve-\d{4}-\d{4,}", r"vulnerability", r"exploit", r"patch",
                r"security flaw", r"bug.*fix", r"security update"
            ],
            "apt": [
                r"apt\d*", r"advanced.*persistent.*threat", r"nation.*state",
                r"espionage", r"targeted.*attack", r"cyber.*warfare"
            ],
            "phishing": [
                r"phishing", r"spear.*phishing", r"credential.*harvest",
                r"fake.*login", r"social.*engineering", r"malicious.*email"
            ],
            "ddos": [
                r"ddos", r"denial.*of.*service", r"botnet", r"amplification.*attack",
                r"flooding.*attack"
            ],
            "zero_day": [
                r"zero[- ]day", r"0[- ]day", r"unknown.*vulnerability",
                r"exploited.*before.*patch", r"no.*patch.*available"
            ],
            "supply_chain": [
                r"supply.*chain", r"third[- ]party", r"vendor.*compromise",
                r"software.*supply.*chain", r"dependency.*attack"
            ],
            "malware": [
                r"malware", r"trojan", r"virus", r"worm", r"backdoor",
                r"remote.*access.*tool", r"rat\b", r"infostealer"
            ],
            "ai_security": [
                r"ai.*security", r"machine.*learning.*attack", r"deepfake",
                r"llm.*vulnerability", r"prompt.*injection", r"model.*poisoning"
            ]
        }
        
        # Compter les correspondances
        scores = {}
        for category, pattern_list in patterns.items():
            score = 0
            for pattern in pattern_list:
                matches = len(re.findall(pattern, text_lower))
                score += matches
            scores[category] = score
        
        # Retourner la catégorie avec le score le plus élevé
        if max(scores.values()) > 0:
            return max(scores, key=scores.get)
        
        return "other"
    
    def _evaluate_severity(self, text: str) -> str:
        """Évalue la sévérité basée sur des indicateurs"""
        text_lower = text.lower()
        
        critical_indicators = [
            "critical", "urgent", "emergency", "actively exploited",
            "zero-day", "widespread", "massive", "wormable",
            "remote code execution", "rce", "unauthenticated"
        ]
        
        high_indicators = [
            "high", "severe", "important", "privilege escalation",
            "authentication bypass", "ransomware", "data breach"
        ]
        
        medium_indicators = [
            "medium", "moderate", "denial of service", "information disclosure"
        ]
        
        low_indicators = [
            "low", "minor", "informational"
        ]
        
        # Calculer le score
        critical_count = sum(1 for ind in critical_indicators if ind in text_lower)
        high_count = sum(1 for ind in high_indicators if ind in text_lower)
        medium_count = sum(1 for ind in medium_indicators if ind in text_lower)
        low_count = sum(1 for ind in low_indicators if ind in text_lower)
        
        if critical_count >= 2:
            return "critical"
        elif critical_count >= 1 or high_count >= 2:
            return "high"
        elif high_count >= 1 or medium_count >= 2:
            return "medium"
        elif medium_count >= 1 or low_count >= 1:
            return "low"
        else:
            return "info"
    
    async def generate_summary(self, description: str, max_length: int = 150) -> str:
        """
        Génère un résumé de la description
        
        Args:
            description: Description complète
            max_length: Longueur maximale du résumé
            
        Returns:
            str: Résumé
        """
        if not description:
            return ""
        
        # Si ML disponible et texte assez long
        if self.use_ml_models and len(description) > 200:
            try:
                result = self.summarizer(
                    description[:1024],
                    max_length=max_length,
                    min_length=30,
                    do_sample=False
                )
                return result[0]["summary_text"]
            except:
                pass
        
        # Sinon, résumé simple (premières phrases)
        sentences = description.split(". ")
        summary = ""
        for sentence in sentences:
            if len(summary) + len(sentence) < max_length:
                summary += sentence + ". "
            else:
                break
        
        return summary.strip() if summary else description[:max_length]
    
    def _extract_entities(self, text: str) -> Dict[str, List[str]]:
        """Extrait les entités nommées"""
        entities = {
            "cves": [],
            "organizations": [],
            "products": [],
            "malware_families": []
        }
        
        # CVEs
        cves = re.findall(r'CVE-\d{4}-\d{4,}', text, re.IGNORECASE)
        entities["cves"] = list(set([cve.upper() for cve in cves]))
        
        # Familles de malware connues
        malware_patterns = [
            "LockBit", "Conti", "REvil", "BlackCat", "Hive",
            "Emotet", "TrickBot", "Qbot", "IcedID", "Cobalt Strike"
        ]
        for malware in malware_patterns:
            if malware.lower() in text.lower():
                entities["malware_families"].append(malware)
        
        return entities
    
    def _extract_advanced_tags(self, text: str) -> List[str]:
        """Extrait des tags avancés"""
        tags = set()
        text_lower = text.lower()
        
        # Techniques d'attaque (basé sur MITRE ATT&CK)
        techniques = {
            "lateral movement": ["lateral movement", "move laterally"],
            "privilege escalation": ["privilege escalation", "elevate privileges"],
            "credential access": ["credential dumping", "credential theft", "password spray"],
            "persistence": ["persistence", "backdoor", "maintain access"],
            "command and control": ["c2", "command and control", "c&c"],
            "exfiltration": ["exfiltration", "data theft", "steal data"],
            "initial access": ["initial access", "entry point", "phishing"],
        }
        
        for tag, keywords in techniques.items():
            if any(kw in text_lower for kw in keywords):
                tags.add(tag.replace(" ", "-"))
        
        # Vecteurs d'attaque
        vectors = ["email", "web", "network", "usb", "supply-chain", "cloud", "mobile"]
        for vector in vectors:
            if vector in text_lower:
                tags.add(f"{vector}-vector")
        
        return list(tags)[:15]
    
    def _identify_affected_sectors(self, text: str) -> List[str]:
        """Identifie les secteurs affectés"""
        sectors = {
            "Healthcare": ["healthcare", "hospital", "medical", "health"],
            "Finance": ["financial", "bank", "finance", "fintech"],
            "Government": ["government", "public sector", "federal", "state"],
            "Energy": ["energy", "power", "utility", "oil", "gas"],
            "Manufacturing": ["manufacturing", "industrial", "factory"],
            "Education": ["education", "university", "school"],
            "Retail": ["retail", "e-commerce", "store"],
            "Technology": ["technology", "software", "tech company"],
            "Critical Infrastructure": ["critical infrastructure", "scada", "ics"],
        }
        
        text_lower = text.lower()
        affected = []
        
        for sector, keywords in sectors.items():
            if any(kw in text_lower for kw in keywords):
                affected.append(sector)
        
        return affected
    
    def _identify_regions(self, text: str) -> List[str]:
        """Identifie les régions géographiques mentionnées"""
        regions = []
        text_lower = text.lower()
        
        # Continents/régions
        region_keywords = {
            "North America": ["united states", "usa", "us ", "canada", "mexico"],
            "Europe": ["europe", "european", "eu ", "uk", "germany", "france"],
            "Asia": ["asia", "china", "japan", "india", "korea"],
            "Middle East": ["middle east", "israel", "saudi", "uae"],
            "Africa": ["africa", "african"],
            "Latin America": ["latin america", "brazil", "argentina"],
            "Oceania": ["australia", "new zealand"],
        }
        
        for region, keywords in region_keywords.items():
            if any(kw in text_lower for kw in keywords):
                regions.append(region)
        
        return regions
    
    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extrait les IOCs (Indicators of Compromise)"""
        iocs = {
            "ip_addresses": [],
            "domains": [],
            "urls": [],
            "file_hashes": [],
            "email_addresses": []
        }
        
        # IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, text)
        iocs["ip_addresses"] = [ip for ip in ips if self._is_valid_ip(ip)]
        
        # Domaines
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        iocs["domains"] = re.findall(domain_pattern, text.lower())[:10]
        
        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        iocs["urls"] = re.findall(url_pattern, text)[:10]
        
        # Hashes (MD5, SHA1, SHA256)
        hash_pattern = r'\b[a-f0-9]{32,64}\b'
        iocs["file_hashes"] = re.findall(hash_pattern, text.lower())[:10]
        
        # Emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs["email_addresses"] = re.findall(email_pattern, text)[:10]
        
        return iocs
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Vérifie si une IP est valide"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def _calculate_confidence(self, text: str) -> float:
        """Calcule un score de confiance pour l'analyse"""
        # Facteurs de confiance
        score = 0.5  # Base
        
        # Plus de texte = plus de confiance
        if len(text) > 500:
            score += 0.2
        elif len(text) > 200:
            score += 0.1
        
        # Présence de CVE = plus de confiance
        if re.search(r'CVE-\d{4}-\d{4,}', text):
            score += 0.15
        
        # Présence de termes techniques = plus de confiance
        tech_terms = ["vulnerability", "exploit", "patch", "malware", "attack"]
        if sum(1 for term in tech_terms if term in text.lower()) >= 3:
            score += 0.15
        
        return min(score, 1.0)


# Instance globale
nlp_analyzer = NLPAnalyzer(use_ml_models=False)  # Démarrer en mode rule-based

