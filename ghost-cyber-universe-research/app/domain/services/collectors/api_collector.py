import aiohttp
from typing import List, Optional, Any, Dict
from datetime import datetime, timedelta
import logging

from app.collectors.base_collector import BaseCollector
from app.schemas import ThreatCreate
from app.models import SourceType, ThreatCategory, SeverityLevel
from config import settings

logger = logging.getLogger(__name__)


class NVDCollector(BaseCollector):
    """Collecteur pour la NVD (National Vulnerability Database)"""
    
    def __init__(self):
        super().__init__(
            "NVD - NIST",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            SourceType.API
        )
        self.api_key = settings.NVD_API_KEY
        self.days_back = 7  # Collecter les CVE des 7 derniers jours
    
    async def collect(self) -> List[ThreatCreate]:
        """Collecte les CVE récentes depuis NVD"""
        try:
            self.log_info("Début de la collecte NVD")
            
            # Calculer la période
            end_date = datetime.now()
            start_date = end_date - timedelta(days=self.days_back)
            
            # Préparer les paramètres
            params = {
                "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
                "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
            }
            
            headers = {}
            if self.api_key:
                headers["apiKey"] = self.api_key
            
            # Requête API
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.source_url,
                    params=params,
                    headers=headers,
                    timeout=60
                ) as response:
                    if response.status != 200:
                        self.log_error(f"Erreur HTTP {response.status}")
                        return []
                    
                    data = await response.json()
            
            # Parser les résultats
            vulnerabilities = data.get("vulnerabilities", [])
            
            threats = []
            for vuln_item in vulnerabilities:
                threat = await self.parse_item(vuln_item)
                if threat:
                    threats.append(threat)
            
            self.last_update = datetime.now()
            self.log_info(f"Collecte terminée: {len(threats)} CVE collectées")
            
            return threats
            
        except Exception as e:
            self.log_error(f"Erreur lors de la collecte: {str(e)}")
            return []
    
    async def parse_item(self, item: Any) -> Optional[ThreatCreate]:
        """Parse une CVE NVD en ThreatCreate"""
        try:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            
            # Métadonnées
            metadata = cve.get("vulnStatus", "")
            
            # Description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            if not description and descriptions:
                description = descriptions[0].get("value", "")
            
            # Dates
            published = cve.get("published", "")
            published_date = None
            if published:
                try:
                    published_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
                except:
                    pass
            
            # CVSS scores
            cvss_score = None
            cvss_vector = None
            severity_text = "medium"
            
            metrics = cve.get("metrics", {})
            
            # Préférence pour CVSS v3.1
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                severity_text = cvss_data.get("baseSeverity", "MEDIUM").lower()
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                severity_text = cvss_data.get("baseSeverity", "MEDIUM").lower()
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
            
            # Mapper severity NVD vers notre enum
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "none": "info"
            }
            severity = severity_map.get(severity_text, "medium")
            
            # Références
            references = []
            for ref in cve.get("references", []):
                url = ref.get("url")
                if url:
                    references.append(url)
            
            # Configurations affectées
            affected_systems = self._extract_affected_products(cve)
            
            # Tags
            tags = ["cve", "vulnerability"]
            if cvss_score and cvss_score >= 9.0:
                tags.append("critical-vulnerability")
            
            # CWE (Common Weakness Enumeration)
            weaknesses = cve.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_id = desc.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        tags.append(cwe_id.lower())
            
            return ThreatCreate(
                external_id=cve_id,
                title=f"{cve_id}: Vulnerability in {', '.join(affected_systems[:3]) if affected_systems else 'Multiple Products'}",
                description=description[:2000],
                category=ThreatCategory.VULNERABILITY,
                severity=SeverityLevel(severity),
                cvss_score=cvss_score,
                source_name=self.source_name,
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                published_date=published_date,
                tags=tags[:15],
                affected_systems=affected_systems[:10]
            )
            
        except Exception as e:
            logger.error(f"Erreur parsing CVE: {str(e)}")
            return None
    
    def _extract_affected_products(self, cve: Dict) -> List[str]:
        """Extrait les produits affectés depuis les configurations"""
        products = set()
        
        configurations = cve.get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    cpe_uri = cpe.get("criteria", "")
                    # Format CPE: cpe:2.3:a:vendor:product:version:...
                    parts = cpe_uri.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        if vendor != "*" and product != "*":
                            products.add(f"{vendor} {product}".title())
        
        return list(products)


class CISAKEVCollector(BaseCollector):
    """Collecteur pour CISA Known Exploited Vulnerabilities"""
    
    def __init__(self):
        super().__init__(
            "CISA KEV Catalog",
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            SourceType.API
        )
    
    async def collect(self) -> List[ThreatCreate]:
        """Collecte les vulnérabilités exploitées depuis CISA KEV"""
        try:
            self.log_info("Début de la collecte CISA KEV")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.source_url, timeout=30) as response:
                    if response.status != 200:
                        self.log_error(f"Erreur HTTP {response.status}")
                        return []
                    
                    data = await response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Ne collecter que les vulnérabilités récentes (30 derniers jours)
            cutoff_date = datetime.now() - timedelta(days=30)
            
            threats = []
            for vuln in vulnerabilities:
                threat = await self.parse_item(vuln)
                if threat and threat.published_date and threat.published_date >= cutoff_date:
                    threats.append(threat)
            
            self.last_update = datetime.now()
            self.log_info(f"Collecte terminée: {len(threats)} vulnérabilités exploitées")
            
            return threats
            
        except Exception as e:
            self.log_error(f"Erreur lors de la collecte: {str(e)}")
            return []
    
    async def parse_item(self, item: Any) -> Optional[ThreatCreate]:
        """Parse une vulnérabilité KEV en ThreatCreate"""
        try:
            cve_id = item.get("cveID", "")
            vendor = item.get("vendorProject", "")
            product = item.get("product", "")
            vuln_name = item.get("vulnerabilityName", "")
            description = item.get("shortDescription", "")
            required_action = item.get("requiredAction", "")
            
            # Date
            date_added = item.get("dateAdded", "")
            published_date = None
            if date_added:
                try:
                    published_date = datetime.strptime(date_added, "%Y-%m-%d")
                except:
                    pass
            
            # Title
            title = f"{cve_id}: {vuln_name} in {vendor} {product}" if vuln_name else f"{cve_id} in {vendor} {product}"
            
            # Description complète
            full_description = f"{description}\n\nRequired Action: {required_action}"
            
            # Tags - vulnérabilité exploitée activement
            tags = ["cve", "exploited", "actively-exploited", "kev"]
            tags.extend(self._extract_tags(title, description))
            
            return ThreatCreate(
                external_id=cve_id,
                title=title[:500],
                description=full_description,
                category=ThreatCategory.ZERO_DAY,  # Considéré comme critique
                severity=SeverityLevel.CRITICAL,  # Toutes les KEV sont critiques
                source_name=self.source_name,
                source_url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                published_date=published_date,
                tags=tags[:15],
                affected_systems=[f"{vendor} {product}"]
            )
            
        except Exception as e:
            logger.error(f"Erreur parsing KEV: {str(e)}")
            return None

