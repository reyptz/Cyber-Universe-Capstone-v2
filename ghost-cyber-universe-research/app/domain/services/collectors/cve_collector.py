"""
Collector CVE - Récupère les CVE depuis l'API NVD
"""

import aiohttp
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict
import logging
from deep_translator import GoogleTranslator

logger = logging.getLogger(__name__)

# Traducteur Google
translator = GoogleTranslator(source='en', target='fr')

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def fetch_recent_cves(days: int = 7, results_per_page: int = 100) -> List[Dict]:
    """Récupère les CVE récents depuis NVD"""
    try:
        # Calculer la date de début
        pub_start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000")
        pub_end_date = datetime.now().strftime("%Y-%m-%dT23:59:59.999")
        
        params = {
            "pubStartDate": pub_start_date,
            "pubEndDate": pub_end_date,
            "resultsPerPage": results_per_page
        }
        
        cves = []
        
        async with aiohttp.ClientSession() as session:
            async with session.get(NVD_API_URL, params=params) as response:
                if response.status != 200:
                    logger.error(f"Erreur API NVD: {response.status}")
                    return []
                
                data = await response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    try:
                        cve_data = vuln.get('cve', {})
                        
                        cve_id = cve_data.get('id', '')
                        
                        # Description
                        descriptions = cve_data.get('descriptions', [])
                        description = ''
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                description = desc.get('value', '')
                                break
                        
                        # CVSS Score
                        metrics = cve_data.get('metrics', {})
                        cvss_score = 0.0
                        cvss_severity = 'UNKNOWN'
                        
                        # CVSS v3.1 ou v3.0
                        if 'cvssMetricV31' in metrics:
                            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        elif 'cvssMetricV30' in metrics:
                            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            cvss_severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        elif 'cvssMetricV2' in metrics:
                            cvss_score = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 0.0)
                            cvss_severity = 'MEDIUM' if cvss_score < 7.0 else 'HIGH'
                        
                        # Date de publication
                        pub_date_str = cve_data.get('published', '')
                        pub_date = datetime.fromisoformat(pub_date_str.replace('Z', '+00:00')) if pub_date_str else datetime.now()
                        
                        # CPE (produits affectés)
                        affected_products = []
                        configurations = cve_data.get('configurations', [])
                        for config in configurations:
                            for node in config.get('nodes', []):
                                for cpe_match in node.get('cpeMatch', []):
                                    if cpe_match.get('vulnerable'):
                                        cpe = cpe_match.get('criteria', '')
                                        # Extraire le produit du CPE
                                        # Format: cpe:2.3:a:vendor:product:version...
                                        parts = cpe.split(':')
                                        if len(parts) >= 5:
                                            product = f"{parts[3]} {parts[4]}"
                                            if product not in affected_products:
                                                affected_products.append(product)
                        
                        # Références
                        references = []
                        for ref in cve_data.get('references', [])[:5]:  # Max 5
                            references.append({
                                'url': ref.get('url', ''),
                                'source': ref.get('source', '')
                            })
                        
                        # Traduire la description
                        try:
                            description_fr = translator.translate(description[:500])
                            summary_fr = description_fr[:300] + "..." if len(description_fr) > 300 else description_fr
                        except Exception as e:
                            logger.warning(f"Erreur traduction CVE: {e}")
                            description_fr = description
                            summary_fr = description[:300] + "..." if len(description) > 300 else description
                        
                        cve_entry = {
                            'cve_id': cve_id,
                            'title': f"{cve_id} - Vulnérabilité",
                            'description': description_fr,  # Traduit
                            'summary': summary_fr,  # Traduit
                            'cvss_score': cvss_score,
                            'cvss_severity': cvss_severity,
                            'published_date': pub_date,
                            'affected_products': affected_products,
                            'references': references,
                            'source_url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            'original_description': description,  # Garder l'original
                        }
                        
                        cves.append(cve_entry)
                        
                    except Exception as e:
                        logger.error(f"Erreur traitement CVE: {e}")
                        continue
        
        logger.info(f"Collecté {len(cves)} CVEs")
        return cves
        
    except Exception as e:
        logger.error(f"Erreur collecte CVE: {e}")
        return []


async def save_cves_to_database(cves: List[Dict]):
    """Sauvegarde les CVE dans MongoDB"""
    from app.models import Threat, Source, ThreatCategory, SeverityLevel, SourceType
    
    saved_count = 0
    
    # Créer/récupérer source NVD
    nvd_source = await Source.find_one(Source.name == "NVD")
    if not nvd_source:
        nvd_source = Source(
            name="NVD",
            url="https://nvd.nist.gov",
            type=SourceType.API,
            is_active=True
        )
        await nvd_source.insert()
    
    for cve_data in cves:
        try:
            # Vérifier si existe
            existing = await Threat.find_one(Threat.source_url == cve_data['source_url'])
            if existing:
                continue
            
            # Mapper sévérité CVSS vers notre enum
            severity_map = {
                'CRITICAL': 'critical',
                'HIGH': 'high',
                'MEDIUM': 'medium',
                'LOW': 'low',
                'UNKNOWN': 'low'
            }
            severity = severity_map.get(cve_data['cvss_severity'], 'medium')
            
            threat = Threat(
                title=cve_data['title'],
                description=cve_data['description'],
                summary=cve_data['summary'],
                category=ThreatCategory.VULNERABILITY,
                severity=SeverityLevel(severity),
                source_id=nvd_source.id,
                source_url=cve_data['source_url'],
                published_date=cve_data['published_date'],
                cvss_score=cve_data['cvss_score'],
                affected_products=cve_data['affected_products'],
                tags=[cve_data['cve_id'], 'cve', 'vulnerability'],
                iocs=[]
            )
            
            await threat.insert()
            saved_count += 1
            
        except Exception as e:
            logger.error(f"Erreur sauvegarde CVE: {e}")
            continue
    
    logger.info(f"Sauvegardé {saved_count} nouveaux CVEs")
    return saved_count


async def run_cve_collection(days: int = 7):
    """Point d'entrée principal"""
    cves = await fetch_recent_cves(days=days)
    saved = await save_cves_to_database(cves)
    return {
        "collected": len(cves),
        "saved": saved,
        "source": "NVD"
    }

