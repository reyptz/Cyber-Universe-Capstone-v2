"""
Collector RSS - Récupère les actualités cyber depuis les flux RSS
"""

import feedparser
import asyncio
from datetime import datetime
from typing import List, Dict
import logging
from bs4 import BeautifulSoup
import re
from deep_translator import GoogleTranslator

logger = logging.getLogger(__name__)

# Traducteur Google (Anglais → Français)
translator = GoogleTranslator(source='en', target='fr')

# Sources RSS fiables
RSS_FEEDS = {
    "thehackernews": "https://feeds.feedburner.com/TheHackersNews",
    "bleepingcomputer": "https://www.bleepingcomputer.com/feed/",
    "securityweek": "https://www.securityweek.com/feed/",
    "threatpost": "https://threatpost.com/feed/",
    "darkreading": "https://www.darkreading.com/rss.xml",
    "krebsonsecurity": "https://krebsonsecurity.com/feed/",
}


def clean_html(raw_html: str) -> str:
    """Nettoie le HTML pour extraire le texte"""
    if not raw_html:
        return ""
    soup = BeautifulSoup(raw_html, 'html.parser')
    text = soup.get_text(separator=' ', strip=True)
    # Limiter à 500 caractères pour le résumé
    return text[:500] + "..." if len(text) > 500 else text


def categorize_threat(title: str, description: str) -> str:
    """Catégorise automatiquement la menace"""
    text = (title + " " + description).lower()
    
    if any(word in text for word in ['ransomware', 'lockbit', 'revil']):
        return 'ransomware'
    elif any(word in text for word in ['phishing', 'scam', 'fraud']):
        return 'phishing'
    elif any(word in text for word in ['malware', 'trojan', 'virus']):
        return 'malware'
    elif any(word in text for word in ['vulnerability', 'cve-', 'exploit', 'patch']):
        return 'vulnerability'
    elif any(word in text for word in ['ddos', 'botnet']):
        return 'ddos'
    elif any(word in text for word in ['apt', 'espionage', 'nation-state']):
        return 'apt'
    elif any(word in text for word in ['data breach', 'leak', 'stolen']):
        return 'data_breach'
    else:
        return 'other'


def assess_severity(title: str, description: str) -> str:
    """Évalue la sévérité"""
    text = (title + " " + description).lower()
    
    critical_keywords = ['critical', 'zero-day', 'actively exploited', 'emergency', 'widespread']
    high_keywords = ['severe', 'serious', 'major', 'ransomware']
    
    if any(word in text for word in critical_keywords):
        return 'critical'
    elif any(word in text for word in high_keywords):
        return 'high'
    elif 'patch' in text or 'update' in text:
        return 'medium'
    else:
        return 'low'


async def collect_from_rss(feed_url: str, source_name: str) -> List[Dict]:
    """Collecte les articles d'un flux RSS"""
    try:
        # Parser le flux RSS
        feed = await asyncio.to_thread(feedparser.parse, feed_url)
        
        articles = []
        for entry in feed.entries[:10]:  # Max 10 par source
            try:
                # Extraire les données
                title = entry.get('title', 'No title')
                link = entry.get('link', '')
                description = clean_html(entry.get('description', '') or entry.get('summary', ''))
                
                # Date de publication
                published = entry.get('published_parsed') or entry.get('updated_parsed')
                if published:
                    pub_date = datetime(*published[:6])
                else:
                    pub_date = datetime.now()
                
                # Catégorisation automatique
                category = categorize_threat(title, description)
                severity = assess_severity(title, description)
                
                # Extraire image si disponible
                image_url = None
                if 'media_content' in entry:
                    image_url = entry.media_content[0].get('url')
                elif 'enclosures' in entry and entry.enclosures:
                    image_url = entry.enclosures[0].get('href')
                
                # Traduire en français
                try:
                    title_fr = translator.translate(title)
                    summary_fr = translator.translate(description[:500]) if description else description
                except Exception as e:
                    logger.warning(f"Erreur traduction: {e}")
                    title_fr = title
                    summary_fr = description
                
                article = {
                    'title': title_fr,  # Titre traduit
                    'url': link,
                    'summary': summary_fr,  # Résumé traduit
                    'description': summary_fr,
                    'category': category,
                    'severity': severity,
                    'source_name': source_name,
                    'source_url': link,
                    'published_date': pub_date,
                    'image_url': image_url,
                    'tags': [category, severity, source_name.lower()],
                    'original_title': title,  # Garder l'original
                    'original_description': description,
                }
                
                articles.append(article)
                
            except Exception as e:
                logger.error(f"Erreur traitement article {source_name}: {e}")
                continue
        
        logger.info(f"Collecté {len(articles)} articles depuis {source_name}")
        return articles
        
    except Exception as e:
        logger.error(f"Erreur collecte RSS {source_name}: {e}")
        return []


async def collect_all_rss() -> List[Dict]:
    """Collecte tous les flux RSS en parallèle"""
    logger.info("Début collecte RSS...")
    
    tasks = [
        collect_from_rss(url, name)
        for name, url in RSS_FEEDS.items()
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Fusionner tous les articles
    all_articles = []
    for result in results:
        if isinstance(result, list):
            all_articles.extend(result)
    
    logger.info(f"Total RSS collectés: {len(all_articles)} articles")
    return all_articles


async def save_to_database(articles: List[Dict]):
    """Sauvegarde dans MongoDB"""
    from app.models import Threat, Source, ThreatCategory, SeverityLevel, SourceType
    
    saved_count = 0
    for article_data in articles:
        try:
            # Vérifier si existe déjà
            existing = await Threat.find_one(Threat.source_url == article_data['url'])
            if existing:
                continue
            
            # Créer/récupérer la source
            source = await Source.find_one(Source.name == article_data['source_name'])
            if not source:
                source = Source(
                    name=article_data['source_name'],
                    url=article_data['source_url'],
                    type=SourceType.RSS,
                    is_active=True
                )
                await source.insert()
            
            # Créer la menace
            threat = Threat(
                title=article_data['title'],
                description=article_data['description'],
                summary=article_data['summary'],
                category=ThreatCategory(article_data['category']),
                severity=SeverityLevel(article_data['severity']),
                source_id=source.id,
                source_url=article_data['url'],
                published_date=article_data['published_date'],
                tags=article_data['tags'],
                iocs=[]
            )
            
            await threat.insert()
            saved_count += 1
            
        except Exception as e:
            logger.error(f"Erreur sauvegarde article: {e}")
            continue
    
    logger.info(f"Sauvegardé {saved_count} nouvelles menaces")
    return saved_count


async def run_rss_collection():
    """Point d'entrée principal"""
    articles = await collect_all_rss()
    saved = await save_to_database(articles)
    return {
        "collected": len(articles),
        "saved": saved,
        "sources": list(RSS_FEEDS.keys())
    }
