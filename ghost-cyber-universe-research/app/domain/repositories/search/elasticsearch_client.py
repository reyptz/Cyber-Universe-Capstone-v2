from typing import List, Dict, Any, Optional
import logging

from config import settings

logger = logging.getLogger(__name__)

# Elasticsearch optionnel
try:
    from elasticsearch import AsyncElasticsearch
    HAS_ELASTICSEARCH = True
except ImportError:
    AsyncElasticsearch = None
    HAS_ELASTICSEARCH = False
    logger.warning("Elasticsearch not available. Search functionality disabled.")

# Client Elasticsearch global
es_client: Optional[Any] = None


async def connect_elasticsearch():
    """Connexion à Elasticsearch"""
    global es_client
    
    if not settings.ELASTICSEARCH_ENABLED:
        logger.info("Elasticsearch disabled in settings")
        return
    
    if not HAS_ELASTICSEARCH:
        logger.warning("Elasticsearch not installed. Install with: pip install elasticsearch")
        return
    
    try:
        es_client = AsyncElasticsearch(
            [settings.ELASTICSEARCH_URL],
            verify_certs=False,
            max_retries=3,
            retry_on_timeout=True
        )
        
        # Tester la connexion
        info = await es_client.info()
        logger.info(f"✅ Connected to Elasticsearch {info['version']['number']}")
        
        # Créer l'index si nécessaire
        await create_threats_index()
        
    except Exception as e:
        logger.error(f"❌ Elasticsearch connection failed: {str(e)}")
        es_client = None


async def close_elasticsearch():
    """Ferme la connexion Elasticsearch"""
    global es_client
    
    if es_client:
        await es_client.close()
        logger.info("Elasticsearch connection closed")


async def create_threats_index():
    """Crée l'index pour les menaces avec mapping optimisé"""
    if not es_client:
        return
    
    index_name = settings.ELASTICSEARCH_INDEX
    
    # Vérifier si l'index existe
    exists = await es_client.indices.exists(index=index_name)
    
    if exists:
        logger.info(f"Index {index_name} already exists")
        return
    
    # Mapping pour recherche optimisée
    mapping = {
        "mappings": {
            "properties": {
                "external_id": {"type": "keyword"},
                "title": {
                    "type": "text",
                    "analyzer": "standard",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                "description": {
                    "type": "text",
                    "analyzer": "standard"
                },
                "summary": {"type": "text"},
                "category": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "cvss_score": {"type": "float"},
                "source_name": {"type": "keyword"},
                "tags": {"type": "keyword"},
                "affected_systems": {"type": "keyword"},
                "affected_sectors": {"type": "keyword"},
                "affected_regions": {"type": "keyword"},
                "detected_date": {"type": "date"},
                "published_date": {"type": "date"},
                "is_active": {"type": "boolean"},
                "is_trending": {"type": "boolean"},
                "view_count": {"type": "integer"}
            }
        },
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 1,
            "analysis": {
                "analyzer": {
                    "cyber_analyzer": {
                        "type": "standard",
                        "stopwords": "_english_"
                    }
                }
            }
        }
    }
    
    await es_client.indices.create(index=index_name, body=mapping)
    logger.info(f"✅ Created Elasticsearch index: {index_name}")


async def index_threat(threat_id: str, threat_data: Dict) -> bool:
    """
    Indexe une menace dans Elasticsearch
    
    Args:
        threat_id: ID MongoDB de la menace
        threat_data: Données de la menace
        
    Returns:
        bool: Succès de l'indexation
    """
    if not es_client:
        return False
    
    try:
        await es_client.index(
            index=settings.ELASTICSEARCH_INDEX,
            id=threat_id,
            document=threat_data
        )
        return True
    except Exception as e:
        logger.error(f"Error indexing threat {threat_id}: {e}")
        return False


async def search_threats(
    query: str,
    filters: Optional[Dict] = None,
    size: int = 20,
    from_: int = 0
) -> Dict:
    """
    Recherche fulltext dans les menaces
    
    Args:
        query: Texte de recherche
        filters: Filtres additionnels
        size: Nombre de résultats
        from_: Offset pour pagination
        
    Returns:
        Dict: Résultats de recherche
    """
    if not es_client:
        return {"hits": {"total": {"value": 0}, "hits": []}}
    
    try:
        # Construire la requête
        must_clauses = [
            {
                "multi_match": {
                    "query": query,
                    "fields": [
                        "title^3",  # Boost titre
                        "description^2",
                        "summary",
                        "external_id^4"
                    ],
                    "type": "best_fields",
                    "fuzziness": "AUTO"
                }
            }
        ]
        
        # Ajouter les filtres
        filter_clauses = []
        if filters:
            if "category" in filters:
                filter_clauses.append({"term": {"category": filters["category"]}})
            if "severity" in filters:
                filter_clauses.append({"term": {"severity": filters["severity"]}})
            if "is_active" in filters:
                filter_clauses.append({"term": {"is_active": filters["is_active"]}})
        
        # Requête complète
        search_body = {
            "query": {
                "bool": {
                    "must": must_clauses,
                    "filter": filter_clauses
                }
            },
            "highlight": {
                "fields": {
                    "title": {},
                    "description": {},
                    "summary": {}
                }
            },
            "sort": [
                {"_score": {"order": "desc"}},
                {"detected_date": {"order": "desc"}}
            ]
        }
        
        results = await es_client.search(
            index=settings.ELASTICSEARCH_INDEX,
            body=search_body,
            size=size,
            from_=from_
        )
        
        return results
        
    except Exception as e:
        logger.error(f"Elasticsearch search error: {e}")
        return {"hits": {"total": {"value": 0}, "hits": []}}


async def delete_threat_from_index(threat_id: str) -> bool:
    """Supprime une menace de l'index"""
    if not es_client:
        return False
    
    try:
        await es_client.delete(
            index=settings.ELASTICSEARCH_INDEX,
            id=threat_id
        )
        return True
    except Exception as e:
        logger.error(f"Error deleting from index: {e}")
        return False


async def bulk_index_threats(threats: List[Dict]) -> int:
    """
    Indexe plusieurs menaces en batch
    
    Args:
        threats: Liste de {id, data}
        
    Returns:
        int: Nombre de menaces indexées
    """
    if not es_client or not threats:
        return 0
    
    try:
        from elasticsearch.helpers import async_bulk
        
        actions = [
            {
                "_index": settings.ELASTICSEARCH_INDEX,
                "_id": threat["id"],
                "_source": threat["data"]
            }
            for threat in threats
        ]
        
        success, failed = await async_bulk(es_client, actions)
        logger.info(f"Bulk indexed {success} threats, {len(failed)} failed")
        
        return success
        
    except Exception as e:
        logger.error(f"Bulk indexing error: {e}")
        return 0

