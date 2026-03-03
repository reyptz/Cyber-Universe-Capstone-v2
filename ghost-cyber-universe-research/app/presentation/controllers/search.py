from fastapi import APIRouter, Query, HTTPException
from typing import Optional

from app.search.elasticsearch_client import search_threats, es_client
from config import settings

router = APIRouter(prefix="/search", tags=["Search"])


@router.get("/")
async def search(
    q: str = Query(..., min_length=2, description="Requête de recherche"),
    category: Optional[str] = None,
    severity: Optional[str] = None,
    size: int = Query(default=20, ge=1, le=100),
    page: int = Query(default=1, ge=1)
):
    """
    Recherche fulltext dans les menaces avec Elasticsearch
    
    Plus rapide et plus pertinent que la recherche MongoDB native.
    """
    if not settings.ELASTICSEARCH_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Elasticsearch is not enabled. Use /threats/?search=query instead"
        )
    
    if not es_client:
        raise HTTPException(
            status_code=503,
            detail="Elasticsearch not connected"
        )
    
    # Construire les filtres
    filters = {"is_active": True}
    if category:
        filters["category"] = category
    if severity:
        filters["severity"] = severity
    
    # Calculer offset
    from_ = (page - 1) * size
    
    # Rechercher
    results = await search_threats(
        query=q,
        filters=filters,
        size=size,
        from_=from_
    )
    
    # Formater la réponse
    hits = results.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    
    threats = []
    for hit in hits.get("hits", []):
        source = hit["_source"]
        threat = {
            "id": hit["_id"],
            "score": hit["_score"],
            **source
        }
        
        # Ajouter les highlights si disponibles
        if "highlight" in hit:
            threat["highlights"] = hit["highlight"]
        
        threats.append(threat)
    
    return {
        "query": q,
        "total": total,
        "page": page,
        "page_size": size,
        "has_more": (page * size) < total,
        "results": threats
    }


@router.get("/suggest")
async def get_search_suggestions(
    q: str = Query(..., min_length=2),
    size: int = Query(default=5, ge=1, le=10)
):
    """
    Suggestions de recherche (autocomplete)
    """
    if not es_client:
        return {"suggestions": []}
    
    try:
        # Recherche de suggestions basée sur le titre
        search_body = {
            "suggest": {
                "title-suggest": {
                    "prefix": q,
                    "completion": {
                        "field": "title.keyword",
                        "size": size,
                        "skip_duplicates": True
                    }
                }
            }
        }
        
        results = await es_client.search(
            index=settings.ELASTICSEARCH_INDEX,
            body=search_body
        )
        
        suggestions = []
        if "suggest" in results:
            for option in results["suggest"]["title-suggest"][0]["options"]:
                suggestions.append({
                    "text": option["text"],
                    "score": option["_score"]
                })
        
        return {"suggestions": suggestions}
        
    except Exception as e:
        return {"suggestions": [], "error": str(e)}

