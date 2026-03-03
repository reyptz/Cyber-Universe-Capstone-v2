"""
Ghost Research Core - Unified RAG Controller
"""
import logging
import os
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel

# Imports with new paths
from app.domain.services.rag_chain import SecureRAGChain

logger = logging.getLogger(__name__)

router = APIRouter()

# Pydantic models
class QueryRequest(BaseModel):
    query: str
    user_id: Optional[str] = None

class QueryResponse(BaseModel):
    success: bool
    answer: Optional[str] = None
    error: Optional[str] = None
    security_analysis: Optional[Dict[str, Any]] = None
    response_analysis: Optional[Dict[str, Any]] = None

# Dependency to get RAG chain from the main app state
def get_rag_chain():
    from run import rag_chain
    if rag_chain is None:
        raise HTTPException(status_code=503, detail="RAG chain not initialized")
    return rag_chain

@router.get("/health")
async def health_check(rag: SecureRAGChain = Depends(get_rag_chain)):
    try:
        status = rag.get_security_status()
        return {"status": "healthy", "details": status}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

@router.post("/query", response_model=QueryResponse)
async def secure_query(
    request: QueryRequest,
    background_tasks: BackgroundTasks,
    rag: SecureRAGChain = Depends(get_rag_chain)
):
    try:
        result = rag.secure_query(request.query, request.user_id)
        # Background task for auditing could be added here
        return QueryResponse(**result)
    except Exception as e:
        logger.error(f"RAG query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/security/status")
async def get_security_status(rag: SecureRAGChain = Depends(get_rag_chain)):
    return rag.get_security_status()

@router.get("/security/report")
async def generate_security_report(rag: SecureRAGChain = Depends(get_rag_chain)):
    return rag.generate_security_report()
