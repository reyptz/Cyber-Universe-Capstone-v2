"""
Ghost Research Core - Unified Entry Point
Consolidated launcher for CyberRadar API and Secure RAG Assistant
"""
import uvicorn
import logging
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from typing import Optional

# Configurations
from config.research_config import settings as research_settings
from app.domain.repositories.database import init_all_databases, close_all_databases

# RAG Logic Imports
from app.domain.services.rag_chain import SecureRAGChain

# Global instances
rag_chain: Optional[SecureRAGChain] = None

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ghost-research")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for the unified API"""
    global rag_chain
    
    # 1. Initialize CyberRadar
    logger.info("Starting CyberRadar Intelligence...")
    try:
        await init_all_databases()
        logger.info("CyberRadar databases initialized")
    except Exception as e:
        logger.error(f"CyberRadar initialization failed: {e}")

    # 2. Initialize RAG Assistant
    logger.info("Initializing Secure RAG Assistant...")
    try:
        docs_dir = os.path.join(os.path.dirname(__file__), "docs")
        if not os.path.exists(docs_dir):
            os.makedirs(docs_dir, exist_ok=True)
            
        rag_chain = SecureRAGChain(
            docs_directory=docs_dir,
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )
        
        load_result = rag_chain.load_and_process_documents()
        if load_result.get('success', False):
            logger.info(f"RAG Documents loaded: {load_result['processed_documents']} documents")
        else:
            logger.warning(f"RAG loading warning: {load_result.get('error', 'Unknown error')}")
        
        logger.info("Secure RAG Assistant ready")
    except Exception as e:
        logger.error(f"RAG initialization failed: {e}")

    yield
    
    # Shutdown
    logger.info("Shutting down Ghost Research Core...")
    await close_all_databases()

# Unified FastAPI App
app = FastAPI(
    title="Ghost Research Core",
    version="1.0.0",
    description="Unified Cyber Threat Intelligence & Secure RAG Assistant",
    lifespan=lifespan
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Include Research (CyberRadar) Routes ---
from app.presentation.controllers import (
    auth, threats, collector, dashboard, 
    educational, info, search, trends
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["Research-Auth"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["Research-Threats"])
app.include_router(collector.router, prefix="/api/v1/collector", tags=["Research-Collector"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Research-Dashboard"])
app.include_router(educational.router, prefix="/api/v1/educational", tags=["Research-Educational"])
app.include_router(info.router, prefix="/api/v1/info", tags=["Research-Info"])
app.include_router(search.router, prefix="/api/v1/search", tags=["Research-Search"])
app.include_router(trends.router, prefix="/api/v1/trends", tags=["Research-Trends"])

# --- Include RAG Assistant Routes ---
from app.presentation.controllers import rag_controller
app.include_router(rag_controller.router, prefix="/api/v1/rag", tags=["RAG-Assistant"])

@app.get("/", tags=["Health"])
async def health():
    return {
        "status": "online",
        "service": "Ghost Research Core",
        "version": "1.0.0"
    }

if __name__ == "__main__":
    uvicorn.run("run:app", host="0.0.0.0", port=8000, reload=True)
