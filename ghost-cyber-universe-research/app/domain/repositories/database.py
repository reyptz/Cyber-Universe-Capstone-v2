from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
import logging

from config import settings

logger = logging.getLogger(__name__)

# Client MongoDB global
mongodb_client: AsyncIOMotorClient = None


async def init_all_databases():
    """Initialise toutes les bases de données"""
    # MongoDB
    await connect_to_mongo()
    
    # Elasticsearch (optionnel)
    if settings.ELASTICSEARCH_ENABLED:
        from app.search.elasticsearch_client import connect_elasticsearch
        await connect_elasticsearch()
    
    # Initialiser Aetherium
    from app.crypto.aetherium import aetherium
    
    if settings.AETHERIUM_MASTER_KEY:
        # Clé directe
        master_key = bytes.fromhex(settings.AETHERIUM_MASTER_KEY)
        aetherium.master_key = master_key
        logger.info("Aetherium encryption initialized (master key)")
    elif settings.AETHERIUM_MASTER_PASSWORD:
        # Mot de passe (dérivé avec Argon2id)
        aetherium.set_master_password(settings.AETHERIUM_MASTER_PASSWORD)
        logger.info("Aetherium encryption initialized (password)")
    
    # Afficher les infos crypto
    crypto_info = aetherium.get_info()
    logger.info(f"Aetherium: {crypto_info['version']} - PQC: {crypto_info['pqc_enabled']}")
    logger.info(f"KEM: {crypto_info['kem_algorithm']} | Sig: {crypto_info['sig_algorithm']}")
    logger.info(f"KDF: {crypto_info['kdf']} | Hash: {crypto_info['hash']}")


async def close_all_databases():
    """Ferme toutes les connexions"""
    await close_mongo_connection()
    
    if settings.ELASTICSEARCH_ENABLED:
        from app.search.elasticsearch_client import close_elasticsearch
        await close_elasticsearch()


async def connect_to_mongo():
    """Connexion à MongoDB"""
    global mongodb_client
    
    try:
        mongodb_client = AsyncIOMotorClient(settings.MONGODB_URL)
        
        # Tester la connexion
        await mongodb_client.admin.command('ping')
        
        logger.info(f"Connected to MongoDB at {settings.MONGODB_URL}")
        
        # Initialiser Beanie avec les modèles
        from app.models import (
            Threat, Source, User, Alert, 
            TrendAnalysis, ChatHistory,
            GlossaryTerm, EducationalResource,
            DailyLesson, UserLessonProgress,
            CyberAttackEvent, GeoStatistics, LiveMapSession
        )
        
        await init_beanie(
            database=mongodb_client[settings.MONGODB_DB_NAME],
            document_models=[
                Threat, Source, User, Alert,
                TrendAnalysis, ChatHistory,
                GlossaryTerm, EducationalResource,
                DailyLesson, UserLessonProgress,
                CyberAttackEvent, GeoStatistics, LiveMapSession
            ]
        )
        
        logger.info("Beanie initialized with document models")
        
    except Exception as e:
        logger.error(f"MongoDB connection failed: {str(e)}")
        raise


async def close_mongo_connection():
    """Fermeture de la connexion MongoDB"""
    global mongodb_client
    
    if mongodb_client:
        mongodb_client.close()
        logger.info("MongoDB connection closed")


def get_database():
    """Retourne l'instance de la base de données"""
    return mongodb_client[settings.MONGODB_DB_NAME]
