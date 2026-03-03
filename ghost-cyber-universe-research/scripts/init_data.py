"""
Script d'initialisation des données de test pour CyberRadar
"""

import asyncio
import sys
import os

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from config import settings
from app.models import (
    Threat, Source, User, Alert, 
    TrendAnalysis, ChatHistory,
    GlossaryTerm, EducationalResource,
    DailyLesson, UserLessonProgress,
    CyberAttackEvent, GeoStatistics, LiveMapSession,
    ThreatCategory, SeverityLevel, SourceType, TeamColor, DifficultyLevel
)
from datetime import datetime, timedelta
import random


async def init_db():
    """Initialiser la connexion MongoDB"""
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    await init_beanie(
        database=client[settings.MONGODB_DB_NAME],
        document_models=[
            Threat, Source, User, Alert,
            TrendAnalysis, ChatHistory,
            GlossaryTerm, EducationalResource,
            DailyLesson, UserLessonProgress,
            CyberAttackEvent, GeoStatistics, LiveMapSession
        ]
    )
    print("✅ Connecté à MongoDB")


async def create_glossary_terms():
    """Créer des termes de glossaire"""
    terms = [
        {
            "term": "Phishing",
            "slug": "phishing",
            "short_definition": "Technique d'hameçonnage visant à obtenir des informations sensibles",
            "long_definition": "Le phishing est une technique de cyberattaque où l'attaquant se fait passer pour une entité de confiance afin de voler des informations sensibles comme des mots de passe ou des données bancaires.",
            "category": ThreatCategory.PHISHING,
            "team_colors": [TeamColor.RED, TeamColor.BLUE],
            "difficulty": DifficultyLevel.BEGINNER,
            "examples": ["Emails frauduleux", "Sites web contrefaits"],
            "related_terms": ["Social Engineering", "Spear Phishing"],
            "tags": ["social-engineering", "email", "web"]
        },
        {
            "term": "Ransomware",
            "slug": "ransomware",
            "short_definition": "Logiciel malveillant qui chiffre les données et exige une rançon",
            "long_definition": "Un ransomware est un type de malware qui chiffre les fichiers de la victime et demande le paiement d'une rançon pour les déchiffrer.",
            "category": ThreatCategory.RANSOMWARE,
            "team_colors": [TeamColor.RED, TeamColor.PURPLE],
            "difficulty": DifficultyLevel.INTERMEDIATE,
            "examples": ["WannaCry", "LockBit", "REvil"],
            "tags": ["malware", "encryption", "extortion"]
        },
        {
            "term": "Zero-Day",
            "slug": "zero-day",
            "short_definition": "Vulnérabilité inconnue exploitée avant qu'un correctif existe",
            "long_definition": "Une vulnérabilité zero-day est une faille de sécurité découverte par des attaquants avant que le développeur en soit informé, laissant zéro jour pour corriger.",
            "category": ThreatCategory.VULNERABILITY,
            "team_colors": [TeamColor.RED],
            "difficulty": DifficultyLevel.ADVANCED,
            "examples": ["Exploits 0-day", "APT attacks"],
            "tags": ["vulnerability", "exploit", "apt"]
        }
    ]
    
    for term_data in terms:
        existing = await GlossaryTerm.find_one(GlossaryTerm.term == term_data["term"])
        if not existing:
            term = GlossaryTerm(**term_data)
            await term.insert()
            print(f"✅ Terme créé: {term.term}")


async def create_lessons():
    """Créer des leçons"""
    lessons = [
        {
            "title": "Fondamentaux de la Cybersécurité",
            "slug": "fondamentaux-cybersecurite",
            "lesson_number": 1,
            "introduction": "Introduction aux concepts de base de la cybersécurité",
            "main_content": "La cybersécurité repose sur trois piliers : Confidentialité, Intégrité et Disponibilité (CIA Triad)...",
            "key_takeaways": ["CIA Triad", "Threat modeling", "Defense in depth"],
            "practical_tips": ["Utilisez des mots de passe forts", "Activez 2FA partout"],
            "category": ThreatCategory.OTHER,
            "team_color": TeamColor.BLUE,
            "difficulty": DifficultyLevel.BEGINNER,
            "duration_minutes": 15,
            "tags": ["basics", "fundamentals"],
            "related_terms": [],
            "related_resources": [],
            "is_published": True
        },
        {
            "title": "Cryptographie Moderne",
            "slug": "cryptographie-moderne",
            "lesson_number": 2,
            "introduction": "Comprendre le chiffrement et le hachage",
            "main_content": "AES, RSA, SHA-256... Les algorithmes cryptographiques protègent nos données...",
            "key_takeaways": ["Chiffrement symétrique vs asymétrique", "Fonctions de hachage", "Certificats SSL/TLS"],
            "category": ThreatCategory.OTHER,
            "team_color": TeamColor.PURPLE,
            "difficulty": DifficultyLevel.INTERMEDIATE,
            "duration_minutes": 20,
            "tags": ["crypto", "encryption"],
            "related_terms": [],
            "related_resources": [],
            "is_published": True
        }
    ]
    
    for lesson_data in lessons:
        existing = await DailyLesson.find_one(DailyLesson.slug == lesson_data["slug"])
        if not existing:
            lesson = DailyLesson(**lesson_data)
            await lesson.insert()
            print(f"✅ Leçon créée: {lesson.title}")


async def create_resources():
    """Créer des ressources éducatives"""
    resources = [
        {
            "title": "OWASP Top 10",
            "slug": "owasp-top-10",
            "type": "standard",
            "description": "Les 10 risques de sécurité web les plus critiques",
            "summary": "Guide de référence sur les vulnérabilités web",
            "organization": "OWASP",
            "official_url": "https://owasp.org/www-project-top-ten/",
            "team_colors": [TeamColor.BLUE, TeamColor.PURPLE],
            "topics": ["Web Security", "Vulnerabilities"],
            "difficulty": DifficultyLevel.INTERMEDIATE,
            "is_featured": True
        },
        {
            "title": "NIST Cybersecurity Framework",
            "slug": "nist-csf",
            "type": "standard",
            "description": "Framework de cybersécurité du NIST",
            "summary": "Méthodologie pour gérer les risques cyber",
            "organization": "NIST",
            "official_url": "https://www.nist.gov/cyberframework",
            "team_colors": [TeamColor.BLUE],
            "topics": ["Framework", "Risk Management"],
            "difficulty": DifficultyLevel.ADVANCED,
            "is_featured": True
        }
    ]
    
    for resource_data in resources:
        existing = await EducationalResource.find_one(EducationalResource.slug == resource_data["slug"])
        if not existing:
            resource = EducationalResource(**resource_data)
            await resource.insert()
            print(f"✅ Ressource créée: {resource.title}")


async def main():
    """Script principal"""
    print("🚀 Initialisation des données CyberRadar...")
    
    await init_db()
    
    print("\n📚 Création du glossaire...")
    await create_glossary_terms()
    
    print("\n🎓 Création des leçons...")
    await create_lessons()
    
    print("\n📖 Création des ressources...")
    await create_resources()
    
    print("\n✅ Initialisation terminée !")
    print("\nPour ajouter des menaces, lancez:")
    print("  curl -X POST http://localhost:8000/api/v1/collector/collect")
    print("\nPour ajouter des événements worldmap:")
    print("  curl -X POST http://localhost:8000/api/v1/worldmap/simulate?count=100")


if __name__ == "__main__":
    asyncio.run(main())

