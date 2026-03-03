from beanie import Document, Indexed
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatCategory(str, Enum):
    """Catégories de menaces"""
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    VULNERABILITY = "vulnerability"
    APT = "apt"  # Advanced Persistent Threat
    MALWARE = "malware"
    PHISHING = "phishing"
    DDOS = "ddos"
    ZERO_DAY = "zero_day"
    SUPPLY_CHAIN = "supply_chain"
    AI_SECURITY = "ai_security"
    OTHER = "other"


class SeverityLevel(str, Enum):
    """Niveaux de gravité"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SourceType(str, Enum):
    """Types de sources"""
    RSS = "rss"
    API = "api"
    MANUAL = "manual"


class TeamColor(str, Enum):
    """Équipes cybersécurité"""
    BLUE = "blue"    # Défense
    RED = "red"      # Attaque (pentesting)
    PURPLE = "purple"  # Hybride
    GREEN = "green"  # Compliance/Governance
    WHITE = "white"  # Éducation


class DifficultyLevel(str, Enum):
    """Niveaux de difficulté"""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class Threat(Document):
    """Modèle pour les menaces cybersécurité"""
    
    # Identification
    external_id: Optional[str] = None  # CVE ID, etc.
    title: str
    description: str
    summary: Optional[str] = None  # Résumé IA
    
    # Classification
    category: ThreatCategory
    severity: SeverityLevel
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    
    # Source
    source_name: str
    source_url: Optional[str] = None
    source_type: SourceType
    
    # Métadonnées
    published_date: Optional[datetime] = None
    detected_date: datetime = Field(default_factory=datetime.now)
    updated_date: datetime = Field(default_factory=datetime.now)
    
    # Analyse IA
    tags: Optional[List[str]] = []
    affected_systems: Optional[List[str]] = []
    affected_sectors: Optional[List[str]] = []
    affected_regions: Optional[List[str]] = []
    
    # Traduction
    translations: Optional[Dict[str, Dict[str, str]]] = {}
    detected_language: Optional[str] = None
    
    # Indicators
    iocs: Optional[Dict[str, Any]] = {}
    mitigation: Optional[str] = None
    references: Optional[List[str]] = []
    
    # Statut
    is_active: bool = True
    is_trending: bool = False
    view_count: int = 0
    
    class Settings:
        name = "threats"
        indexes = [
            "external_id",
            "title",
            "category",
            "severity",
            "source_name",
            "detected_date",
            [("category", 1), ("severity", 1)],
            [("is_trending", 1), ("view_count", -1)],
        ]


class Source(Document):
    """Modèle pour les sources de données"""
    
    name: str
    type: SourceType
    url: str
    
    # Configuration
    is_active: bool = True
    update_interval: int = 30  # minutes
    requires_api_key: bool = False
    
    # Statistiques
    last_update: Optional[datetime] = None
    last_success: Optional[datetime] = None
    total_threats_collected: int = 0
    failure_count: int = 0
    
    # Métadonnées
    description: Optional[str] = None
    region: Optional[str] = None
    language: str = "en"
    reliability_score: float = 1.0
    
    created_date: datetime = Field(default_factory=datetime.now)
    updated_date: datetime = Field(default_factory=datetime.now)
    
    class Settings:
        name = "sources"


class User(Document):
    """Modèle pour les utilisateurs"""
    
    email: str
    username: str
    hashed_password: str
    
    # Profil
    full_name: Optional[str] = None
    organization: Optional[str] = None
    role: str = "user"
    
    # Préférences
    preferences: Optional[Dict[str, Any]] = {}
    notification_settings: Optional[Dict[str, Any]] = {}
    language: str = "fr"
    
    # Statut
    is_active: bool = True
    is_verified: bool = False
    
    # Tokens
    fcm_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    
    # Apprentissage
    learning_progress: Optional[Dict[str, Any]] = {}  # Progression des leçons
    completed_lessons: List[str] = []
    daily_lesson_streak: int = 0
    last_lesson_date: Optional[datetime] = None
    
    # Favoris et recommandations
    favorite_threats: List[str] = []  # IDs des menaces favorites
    security_score: int = 50  # Score de sécurité (0-100)
    
    created_date: datetime = Field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    
    class Settings:
        name = "users"


class Alert(Document):
    """Modèle pour les alertes utilisateur"""
    
    # Relations (stockées comme IDs)
    user_id: str  # ObjectId as string
    threat_id: str  # ObjectId as string
    
    # Statut
    is_read: bool = False
    is_dismissed: bool = False
    
    # Notification
    notification_sent: bool = False
    notification_sent_at: Optional[datetime] = None
    notification_channels: Optional[List[str]] = []
    
    # Métadonnées
    created_date: datetime = Field(default_factory=datetime.now)
    read_date: Optional[datetime] = None
    
    class Settings:
        name = "alerts"
        indexes = [
            "user_id",
            "threat_id",
            [("user_id", 1), ("is_read", 1)],
        ]


class TrendAnalysis(Document):
    """Modèle pour l'analyse des tendances"""
    
    # Période d'analyse
    analysis_date: datetime = Field(default_factory=datetime.now)
    period_start: datetime
    period_end: datetime
    
    # Statistiques globales
    total_threats: int = 0
    critical_threats: int = 0
    high_threats: int = 0
    
    # Tendances par catégorie
    category_distribution: Optional[Dict[str, int]] = {}
    sector_distribution: Optional[Dict[str, int]] = {}
    region_distribution: Optional[Dict[str, int]] = {}
    
    # Top menaces
    trending_threats: Optional[List[str]] = []  # IDs des menaces
    top_tags: Optional[List[str]] = []
    top_targets: Optional[List[str]] = []
    
    # Insights IA
    ai_insights: Optional[str] = None
    predictions: Optional[Dict[str, Any]] = {}
    
    created_date: datetime = Field(default_factory=datetime.now)
    
    class Settings:
        name = "trend_analyses"
        indexes = [
            [("analysis_date", -1)],
        ]


class ChatHistory(Document):
    """Modèle pour l'historique du chatbot"""
    
    # Session
    session_id: str
    user_id: Optional[str] = None  # ObjectId as string
    
    # Messages
    user_message: str
    bot_response: str
    
    # Contexte
    context: Optional[Dict[str, Any]] = {}
    language: str = "fr"
    
    # Feedback
    rating: Optional[int] = None  # 1-5
    
    created_date: datetime = Field(default_factory=datetime.now)
    
    class Settings:
        name = "chat_history"
        indexes = [
            "session_id",
            [("session_id", 1), ("created_date", -1)],
        ]


class GeoLocation(BaseModel):
    """Coordonnées géographiques"""
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    country: Optional[str] = None
    country_code: Optional[str] = None  # ISO 3166-1 alpha-2
    city: Optional[str] = None
    continent: Optional[str] = None


class CyberAttackEvent(Document):
    """Événement de cyberattaque géolocalisé (temps réel)"""
    
    # Identification
    event_id: str  # ID unique de l'événement
    
    # Localisation
    source_location: GeoLocation  # Origine de l'attaque
    target_location: GeoLocation  # Cible de l'attaque
    
    # Type et gravité
    attack_type: ThreatCategory
    severity: SeverityLevel
    
    # Détails
    title: str
    description: Optional[str] = None
    protocol: Optional[str] = None  # TCP, UDP, HTTP, etc.
    port: Optional[int] = None
    
    # Métadonnées
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    source_name: str  # Source de données (FireEye, Kaspersky, etc.)
    
    # Timestamps
    attack_timestamp: datetime  # Quand l'attaque a eu lieu
    detected_timestamp: datetime = Field(default_factory=datetime.now)
    
    # Statistiques
    packet_count: Optional[int] = None
    data_volume_bytes: Optional[int] = None
    duration_seconds: Optional[int] = None
    
    # État
    is_active: bool = True
    is_blocked: bool = False
    
    # TTL pour nettoyage automatique (attaques anciennes)
    expires_at: Optional[datetime] = None
    
    class Settings:
        name = "cyber_attack_events"
        indexes = [
            "event_id",
            "attack_type",
            "severity",
            "source_name",
            "attack_timestamp",
            "is_active",
            [("source_location.country_code", 1)],
            [("target_location.country_code", 1)],
            [("attack_timestamp", -1)],
            [("is_active", 1), ("attack_timestamp", -1)],
        ]


class GeoStatistics(Document):
    """Statistiques géographiques agrégées"""
    
    # Période
    period_start: datetime
    period_end: datetime
    granularity: str  # "hourly", "daily", "weekly"
    
    # Localisation
    country_code: str
    country_name: str
    continent: str
    
    # Statistiques d'attaques
    total_attacks: int = 0
    attacks_as_source: int = 0  # Attaques originaires de ce pays
    attacks_as_target: int = 0  # Attaques ciblant ce pays
    
    # Par type
    attacks_by_type: Dict[str, int] = {}
    
    # Par gravité
    critical_attacks: int = 0
    high_attacks: int = 0
    medium_attacks: int = 0
    low_attacks: int = 0
    
    # Top cibles/sources
    top_source_countries: List[Dict[str, Any]] = []
    top_target_countries: List[Dict[str, Any]] = []
    
    # Tendances
    attack_trend: str = "stable"  # "increasing", "decreasing", "stable"
    trend_percentage: float = 0.0
    
    created_date: datetime = Field(default_factory=datetime.now)
    
    class Settings:
        name = "geo_statistics"
        indexes = [
            "country_code",
            "granularity",
            [("period_start", 1), ("period_end", 1)],
            [("country_code", 1), ("granularity", 1)],
        ]


class LiveMapSession(Document):
    """Session de visualisation de la carte en temps réel"""
    
    session_id: str
    user_id: Optional[str] = None
    
    # Filtres actifs
    filters: Dict[str, Any] = {}
    
    # Statistiques de session
    events_viewed: int = 0
    duration_seconds: int = 0
    
    # Timestamps
    started_at: datetime = Field(default_factory=datetime.now)
    last_activity: datetime = Field(default_factory=datetime.now)
    ended_at: Optional[datetime] = None
    
    class Settings:
        name = "live_map_sessions"
        indexes = [
            "session_id",
            "user_id",
            "started_at",
        ]


class GlossaryTerm(Document):
    """Glossaire des termes cybersécurité"""
    
    term: str
    slug: str
    
    # Définitions
    short_definition: str  # Une phrase
    long_definition: str  # Paragraphe détaillé
    
    # Classification
    category: ThreatCategory
    team_colors: List[TeamColor]  # Blue/Red/Purple team
    difficulty: DifficultyLevel
    
    # Exemples et références
    examples: Optional[List[str]] = []
    real_world_cases: Optional[List[Dict[str, str]]] = []
    related_terms: Optional[List[str]] = []
    
    # Traductions
    translations: Optional[Dict[str, Dict[str, str]]] = {}
    
    # Métadonnées
    tags: Optional[List[str]] = []
    view_count: int = 0
    is_popular: bool = False
    
    created_date: datetime = Field(default_factory=datetime.now)
    updated_date: datetime = Field(default_factory=datetime.now)
    
    class Settings:
        name = "glossary_terms"
        indexes = [
            "term",
            "slug",
            "category",
            "difficulty",
        ]


class EducationalResource(Document):
    """Ressources éducatives (standards, frameworks, certifications)"""
    
    title: str
    slug: str
    type: str  # "standard", "framework", "certification", "guide"
    
    # Contenu
    description: str
    summary: str
    content: Optional[str] = None  # Markdown
    
    # Organisation/Source
    organization: str  # ISO, NIST, OWASP, etc.
    official_url: str
    documentation_url: Optional[str] = None
    
    # Classification
    team_colors: List[TeamColor]
    topics: List[str]  # ["governance", "compliance", "technical", etc.]
    difficulty: DifficultyLevel
    
    # Métadonnées
    language: str = "en"
    icon: Optional[str] = None
    is_featured: bool = False
    view_count: int = 0
    
    created_date: datetime = Field(default_factory=datetime.now)
    updated_date: datetime = Field(default_factory=datetime.now)
    
    class Settings:
        name = "educational_resources"
        indexes = [
            "slug",
            "type",
            "organization",
        ]


class DailyLesson(Document):
    """Leçons quotidiennes (apprentissage continu)"""
    
    title: str
    slug: str
    lesson_number: int  # Numéro de la leçon dans la séquence
    
    # Contenu
    introduction: str
    main_content: str  # Markdown
    key_takeaways: List[str]
    practical_tips: Optional[List[str]] = []
    
    # Classification
    category: ThreatCategory
    team_color: TeamColor
    difficulty: DifficultyLevel
    duration_minutes: int  # Temps de lecture estimé
    
    # Quiz/Exercices (optionnel)
    quiz_questions: Optional[List[Dict[str, Any]]] = []
    
    # Ressources
    related_terms: List[str]  # Références au glossaire
    related_resources: List[str]  # Références aux ressources
    external_links: Optional[List[Dict[str, str]]] = []
    
    # Métadonnées
    tags: List[str]
    language: str = "fr"
    is_published: bool = True
    completion_count: int = 0
    average_rating: float = 0.0
    
    created_date: datetime = Field(default_factory=datetime.now)
    updated_date: datetime = Field(default_factory=datetime.now)
    
    class Settings:
        name = "daily_lessons"
        indexes = [
            "slug",
            "lesson_number",
            "category",
            "is_published",
        ]


class UserLessonProgress(Document):
    """Progression utilisateur pour les leçons"""
    
    user_id: str
    lesson_id: str
    
    # Statut
    is_completed: bool = False
    completion_date: Optional[datetime] = None
    
    # Interaction
    time_spent_seconds: int = 0
    quiz_score: Optional[float] = None
    rating: Optional[int] = None  # 1-5
    
    # Métadonnées
    started_date: datetime = Field(default_factory=datetime.now)
    last_accessed: datetime = Field(default_factory=datetime.now)
    
    class Settings:
        name = "user_lesson_progress"
        indexes = [
            "user_id",
            "lesson_id",
            [("user_id", 1), ("lesson_id", 1)],
        ]
