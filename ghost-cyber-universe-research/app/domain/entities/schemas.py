from pydantic import BaseModel, EmailStr, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from app.models import (
    ThreatCategory, SeverityLevel, SourceType, 
    TeamColor, DifficultyLevel
)


# ============= Threat Schemas =============

class ThreatBase(BaseModel):
    title: str = Field(..., min_length=3, max_length=500)
    description: str = Field(..., min_length=10)
    category: ThreatCategory
    severity: SeverityLevel
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    source_name: str
    source_url: Optional[str] = None
    tags: Optional[List[str]] = None
    affected_systems: Optional[List[str]] = None
    affected_sectors: Optional[List[str]] = None
    affected_regions: Optional[List[str]] = None


class ThreatCreate(ThreatBase):
    external_id: Optional[str] = None
    published_date: Optional[datetime] = None


class ThreatUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    summary: Optional[str] = None
    category: Optional[ThreatCategory] = None
    severity: Optional[SeverityLevel] = None
    cvss_score: Optional[float] = None
    mitigation: Optional[str] = None
    is_active: Optional[bool] = None
    is_trending: Optional[bool] = None


class ThreatResponse(ThreatBase):
    id: str
    external_id: Optional[str] = None
    summary: Optional[str] = None
    cvss_vector: Optional[str] = None
    source_type: SourceType
    published_date: Optional[datetime] = None
    detected_date: datetime
    updated_date: datetime
    iocs: Optional[Dict[str, Any]] = None
    mitigation: Optional[str] = None
    references: Optional[List[str]] = None
    is_active: bool
    is_trending: bool
    view_count: int
    detected_language: Optional[str] = None
    
    class Config:
        from_attributes = True


class ThreatTranslated(ThreatResponse):
    """Threat avec traduction automatique"""
    translated_title: Optional[str] = None
    translated_description: Optional[str] = None
    translated_summary: Optional[str] = None
    translation_language: Optional[str] = None


class ThreatListResponse(BaseModel):
    threats: List[ThreatResponse]
    total: int
    page: int
    page_size: int
    has_more: bool


# ============= Educational Schemas =============

class GlossaryTermCreate(BaseModel):
    term: str
    short_definition: str
    long_definition: str
    category: ThreatCategory
    team_colors: List[TeamColor]
    difficulty: DifficultyLevel
    examples: Optional[List[str]] = []
    related_terms: Optional[List[str]] = []
    tags: Optional[List[str]] = []


class GlossaryTermResponse(BaseModel):
    id: str
    term: str
    slug: str
    short_definition: str
    long_definition: str
    category: ThreatCategory
    team_colors: List[TeamColor]
    difficulty: DifficultyLevel
    examples: Optional[List[str]] = []
    real_world_cases: Optional[List[Dict[str, str]]] = []
    related_terms: Optional[List[str]] = []
    tags: Optional[List[str]] = []
    view_count: int
    is_popular: bool
    
    class Config:
        from_attributes = True


class EducationalResourceCreate(BaseModel):
    title: str
    type: str
    description: str
    summary: str
    organization: str
    official_url: str
    documentation_url: Optional[str] = None
    team_colors: List[TeamColor]
    topics: List[str]
    difficulty: DifficultyLevel


class EducationalResourceResponse(BaseModel):
    id: str
    title: str
    slug: str
    type: str
    description: str
    summary: str
    organization: str
    official_url: str
    documentation_url: Optional[str] = None
    team_colors: List[TeamColor]
    topics: List[str]
    difficulty: DifficultyLevel
    language: str
    icon: Optional[str] = None
    is_featured: bool
    view_count: int
    
    class Config:
        from_attributes = True


class DailyLessonCreate(BaseModel):
    title: str
    lesson_number: int
    introduction: str
    main_content: str
    key_takeaways: List[str]
    practical_tips: Optional[List[str]] = []
    category: ThreatCategory
    team_color: TeamColor
    difficulty: DifficultyLevel
    duration_minutes: int
    tags: List[str]


class DailyLessonResponse(BaseModel):
    id: str
    title: str
    slug: str
    lesson_number: int
    introduction: str
    main_content: str
    key_takeaways: List[str]
    practical_tips: Optional[List[str]] = []
    category: ThreatCategory
    team_color: TeamColor
    difficulty: DifficultyLevel
    duration_minutes: int
    quiz_questions: Optional[List[Dict[str, Any]]] = []
    related_terms: List[str]
    related_resources: List[str]
    tags: List[str]
    language: str
    is_published: bool
    completion_count: int
    average_rating: float
    
    class Config:
        from_attributes = True


class UserLessonProgressResponse(BaseModel):
    lesson_id: str
    is_completed: bool
    completion_date: Optional[datetime] = None
    time_spent_seconds: int
    quiz_score: Optional[float] = None
    rating: Optional[int] = None
    
    class Config:
        from_attributes = True


# ============= Source Schemas =============

class SourceBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    type: SourceType
    url: str
    description: Optional[str] = None
    region: Optional[str] = None
    language: str = "en"


class SourceCreate(SourceBase):
    is_active: bool = True
    update_interval: int = 30
    requires_api_key: bool = False


class SourceUpdate(BaseModel):
    url: Optional[str] = None
    is_active: Optional[bool] = None
    update_interval: Optional[int] = None
    description: Optional[str] = None


class SourceResponse(SourceBase):
    id: str
    is_active: bool
    update_interval: int
    requires_api_key: bool
    last_update: Optional[datetime] = None
    last_success: Optional[datetime] = None
    total_threats_collected: int
    failure_count: int
    reliability_score: float
    created_date: datetime
    
    class Config:
        from_attributes = True


# ============= User Schemas =============

class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    full_name: Optional[str] = None
    organization: Optional[str] = None


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=500)


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    organization: Optional[str] = None
    preferences: Optional[Dict[str, Any]] = None
    notification_settings: Optional[Dict[str, Any]] = None
    language: Optional[str] = None
    fcm_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None


class UserResponse(UserBase):
    id: str
    role: str
    preferences: Optional[Dict[str, Any]] = None
    notification_settings: Optional[Dict[str, Any]] = None
    language: str
    is_active: bool
    is_verified: bool
    daily_lesson_streak: int
    completed_lessons: List[str]
    created_date: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


# ============= Alert Schemas =============

class AlertCreate(BaseModel):
    user_id: str
    threat_id: str
    notification_channels: Optional[List[str]] = ["push"]


class AlertUpdate(BaseModel):
    is_read: Optional[bool] = None
    is_dismissed: Optional[bool] = None


class AlertResponse(BaseModel):
    id: str
    user_id: str
    threat_id: str
    is_read: bool
    is_dismissed: bool
    notification_sent: bool
    notification_sent_at: Optional[datetime] = None
    notification_channels: Optional[List[str]] = None
    created_date: datetime
    read_date: Optional[datetime] = None
    
    class Config:
        from_attributes = True


# ============= Auth Schemas =============

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


# ============= Chatbot Schemas =============

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    session_id: Optional[str] = None
    language: str = "fr"
    context: Optional[Dict[str, Any]] = None
    educational_mode: bool = False  # Mode éducatif activé


class ChatResponse(BaseModel):
    response: str
    session_id: str
    context: Optional[Dict[str, Any]] = None
    suggested_actions: Optional[List[str]] = None
    related_threats: Optional[List[str]] = None
    related_terms: Optional[List[str]] = None  # Termes du glossaire
    related_lessons: Optional[List[str]] = None  # Leçons suggérées


# ============= Trend Analysis Schemas =============

class TrendAnalysisResponse(BaseModel):
    id: str
    analysis_date: datetime
    period_start: datetime
    period_end: datetime
    total_threats: int
    critical_threats: int
    high_threats: int
    category_distribution: Optional[Dict[str, int]] = None
    sector_distribution: Optional[Dict[str, int]] = None
    region_distribution: Optional[Dict[str, int]] = None
    trending_threats: Optional[List[str]] = None
    top_tags: Optional[List[str]] = None
    top_targets: Optional[List[str]] = None
    ai_insights: Optional[str] = None
    predictions: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True


# ============= Statistics Schemas =============

class DashboardStats(BaseModel):
    """Statistiques du tableau de bord"""
    total_threats: int
    active_threats: int
    critical_threats: int
    high_threats: int
    threats_today: int
    threats_this_week: int
    threats_this_month: int
    trending_categories: List[Dict[str, Any]]
    recent_threats: List[ThreatResponse]
    severity_distribution: Dict[str, int]
    category_distribution: Dict[str, int]


class FilterParams(BaseModel):
    """Paramètres de filtrage pour les menaces"""
    category: Optional[ThreatCategory] = None
    severity: Optional[SeverityLevel] = None
    source: Optional[str] = None
    tags: Optional[List[str]] = None
    sector: Optional[str] = None
    region: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    search: Optional[str] = None
    is_trending: Optional[bool] = None
    is_active: Optional[bool] = True
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)
