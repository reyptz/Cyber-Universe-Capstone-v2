from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional

from app.models import (
    GlossaryTerm, EducationalResource, DailyLesson,
    DifficultyLevel, TeamColor
)
from app.schemas import (
    GlossaryTermResponse, GlossaryTermCreate,
    EducationalResourceResponse, EducationalResourceCreate,
    DailyLessonResponse, DailyLessonCreate,
    UserLessonProgressResponse
)
from app.services.educational_service import EducationalService

router = APIRouter(prefix="/educational", tags=["Educational"])


# ============= Glossaire =============

@router.get("/glossary", response_model=List[GlossaryTermResponse])
async def get_glossary(
    query: Optional[str] = None,
    category: Optional[str] = None,
    team_color: Optional[TeamColor] = None,
    difficulty: Optional[DifficultyLevel] = None,
    limit: int = Query(default=50, le=100)
):
    """
    Récupère le glossaire des termes cybersécurité
    """
    terms = await EducationalService.search_glossary(
        query=query,
        category=category,
        team_color=team_color,
        difficulty=difficulty,
        limit=limit
    )
    
    return [GlossaryTermResponse.model_validate({**t.model_dump(), 'id': str(t.id)}) for t in terms]


@router.get("/glossary/popular", response_model=List[GlossaryTermResponse])
async def get_popular_terms(limit: int = Query(default=10, le=50)):
    """
    Récupère les termes populaires du glossaire
    """
    terms = await EducationalService.get_popular_terms(limit)
    return [GlossaryTermResponse.model_validate({**t.model_dump(), 'id': str(t.id)}) for t in terms]


@router.get("/glossary/{slug}", response_model=GlossaryTermResponse)
async def get_glossary_term(slug: str):
    """
    Récupère un terme du glossaire par son slug
    """
    term = await EducationalService.get_glossary_term(slug)
    
    if not term:
        raise HTTPException(status_code=404, detail="Term not found")
    
    return GlossaryTermResponse.model_validate(term.model_dump())


@router.post("/glossary", response_model=GlossaryTermResponse)
async def create_glossary_term(term_data: GlossaryTermCreate):
    """
    Crée un nouveau terme dans le glossaire
    """
    term = await EducationalService.create_glossary_term(term_data)
    return GlossaryTermResponse.model_validate(term.model_dump())


# ============= Ressources Éducatives =============

@router.get("/resources", response_model=List[EducationalResourceResponse])
async def get_resources(
    type: Optional[str] = None,
    organization: Optional[str] = None,
    team_color: Optional[TeamColor] = None,
    is_featured: Optional[bool] = None,
    limit: int = Query(default=100, le=200)
):
    """
    Récupère les ressources éducatives (standards, frameworks, certifications)
    """
    resources = await EducationalService.get_resources(
        type=type,
        organization=organization,
        team_color=team_color,
        is_featured=is_featured,
        limit=limit
    )
    
    return [EducationalResourceResponse.model_validate({**r.model_dump(), 'id': str(r.id)}) for r in resources]


@router.get("/resources/featured", response_model=List[EducationalResourceResponse])
async def get_featured_resources(limit: int = Query(default=10, le=50)):
    """
    Récupère les ressources mises en avant
    """
    resources = await EducationalService.get_featured_resources(limit)
    return [EducationalResourceResponse.model_validate({**r.model_dump(), 'id': str(r.id)}) for r in resources]


@router.get("/resources/{slug}", response_model=EducationalResourceResponse)
async def get_resource(slug: str):
    """
    Récupère une ressource par son slug
    """
    resource = await EducationalService.get_resource(slug)
    
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    
    return EducationalResourceResponse.model_validate(resource.model_dump())


@router.post("/resources", response_model=EducationalResourceResponse)
async def create_resource(resource_data: EducationalResourceCreate):
    """
    Crée une nouvelle ressource éducative
    """
    resource = await EducationalService.create_resource(resource_data)
    return EducationalResourceResponse.model_validate(resource.model_dump())


# ============= Leçons Quotidiennes =============

@router.get("/lessons", response_model=List[DailyLessonResponse])
async def get_lessons(
    category: Optional[str] = None,
    team_color: Optional[TeamColor] = None,
    difficulty: Optional[DifficultyLevel] = None
):
    """
    Récupère toutes les leçons publiées
    """
    lessons = await EducationalService.get_all_lessons(
        category=category,
        team_color=team_color,
        difficulty=difficulty
    )
    
    return [DailyLessonResponse.model_validate({**l.model_dump(), 'id': str(l.id)}) for l in lessons]


@router.get("/lessons/today", response_model=DailyLessonResponse)
async def get_lesson_of_the_day(user_id: Optional[str] = None):
    """
    Récupère la leçon du jour
    
    Si user_id fourni, retourne la prochaine leçon non complétée.
    Sinon, retourne une leçon aléatoire.
    """
    lesson = await EducationalService.get_lesson_of_the_day(user_id)
    
    if not lesson:
        raise HTTPException(
            status_code=404,
            detail="No lesson available. All lessons completed!"
        )
    
    return DailyLessonResponse.model_validate(lesson.model_dump())


@router.get("/lessons/{slug}", response_model=DailyLessonResponse)
async def get_lesson(slug: str):
    """
    Récupère une leçon par son slug
    """
    lesson = await EducationalService.get_lesson(slug)
    
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")
    
    return DailyLessonResponse.model_validate(lesson.model_dump())


@router.post("/lessons", response_model=DailyLessonResponse)
async def create_lesson(lesson_data: DailyLessonCreate):
    """
    Crée une nouvelle leçon quotidienne
    """
    lesson = await EducationalService.create_lesson(lesson_data)
    return DailyLessonResponse.model_validate(lesson.model_dump())


@router.post("/lessons/{lesson_id}/complete")
async def complete_lesson(
    lesson_id: str,
    user_id: str,
    time_spent: int = Query(..., description="Temps passé en secondes"),
    quiz_score: Optional[float] = Query(None, ge=0, le=100),
    rating: Optional[int] = Query(None, ge=1, le=5)
):
    """
    Marque une leçon comme complétée
    """
    progress = await EducationalService.complete_lesson(
        user_id=user_id,
        lesson_id=lesson_id,
        time_spent=time_spent,
        quiz_score=quiz_score,
        rating=rating
    )
    
    return {
        "message": "Lesson completed successfully",
        "progress": UserLessonProgressResponse.model_validate(progress.model_dump())
    }


@router.get("/progress/{user_id}")
async def get_user_progress(user_id: str):
    """
    Récupère la progression d'apprentissage d'un utilisateur
    """
    progress = await EducationalService.get_user_progress(user_id)
    
    if not progress:
        raise HTTPException(status_code=404, detail="User not found")
    
    return progress


# ============= Statistiques =============

@router.get("/stats")
async def get_educational_stats():
    """
    Récupère les statistiques du module éducatif
    """
    stats = await EducationalService.get_educational_stats()
    return stats


# ============= Teams (Blue/Red/Purple) =============

@router.get("/teams/blue")
async def get_blue_team_content():
    """
    Contenu pour la Blue Team (Défense)
    """
    terms = await EducationalService.search_glossary(team_color=TeamColor.BLUE, limit=20)
    resources = await EducationalService.get_resources(team_color=TeamColor.BLUE, limit=20)
    lessons = await EducationalService.get_all_lessons(team_color=TeamColor.BLUE)
    
    return {
        "team": "blue",
        "description": "Équipe de défense - Protection et surveillance des systèmes",
        "glossary_terms": [GlossaryTermResponse.model_validate({**t.model_dump(), 'id': str(t.id)}) for t in terms],
        "resources": [EducationalResourceResponse.model_validate({**r.model_dump(), 'id': str(r.id)}) for r in resources],
        "lessons": [DailyLessonResponse.model_validate({**l.model_dump(), 'id': str(l.id)}) for l in lessons]
    }


@router.get("/teams/red")
async def get_red_team_content():
    """
    Contenu pour la Red Team (Attaque/Pentesting)
    """
    terms = await EducationalService.search_glossary(team_color=TeamColor.RED, limit=20)
    resources = await EducationalService.get_resources(team_color=TeamColor.RED, limit=20)
    lessons = await EducationalService.get_all_lessons(team_color=TeamColor.RED)
    
    return {
        "team": "red",
        "description": "Équipe offensive - Tests d'intrusion et audit de sécurité",
        "glossary_terms": [GlossaryTermResponse.model_validate({**t.model_dump(), 'id': str(t.id)}) for t in terms],
        "resources": [EducationalResourceResponse.model_validate({**r.model_dump(), 'id': str(r.id)}) for r in resources],
        "lessons": [DailyLessonResponse.model_validate({**l.model_dump(), 'id': str(l.id)}) for l in lessons]
    }


@router.get("/teams/purple")
async def get_purple_team_content():
    """
    Contenu pour la Purple Team (Hybride)
    """
    terms = await EducationalService.search_glossary(team_color=TeamColor.PURPLE, limit=20)
    resources = await EducationalService.get_resources(team_color=TeamColor.PURPLE, limit=20)
    lessons = await EducationalService.get_all_lessons(team_color=TeamColor.PURPLE)
    
    return {
        "team": "purple",
        "description": "Équipe hybride - Collaboration défense/attaque",
        "glossary_terms": [GlossaryTermResponse.model_validate({**t.model_dump(), 'id': str(t.id)}) for t in terms],
        "resources": [EducationalResourceResponse.model_validate({**r.model_dump(), 'id': str(r.id)}) for r in resources],
        "lessons": [DailyLessonResponse.model_validate({**l.model_dump(), 'id': str(l.id)}) for l in lessons]
    }


