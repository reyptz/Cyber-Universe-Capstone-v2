from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging
from slugify import slugify

from app.models import (
    GlossaryTerm, EducationalResource, DailyLesson, 
    UserLessonProgress, User, DifficultyLevel, TeamColor
)
from app.schemas import (
    GlossaryTermCreate, EducationalResourceCreate,
    DailyLessonCreate
)

logger = logging.getLogger(__name__)


class EducationalService:
    """Service pour les fonctionnalités éducatives"""
    
    # ========== Glossaire ==========
    
    @staticmethod
    async def create_glossary_term(term_data: GlossaryTermCreate) -> GlossaryTerm:
        """Crée un terme du glossaire"""
        slug = slugify(term_data.term)
        
        term = GlossaryTerm(
            **term_data.model_dump(),
            slug=slug
        )
        
        await term.insert()
        logger.info(f"Created glossary term: {term.term}")
        
        return term
    
    @staticmethod
    async def get_glossary_term(slug: str) -> Optional[GlossaryTerm]:
        """Récupère un terme par son slug"""
        term = await GlossaryTerm.find_one(GlossaryTerm.slug == slug)
        
        if term:
            term.view_count += 1
            await term.save()
        
        return term
    
    @staticmethod
    async def search_glossary(
        query: Optional[str] = None,
        category: Optional[str] = None,
        team_color: Optional[TeamColor] = None,
        difficulty: Optional[DifficultyLevel] = None,
        limit: int = 50
    ) -> List[GlossaryTerm]:
        """Recherche dans le glossaire"""
        criteria = []
        
        if query:
            # Recherche textuelle
            from beanie.operators import RegEx, Or
            criteria.append(
                Or(
                    RegEx(GlossaryTerm.term, query, "i"),
                    RegEx(GlossaryTerm.short_definition, query, "i")
                )
            )
        
        if category:
            criteria.append(GlossaryTerm.category == category)
        
        if team_color:
            from beanie.operators import In
            criteria.append(In(team_color, GlossaryTerm.team_colors))
        
        if difficulty:
            criteria.append(GlossaryTerm.difficulty == difficulty)
        
        if criteria:
            from beanie.operators import And
            terms = await GlossaryTerm.find(And(*criteria)).limit(limit).to_list()
        else:
            terms = await GlossaryTerm.find_all().limit(limit).to_list()
        
        return terms
    
    @staticmethod
    async def get_popular_terms(limit: int = 10) -> List[GlossaryTerm]:
        """Récupère les termes populaires"""
        terms = await GlossaryTerm.find(
            GlossaryTerm.is_popular == True
        ).sort(-GlossaryTerm.view_count).limit(limit).to_list()
        
        return terms
    
    # ========== Ressources Éducatives ==========
    
    @staticmethod
    async def create_resource(resource_data: EducationalResourceCreate) -> EducationalResource:
        """Crée une ressource éducative"""
        slug = slugify(resource_data.title)
        
        resource = EducationalResource(
            **resource_data.model_dump(),
            slug=slug
        )
        
        await resource.insert()
        logger.info(f"Created educational resource: {resource.title}")
        
        return resource
    
    @staticmethod
    async def get_resource(slug: str) -> Optional[EducationalResource]:
        """Récupère une ressource par son slug"""
        resource = await EducationalResource.find_one(
            EducationalResource.slug == slug
        )
        
        if resource:
            resource.view_count += 1
            await resource.save()
        
        return resource
    
    @staticmethod
    async def get_resources(
        type: Optional[str] = None,
        organization: Optional[str] = None,
        team_color: Optional[TeamColor] = None,
        is_featured: Optional[bool] = None,
        limit: int = 100
    ) -> List[EducationalResource]:
        """Récupère les ressources éducatives"""
        criteria = []
        
        if type:
            criteria.append(EducationalResource.type == type)
        
        if organization:
            criteria.append(EducationalResource.organization == organization)
        
        if team_color:
            from beanie.operators import In
            criteria.append(In(team_color, EducationalResource.team_colors))
        
        if is_featured is not None:
            criteria.append(EducationalResource.is_featured == is_featured)
        
        if criteria:
            from beanie.operators import And
            resources = await EducationalResource.find(
                And(*criteria)
            ).limit(limit).to_list()
        else:
            resources = await EducationalResource.find_all().limit(limit).to_list()
        
        return resources
    
    @staticmethod
    async def get_featured_resources(limit: int = 10) -> List[EducationalResource]:
        """Récupère les ressources mises en avant"""
        resources = await EducationalResource.find(
            EducationalResource.is_featured == True
        ).limit(limit).to_list()
        
        return resources
    
    # ========== Leçons Quotidiennes ==========
    
    @staticmethod
    async def create_lesson(lesson_data: DailyLessonCreate) -> DailyLesson:
        """Crée une leçon quotidienne"""
        slug = slugify(lesson_data.title)
        
        lesson = DailyLesson(
            **lesson_data.model_dump(),
            slug=slug,
            related_terms=[],
            related_resources=[]
        )
        
        await lesson.insert()
        logger.info(f"Created daily lesson: {lesson.title}")
        
        return lesson
    
    @staticmethod
    async def get_lesson(slug: str) -> Optional[DailyLesson]:
        """Récupère une leçon par son slug"""
        lesson = await DailyLesson.find_one(DailyLesson.slug == slug)
        return lesson
    
    @staticmethod
    async def get_lesson_of_the_day(user_id: Optional[str] = None) -> Optional[DailyLesson]:
        """Récupère la leçon du jour pour un utilisateur"""
        
        if user_id:
            # Récupérer les leçons déjà complétées
            user = await User.get(user_id)
            if not user:
                return None
            
            completed_ids = user.completed_lessons
            
            # Trouver la prochaine leçon non complétée
            from beanie.operators import NotIn
            lesson = await DailyLesson.find(
                DailyLesson.is_published == True,
                NotIn(DailyLesson.id, completed_ids) if completed_ids else {}
            ).sort(DailyLesson.lesson_number).first_or_none()
        else:
            # Leçon aléatoire ou première leçon
            lesson = await DailyLesson.find(
                DailyLesson.is_published == True
            ).sort(DailyLesson.lesson_number).first_or_none()
        
        return lesson
    
    @staticmethod
    async def get_all_lessons(
        category: Optional[str] = None,
        team_color: Optional[TeamColor] = None,
        difficulty: Optional[DifficultyLevel] = None,
        is_published: bool = True
    ) -> List[DailyLesson]:
        """Récupère toutes les leçons"""
        criteria = [DailyLesson.is_published == is_published]
        
        if category:
            criteria.append(DailyLesson.category == category)
        
        if team_color:
            criteria.append(DailyLesson.team_color == team_color)
        
        if difficulty:
            criteria.append(DailyLesson.difficulty == difficulty)
        
        from beanie.operators import And
        lessons = await DailyLesson.find(
            And(*criteria)
        ).sort(DailyLesson.lesson_number).to_list()
        
        return lessons
    
    @staticmethod
    async def complete_lesson(
        user_id: str,
        lesson_id: str,
        time_spent: int,
        quiz_score: Optional[float] = None,
        rating: Optional[int] = None
    ) -> UserLessonProgress:
        """Marque une leçon comme complétée"""
        
        # Créer ou mettre à jour la progression
        progress = await UserLessonProgress.find_one(
            UserLessonProgress.user_id == user_id,
            UserLessonProgress.lesson_id == lesson_id
        )
        
        if not progress:
            progress = UserLessonProgress(
                user_id=user_id,
                lesson_id=lesson_id
            )
        
        progress.is_completed = True
        progress.completion_date = datetime.now()
        progress.time_spent_seconds = time_spent
        progress.quiz_score = quiz_score
        progress.rating = rating
        progress.last_accessed = datetime.now()
        
        await progress.save()
        
        # Mettre à jour l'utilisateur
        user = await User.get(user_id)
        if user:
            if lesson_id not in user.completed_lessons:
                user.completed_lessons.append(lesson_id)
            
            # Mettre à jour le streak
            if user.last_lesson_date:
                days_since = (datetime.now() - user.last_lesson_date).days
                if days_since == 1:
                    user.daily_lesson_streak += 1
                elif days_since > 1:
                    user.daily_lesson_streak = 1
            else:
                user.daily_lesson_streak = 1
            
            user.last_lesson_date = datetime.now()
            await user.save()
        
        # Mettre à jour les statistiques de la leçon
        lesson = await DailyLesson.get(lesson_id)
        if lesson:
            lesson.completion_count += 1
            
            # Mettre à jour la note moyenne
            if rating:
                total_ratings = lesson.completion_count
                current_avg = lesson.average_rating
                lesson.average_rating = (
                    (current_avg * (total_ratings - 1) + rating) / total_ratings
                )
            
            await lesson.save()
        
        logger.info(f"User {user_id} completed lesson {lesson_id}")
        
        return progress
    
    @staticmethod
    async def get_user_progress(user_id: str) -> Dict[str, Any]:
        """Récupère la progression d'un utilisateur"""
        
        user = await User.get(user_id)
        if not user:
            return {}
        
        # Toutes les leçons complétées
        completed_progresses = await UserLessonProgress.find(
            UserLessonProgress.user_id == user_id,
            UserLessonProgress.is_completed == True
        ).to_list()
        
        # Statistiques
        total_time = sum(p.time_spent_seconds for p in completed_progresses)
        avg_score = (
            sum(p.quiz_score for p in completed_progresses if p.quiz_score) /
            len([p for p in completed_progresses if p.quiz_score])
        ) if completed_progresses else 0
        
        return {
            "user_id": user_id,
            "lessons_completed": len(user.completed_lessons),
            "current_streak": user.daily_lesson_streak,
            "total_time_minutes": total_time // 60,
            "average_quiz_score": round(avg_score, 2),
            "last_lesson_date": user.last_lesson_date,
            "recent_completions": completed_progresses[-5:]
        }
    
    # ========== Statistiques ==========
    
    @staticmethod
    async def get_educational_stats() -> Dict[str, Any]:
        """Récupère les statistiques globales du module éducatif"""
        
        total_terms = await GlossaryTerm.count()
        total_resources = await EducationalResource.count()
        total_lessons = await DailyLesson.find(
            DailyLesson.is_published == True
        ).count()
        
        # Top termes
        popular_terms = await GlossaryTerm.find_all()\
            .sort(-GlossaryTerm.view_count)\
            .limit(5)\
            .to_list()
        
        # Ressources par organisation
        all_resources = await EducationalResource.find_all().to_list()
        orgs = {}
        for r in all_resources:
            orgs[r.organization] = orgs.get(r.organization, 0) + 1
        
        return {
            "glossary": {
                "total_terms": total_terms,
                "popular_terms": [
                    {"term": t.term, "views": t.view_count}
                    for t in popular_terms
                ]
            },
            "resources": {
                "total": total_resources,
                "by_organization": orgs
            },
            "lessons": {
                "total_published": total_lessons
            }
        }

