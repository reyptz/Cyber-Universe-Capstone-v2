from datetime import datetime, timedelta
from typing import Optional
import logging
from passlib.context import CryptContext
from jose import JWTError, jwt

from app.models import User
from app.schemas import UserCreate, UserUpdate
from config import settings

logger = logging.getLogger(__name__)

# Context pour hash de mots de passe
# Utiliser bcrypt_sha256 pour supporter les mots de passe > 72 octets en toute sécurité
pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")


class AuthService:
    """Service d'authentification et gestion utilisateurs"""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Vérifie un mot de passe"""
        return verify_password_simple(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Hash un mot de passe SHA-256 + salt"""
        return hash_password(password)
    
    @staticmethod
    def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """Crée un token JWT"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        
        encoded_jwt = jwt.encode(
            to_encode,
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM
        )
        
        return encoded_jwt
    
    @staticmethod
    def decode_access_token(token: str) -> Optional[dict]:
        """Décode un token JWT"""
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.ALGORITHM]
            )
            return payload
        except JWTError:
            return None
    
    @staticmethod
    async def authenticate_user(username: str, password: str) -> Optional[User]:
        """Authentifie un utilisateur"""
        # Autoriser l'authentification par username OU email
        user = await User.find_one(User.username == username)
        if not user:
            user = await User.find_one(User.email == username)
        
        if not user:
            return None
        
        if not AuthService.verify_password(password, user.hashed_password):
            return None
        
        return user
    
    @staticmethod
    async def create_user(user_data: UserCreate) -> User:
        """Crée un nouvel utilisateur"""
        # Vérifier si l'utilisateur existe déjà
        existing_user = await User.find_one(User.email == user_data.email)
        if existing_user:
            raise ValueError("Email already registered")
        
        existing_username = await User.find_one(User.username == user_data.username)
        if existing_username:
            raise ValueError("Username already taken")
        
        # Créer l'utilisateur
        hashed_password = AuthService.get_password_hash(user_data.password)
        
        user = User(
            email=user_data.email,
            username=user_data.username,
            hashed_password=hashed_password,
            full_name=user_data.full_name,
            organization=user_data.organization,
            preferences={
                "categories": [],
                "severity_min": "medium",
                "sectors": [],
                "regions": []
            },
            notification_settings={
                "push_enabled": True,
                "email_enabled": True,
                "critical_only": False
            }
        )
        
        await user.insert()
        
        logger.info(f"Created user: {user.username}")
        
        return user
    
    @staticmethod
    async def get_user_by_username(username: str) -> Optional[User]:
        """Récupère un utilisateur par username"""
        return await User.find_one(User.username == username)
    
    @staticmethod
    async def get_user_by_email(email: str) -> Optional[User]:
        """Récupère un utilisateur par email"""
        return await User.find_one(User.email == email)
    
    @staticmethod
    async def update_user(user_id: str, user_data: UserUpdate) -> Optional[User]:
        """Met à jour un utilisateur"""
        user = await User.get(user_id)
        
        if not user:
            return None
        
        # Mettre à jour les champs fournis
        update_data = user_data.model_dump(exclude_unset=True)
        
        for field, value in update_data.items():
            setattr(user, field, value)
        
        await user.save()
        
        logger.info(f"Updated user: {user_id}")
        
        return user
    
    @staticmethod
    async def update_last_login(user_id: str):
        """Met à jour la dernière connexion"""
        user = await User.get(user_id)
        
        if user:
            user.last_login = datetime.now()
            await user.save()
    
    @staticmethod
    async def add_favorite_alert(user_id: str, threat_id: str) -> User:
        """Ajoute une alerte aux favoris"""
        user = await User.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if not hasattr(user, 'favorite_threats'):
            user.favorite_threats = []
        
        if threat_id not in user.favorite_threats:
            user.favorite_threats.append(threat_id)
            await user.save()
        
        return user
    
    @staticmethod
    async def remove_favorite_alert(user_id: str, threat_id: str) -> User:
        """Retire une alerte des favoris"""
        user = await User.get(user_id)
        
        if not user:
            raise ValueError("User not found")
        
        if hasattr(user, 'favorite_threats') and threat_id in user.favorite_threats:
            user.favorite_threats.remove(threat_id)
            await user.save()
        
        return user
    
    @staticmethod
    async def get_user_recommendations(user_id: str) -> dict:
        """Génère des recommandations personnalisées"""
        user = await User.get(user_id)
        
        if not user:
            return {}
        
        from app.services.threat_service import ThreatService
        from app.models import SeverityLevel
        
        recommendations = {
            "security_tips": [],
            "suggested_lessons": [],
            "relevant_threats": [],
            "security_score": 0
        }
        
        # Calculer un score de sécurité basé sur l'activité
        score = 50  # Score de base
        
        # +10 si MFA activé (à implémenter)
        # +15 si leçons complétées
        if user.completed_lessons and len(user.completed_lessons) > 5:
            score += 15
        
        # +10 pour streak actif
        if user.daily_lesson_streak > 3:
            score += 10
        
        # +15 si profil complet
        if user.full_name and user.organization:
            score += 15
        
        recommendations["security_score"] = min(score, 100)
        
        # Tips personnalisés
        if score < 70:
            recommendations["security_tips"].append(
                "Complétez votre profil pour des recommandations plus précises"
            )
        
        if not user.fcm_token:
            recommendations["security_tips"].append(
                "Activez les notifications push pour rester informé des menaces critiques"
            )
        
        if user.daily_lesson_streak == 0:
            recommendations["security_tips"].append(
                "Commencez votre formation quotidienne en cybersécurité"
            )
        
        # Leçons suggérées (basées sur les préférences)
        if user.preferences:
            categories = user.preferences.get("categories", [])
            # Suggérer des leçons pertinentes
            recommendations["suggested_lessons"] = [
                "intro-cybersecurite",
                "phishing-reconnaissance-protection",
                "mots-de-passe-securises"
            ]
        
        # Menaces pertinentes basées sur les préférences
        if user.preferences:
            severity_min = user.preferences.get("severity_min", "medium")
            sectors = user.preferences.get("sectors", [])
            
            # Récupérer quelques menaces récentes
            # (implémentation simplifiée)
            recommendations["relevant_threats"] = []
        
        return recommendations

