from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from beanie import PydanticObjectId
import hashlib
import secrets
import logging

from config import settings
from app.models import User
from app.schemas import UserCreate

logger = logging.getLogger(__name__)

# Fonctions de hachage simples - SHA-256 + salt (pas de limite de taille)
def hash_password(password: str) -> str:
    """Hash SHA-256 + salt sécurisé"""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"sha256${salt}${hashed}"

def verify_password_simple(password: str, hashed: str) -> bool:
    """Vérifie SHA-256 + salt"""
    try:
        parts = hashed.split('$')
        if len(parts) != 3 or parts[0] != 'sha256':
            return False
        salt, stored_hash = parts[1], parts[2]
        computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return secrets.compare_digest(stored_hash, computed_hash)
    except:
        return False


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
    async def get_user_by_username(username: str) -> Optional[User]:
        """Récupère un utilisateur par nom d'utilisateur"""
        return await User.find_one(User.username == username)
    
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
        logger.info(f"Nouvel utilisateur créé: {user.email}")
        
        return user
    
    @staticmethod
    async def update_last_login(user_id: str):
        """Met à jour la date de dernière connexion"""
        try:
            user = await User.get(PydanticObjectId(user_id))
            if user:
                user.last_login = datetime.utcnow()
                await user.save()
        except Exception as e:
            logger.error(f"Erreur mise à jour last_login: {e}")
    
    @staticmethod
    async def get_user_recommendations(user_id: str) -> dict:
        """Recommandations personnalisées pour l'utilisateur"""
        try:
            user = await User.get(PydanticObjectId(user_id))
            if not user:
                return {"recommendations": []}
            
            # Recommandations basiques
            recommendations = [
                {
                    "type": "security",
                    "title": "Activer l'authentification 2FA",
                    "description": "Renforcez la sécurité de votre compte",
                    "priority": "high"
                },
                {
                    "type": "education", 
                    "title": "Compléter le module Phishing",
                    "description": "Apprenez à détecter les tentatives d'hameçonnage",
                    "priority": "medium"
                }
            ]
            
            return {
                "user_id": user_id,
                "recommendations": recommendations
            }
            
        except Exception as e:
            logger.error(f"Erreur recommandations: {e}")
            return {"recommendations": []}
    
    @staticmethod
    async def add_favorite_alert(user_id: str, threat_id: str) -> User:
        """Ajoute une menace aux favoris"""
        user = await User.get(PydanticObjectId(user_id))
        if not user:
            raise ValueError("User not found")
        
        if threat_id not in user.favorite_threats:
            user.favorite_threats.append(threat_id)
            await user.save()
        
        return user
    
    @staticmethod
    async def remove_favorite_alert(user_id: str, threat_id: str) -> User:
        """Retire une menace des favoris"""
        user = await User.get(PydanticObjectId(user_id))
        if not user:
            raise ValueError("User not found")
        
        if threat_id in user.favorite_threats:
            user.favorite_threats.remove(threat_id)
            await user.save()
        
        return user
