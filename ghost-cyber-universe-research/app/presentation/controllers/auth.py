from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Optional

from app.schemas import UserCreate, UserResponse, Token, LoginRequest
from app.services.auth_service import AuthService
from app.models import User

router = APIRouter(prefix="/auth", tags=["Authentication"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Récupère l'utilisateur actuel depuis le token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = AuthService.decode_access_token(token)
    
    if payload is None:
        raise credentials_exception
    
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
    
    user = await AuthService.get_user_by_username(username)
    if user is None:
        raise credentials_exception
    
    return user


@router.post("/register", response_model=UserResponse)
async def register(user_data: UserCreate):
    """
    Inscription d'un nouvel utilisateur
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"Tentative inscription: {user_data.email}, username: {user_data.username}")
        user = await AuthService.create_user(user_data)
        logger.info(f"Utilisateur créé: {user.email}")
        
        # Convertir l'ObjectId en string
        user_dict = user.model_dump()
        user_dict['id'] = str(user.id)
        
        return UserResponse.model_validate(user_dict)
    except ValueError as e:
        logger.error(f"Erreur validation: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Erreur inattendue: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Erreur serveur: {str(e)}")


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Connexion utilisateur (retourne un JWT)
    """
    user = await AuthService.authenticate_user(form_data.username, form_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Créer le token
    access_token = AuthService.create_access_token(
        data={"sub": user.username}
    )
    
    # Mettre à jour last_login
    await AuthService.update_last_login(str(user.id))
    
    return Token(access_token=access_token, token_type="bearer")


@router.post("/login/json", response_model=Token)
async def login_json(login_data: LoginRequest):
    """
    Connexion utilisateur avec JSON (alternative à form-data)
    """
    user = await AuthService.authenticate_user(login_data.username, login_data.password)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    
    access_token = AuthService.create_access_token(
        data={"sub": user.username}
    )
    
    await AuthService.update_last_login(str(user.id))
    
    return Token(access_token=access_token, token_type="bearer")


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    Récupère les informations de l'utilisateur connecté
    """
    user_dict = current_user.model_dump()
    user_dict['id'] = str(current_user.id)
    return UserResponse.model_validate(user_dict)


@router.get("/me/recommendations")
async def get_my_recommendations(current_user: User = Depends(get_current_user)):
    """
    Recommandations personnalisées pour l'utilisateur connecté
    """
    recommendations = await AuthService.get_user_recommendations(str(current_user.id))
    return recommendations


@router.post("/me/favorites/{threat_id}")
async def add_favorite(
    threat_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Ajoute une menace aux favoris
    """
    user = await AuthService.add_favorite_alert(str(current_user.id), threat_id)
    
    return {
        "message": "Threat added to favorites",
        "favorites_count": len(user.favorite_threats)
    }


@router.delete("/me/favorites/{threat_id}")
async def remove_favorite(
    threat_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Retire une menace des favoris
    """
    user = await AuthService.remove_favorite_alert(str(current_user.id), threat_id)
    
    return {
        "message": "Threat removed from favorites",
        "favorites_count": len(user.favorite_threats)
    }


@router.get("/me/favorites")
async def get_favorites(current_user: User = Depends(get_current_user)):
    """
    Liste des menaces favorites de l'utilisateur
    """
    from app.models import Threat
    from beanie import PydanticObjectId
    
    favorites = []
    for threat_id in current_user.favorite_threats:
        try:
            threat = await Threat.get(PydanticObjectId(threat_id))
            if threat:
                favorites.append(threat)
        except:
            pass
    
    return {
        "count": len(favorites),
        "favorites": [
            {
                "id": str(t.id),
                "title": t.title,
                "category": t.category.value,
                "severity": t.severity.value,
                "detected_date": t.detected_date
            }
            for t in favorites
        ]
    }

