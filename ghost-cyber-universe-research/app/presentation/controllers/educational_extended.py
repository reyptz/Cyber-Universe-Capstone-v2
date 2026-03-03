"""
Routes étendues pour le contenu éducatif généré par IA
"""

from fastapi import APIRouter

router = APIRouter(prefix="/educational", tags=["Educational Extended"])


@router.post("/generate/scenarios")
async def generate_scenarios():
    """
    Génère les scénarios Red vs Blue avec l'IA
    """
    from app.services.educational_generator import save_scenarios_to_database
    
    saved = await save_scenarios_to_database()
    
    return {
        "message": f"{saved} scénarios générés",
        "saved": saved
    }


@router.post("/generate/glossary")
async def generate_glossary():
    """
    Génère le glossaire avec l'IA
    """
    from app.services.educational_generator import generate_glossary_terms
    
    saved = await generate_glossary_terms()
    
    return {
        "message": f"{saved} termes générés",
        "saved": saved
    }


@router.get("/scenarios")
async def get_red_blue_scenarios():
    """
    Récupère les scénarios Red vs Blue depuis le backend (générés par IA)
    """
    from app.services.educational_generator import generate_red_blue_scenarios
    
    scenarios = await generate_red_blue_scenarios()
    
    return {
        "total": len(scenarios),
        "scenarios": scenarios
    }

