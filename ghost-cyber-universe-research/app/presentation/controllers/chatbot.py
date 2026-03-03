from fastapi import APIRouter, HTTPException
from typing import Optional
import uuid

from app.schemas import ChatRequest, ChatResponse
from app.ai.chatbot import chatbot
from app.models import ChatHistory, User

router = APIRouter(prefix="/chatbot", tags=["Chatbot"])


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest
):
    """
    Dialogue avec le chatbot IA cybersécurité
    """
    try:
        # Générer un session_id si non fourni
        session_id = request.session_id or str(uuid.uuid4())
        
        # Récupérer l'historique de conversation si session existante
        conversation_history = []
        if request.session_id:
            chat_records = await ChatHistory.find(
                ChatHistory.session_id == request.session_id
            ).sort(-ChatHistory.created_date).limit(10).to_list()
            
            for record in reversed(chat_records):
                conversation_history.append({"role": "user", "content": record.user_message})
                conversation_history.append({"role": "assistant", "content": record.bot_response})
        
        # Obtenir la réponse du chatbot
        response = await chatbot.chat(
            message=request.message,
            language=request.language,
            context=request.context,
            conversation_history=conversation_history
        )
        
        # Enregistrer dans l'historique
        chat_record = ChatHistory(
            session_id=session_id,
            user_message=request.message,
            bot_response=response["response"],
            context=request.context,
            language=request.language
        )
        
        await chat_record.insert()
        
        return ChatResponse(
            response=response["response"],
            session_id=session_id,
            context=response.get("context"),
            suggested_actions=response.get("suggested_actions"),
            related_threats=response.get("related_threats")
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chatbot error: {str(e)}")


@router.get("/history/{session_id}")
async def get_chat_history(
    session_id: str,
    limit: int = 50
):
    """
    Récupère l'historique de chat d'une session
    """
    history = await ChatHistory.find(
        ChatHistory.session_id == session_id
    ).sort(-ChatHistory.created_date).limit(limit).to_list()
    
    return {
        "session_id": session_id,
        "messages": [
            {
                "user": h.user_message,
                "bot": h.bot_response,
                "timestamp": h.created_date
            }
            for h in reversed(history)
        ]
    }


@router.post("/feedback/{chat_id}")
async def submit_feedback(
    chat_id: str,
    rating: int
):
    """
    Soumet un feedback pour une réponse du chatbot
    """
    if not 1 <= rating <= 5:
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")
    
    chat = await ChatHistory.get(chat_id)
    if chat:
        chat.rating = rating
        await chat.save()
    
    return {"message": "Feedback submitted successfully"}

