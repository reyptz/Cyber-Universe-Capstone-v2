from typing import List, Dict, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Imports conditionnels
try:
    import firebase_admin
    from firebase_admin import credentials, messaging
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False
    logger.warning("Firebase not available. Push notifications disabled.")

from config import settings


class NotificationService:
    """Service de notifications push"""
    
    def __init__(self):
        self.firebase_initialized = False
        
        if FIREBASE_AVAILABLE and settings.FIREBASE_CREDENTIALS_PATH:
            try:
                # Initialiser Firebase
                cred = credentials.Certificate(settings.FIREBASE_CREDENTIALS_PATH)
                firebase_admin.initialize_app(cred)
                self.firebase_initialized = True
                logger.info("Firebase initialized successfully")
            except Exception as e:
                logger.error(f"Firebase initialization failed: {str(e)}")
    
    async def send_threat_alert(
        self,
        fcm_token: str,
        threat: Dict,
        language: str = "fr"
    ) -> bool:
        """
        Envoie une alerte de menace
        
        Args:
            fcm_token: Token FCM de l'utilisateur
            threat: Données de la menace
            language: Langue de la notification
            
        Returns:
            bool: Succès de l'envoi
        """
        if not self.firebase_initialized:
            logger.warning("Firebase not initialized. Cannot send notification.")
            return False
        
        try:
            # Construire le message
            title, body = self._format_notification(threat, language)
            
            message = messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=body
                ),
                data={
                    "type": "threat_alert",
                    "threat_id": str(threat.get("id", "")),
                    "severity": threat.get("severity", ""),
                    "category": threat.get("category", "")
                },
                token=fcm_token,
                android=messaging.AndroidConfig(
                    priority="high",
                    notification=messaging.AndroidNotification(
                        sound="default",
                        color="#FF5733",
                        priority="max"
                    )
                ),
                apns=messaging.APNSConfig(
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            sound="default",
                            badge=1
                        )
                    )
                )
            )
            
            # Envoyer
            response = messaging.send(message)
            logger.info(f"Notification sent successfully: {response}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")
            return False
    
    async def send_batch_notifications(
        self,
        tokens: List[str],
        threat: Dict,
        language: str = "fr"
    ) -> Dict[str, int]:
        """
        Envoie des notifications en batch
        
        Args:
            tokens: Liste de tokens FCM
            threat: Données de la menace
            language: Langue des notifications
            
        Returns:
            Dict: Statistiques d'envoi
        """
        if not self.firebase_initialized:
            return {"success": 0, "failure": len(tokens)}
        
        try:
            title, body = self._format_notification(threat, language)
            
            # Créer les messages
            messages = []
            for token in tokens[:500]:  # Firebase limite à 500 par batch
                message = messaging.Message(
                    notification=messaging.Notification(
                        title=title,
                        body=body
                    ),
                    data={
                        "type": "threat_alert",
                        "threat_id": str(threat.get("id", "")),
                        "severity": threat.get("severity", ""),
                        "category": threat.get("category", "")
                    },
                    token=token
                )
                messages.append(message)
            
            # Envoyer en batch
            response = messaging.send_all(messages)
            
            logger.info(
                f"Batch notification sent: {response.success_count} success, "
                f"{response.failure_count} failures"
            )
            
            return {
                "success": response.success_count,
                "failure": response.failure_count
            }
            
        except Exception as e:
            logger.error(f"Error sending batch notifications: {str(e)}")
            return {"success": 0, "failure": len(tokens)}
    
    def _format_notification(
        self,
        threat: Dict,
        language: str
    ) -> tuple[str, str]:
        """Formate le contenu de la notification"""
        
        severity = threat.get("severity", "").upper()
        category = threat.get("category", "")
        title_text = threat.get("title", "")[:100]
        
        # Emojis par sévérité
        severity_emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "ℹ️"
        }.get(severity, "⚠️")
        
        if language == "fr":
            title = f"{severity_emoji} Alerte {severity} - Cybersécurité"
            body = f"{category.replace('_', ' ').title()}: {title_text}"
        elif language == "es":
            title = f"{severity_emoji} Alerta {severity} - Ciberseguridad"
            body = f"{category.replace('_', ' ').title()}: {title_text}"
        elif language == "ar":
            title = f"{severity_emoji} تنبيه {severity} - الأمن السيبراني"
            body = title_text
        else:  # English
            title = f"{severity_emoji} {severity} Alert - Cybersecurity"
            body = f"{category.replace('_', ' ').title()}: {title_text}"
        
        return title, body
    
    async def send_topic_notification(
        self,
        topic: str,
        threat: Dict,
        language: str = "fr"
    ) -> bool:
        """
        Envoie une notification à un topic
        
        Args:
            topic: Nom du topic (ex: "critical_threats")
            threat: Données de la menace
            language: Langue de la notification
            
        Returns:
            bool: Succès de l'envoi
        """
        if not self.firebase_initialized:
            return False
        
        try:
            title, body = self._format_notification(threat, language)
            
            message = messaging.Message(
                notification=messaging.Notification(
                    title=title,
                    body=body
                ),
                data={
                    "type": "threat_alert",
                    "threat_id": str(threat.get("id", "")),
                    "severity": threat.get("severity", ""),
                    "category": threat.get("category", "")
                },
                topic=topic
            )
            
            response = messaging.send(message)
            logger.info(f"Topic notification sent: {response}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending topic notification: {str(e)}")
            return False
    
    async def subscribe_to_topic(
        self,
        tokens: List[str],
        topic: str
    ) -> bool:
        """Abonne des utilisateurs à un topic"""
        if not self.firebase_initialized:
            return False
        
        try:
            response = messaging.subscribe_to_topic(tokens, topic)
            logger.info(f"Subscribed {response.success_count} users to topic {topic}")
            return True
        except Exception as e:
            logger.error(f"Error subscribing to topic: {str(e)}")
            return False
    
    async def unsubscribe_from_topic(
        self,
        tokens: List[str],
        topic: str
    ) -> bool:
        """Désabonne des utilisateurs d'un topic"""
        if not self.firebase_initialized:
            return False
        
        try:
            response = messaging.unsubscribe_from_topic(tokens, topic)
            logger.info(f"Unsubscribed {response.success_count} users from topic {topic}")
            return True
        except Exception as e:
            logger.error(f"Error unsubscribing from topic: {str(e)}")
            return False


# Instance globale
notification_service = NotificationService()

