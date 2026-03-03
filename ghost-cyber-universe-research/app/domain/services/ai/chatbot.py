from typing import Dict, List, Optional, Any
import json
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Import conditionnel pour OpenAI
try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logger.warning("OpenAI not available. Using rule-based chatbot.")

from config import settings


class CyberSecurityChatbot:
    """
    Chatbot IA spécialisé en cybersécurité
    Type: Copilot Cyber pour conseils et explications
    """
    
    def __init__(self):
        self.openai_available = OPENAI_AVAILABLE and settings.OPENAI_API_KEY
        
        if self.openai_available:
            self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            self.model = "gpt-3.5-turbo"  # Ou "gpt-4" pour de meilleurs résultats
        
        # Contexte système pour le chatbot
        self.system_prompt = """Tu es CyberRadar Assistant, un expert en cybersécurité qui aide les utilisateurs à comprendre les menaces et à s'en protéger.

Tes responsabilités:
- Expliquer les menaces de cybersécurité de manière claire
- Fournir des conseils de mitigation pratiques
- Répondre aux questions sur les CVE, malwares, et autres menaces
- Aider à évaluer la gravité et l'impact des menaces
- Suggérer des actions de protection

Ton style:
- Professionnel mais accessible
- Précis et factuel
- Proactif dans les recommandations
- Multilingue (s'adapter à la langue de l'utilisateur)

Reste focalisé sur la cybersécurité. Si une question est hors sujet, redirige poliment vers la sécurité."""
        
        # Base de connaissances rule-based
        self.knowledge_base = self._init_knowledge_base()
    
    def _init_knowledge_base(self) -> Dict[str, Any]:
        """Initialise la base de connaissances pour les réponses rule-based"""
        return {
            "ransomware": {
                "definition": "Un ransomware est un type de malware qui chiffre les fichiers de la victime et demande une rançon pour les déchiffrer.",
                "mitigation": [
                    "Maintenir des sauvegardes régulières offline",
                    "Appliquer les patches de sécurité rapidement",
                    "Utiliser un antivirus à jour",
                    "Former les employés à reconnaître les emails de phishing",
                    "Segmenter le réseau",
                    "Implémenter le principe du moindre privilège"
                ]
            },
            "phishing": {
                "definition": "Le phishing est une technique d'ingénierie sociale visant à voler des informations sensibles en se faisant passer pour une entité de confiance.",
                "mitigation": [
                    "Vérifier l'expéditeur des emails",
                    "Ne pas cliquer sur des liens suspects",
                    "Activer l'authentification multi-facteurs (MFA)",
                    "Former les utilisateurs régulièrement",
                    "Utiliser des filtres anti-phishing",
                    "Signaler les tentatives de phishing"
                ]
            },
            "vulnerability": {
                "definition": "Une vulnérabilité est une faiblesse dans un système qui peut être exploitée par des attaquants.",
                "mitigation": [
                    "Appliquer les patches de sécurité rapidement",
                    "Effectuer des scans de vulnérabilités réguliers",
                    "Maintenir un inventaire des assets",
                    "Suivre les avis de sécurité des éditeurs",
                    "Implémenter un processus de patch management",
                    "Utiliser des solutions de détection d'intrusion"
                ]
            },
            "data_breach": {
                "definition": "Une fuite de données est un incident où des informations sensibles sont exposées à des personnes non autorisées.",
                "mitigation": [
                    "Chiffrer les données sensibles",
                    "Implémenter des contrôles d'accès stricts",
                    "Monitorer les accès aux données",
                    "Effectuer des audits de sécurité réguliers",
                    "Avoir un plan de réponse aux incidents",
                    "Former le personnel sur la protection des données"
                ]
            },
            "zero_day": {
                "definition": "Une vulnérabilité zero-day est une faille de sécurité inconnue de l'éditeur et sans patch disponible.",
                "mitigation": [
                    "Utiliser des solutions de détection comportementale",
                    "Implémenter le principe du moindre privilège",
                    "Segmenter le réseau",
                    "Maintenir des systèmes de détection d'intrusion à jour",
                    "Avoir un plan de réponse aux incidents",
                    "Surveiller les indicateurs de compromission"
                ]
            }
        }
    
    async def chat(
        self,
        message: str,
        language: str = "fr",
        context: Optional[Dict] = None,
        conversation_history: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Répond à un message utilisateur
        
        Args:
            message: Message de l'utilisateur
            language: Langue de la conversation
            context: Contexte additionnel (menaces référencées, etc.)
            conversation_history: Historique de la conversation
            
        Returns:
            Dict avec la réponse et métadonnées
        """
        try:
            # Si OpenAI disponible, utiliser GPT
            if self.openai_available:
                return await self._chat_with_gpt(message, language, context, conversation_history)
            else:
                return await self._chat_rule_based(message, language, context)
        
        except Exception as e:
            logger.error(f"Chatbot error: {str(e)}")
            return {
                "response": self._get_error_message(language),
                "error": str(e)
            }
    
    async def _chat_with_gpt(
        self,
        message: str,
        language: str,
        context: Optional[Dict],
        conversation_history: Optional[List[Dict]]
    ) -> Dict[str, Any]:
        """Utilise GPT pour répondre"""
        
        # Construire les messages
        messages = [{"role": "system", "content": self.system_prompt}]
        
        # Ajouter le contexte si disponible
        if context:
            context_msg = self._format_context(context, language)
            messages.append({"role": "system", "content": context_msg})
        
        # Ajouter l'historique
        if conversation_history:
            messages.extend(conversation_history[-10:])  # Garder les 10 derniers messages
        
        # Ajouter le message actuel
        messages.append({"role": "user", "content": message})
        
        # Appeler GPT
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.7,
            max_tokens=500
        )
        
        bot_response = response.choices[0].message.content
        
        # Extraire les suggestions d'actions
        suggested_actions = self._extract_actions(bot_response)
        
        # Identifier les menaces référencées
        related_threats = self._extract_threat_references(message, context)
        
        return {
            "response": bot_response,
            "suggested_actions": suggested_actions,
            "related_threats": related_threats,
            "model": self.model,
            "tokens_used": response.usage.total_tokens
        }
    
    async def _chat_rule_based(
        self,
        message: str,
        language: str,
        context: Optional[Dict]
    ) -> Dict[str, Any]:
        """Chatbot basé sur des règles (fallback)"""
        
        message_lower = message.lower()
        
        # Détection d'intention
        intent = self._detect_intent(message_lower)
        
        # Générer la réponse selon l'intention
        if intent == "explain_threat":
            response = self._explain_threat(message_lower, language)
        elif intent == "mitigation":
            response = self._provide_mitigation(message_lower, language)
        elif intent == "severity":
            response = self._explain_severity(message_lower, language)
        elif intent == "greeting":
            response = self._get_greeting(language)
        else:
            response = self._get_default_response(language)
        
        return {
            "response": response,
            "suggested_actions": self._get_general_actions(language),
            "related_threats": [],
            "model": "rule-based"
        }
    
    def _detect_intent(self, message: str) -> str:
        """Détecte l'intention du message"""
        
        # Patterns d'intention
        patterns = {
            "greeting": [r"\b(bonjour|salut|hello|hi|hey)\b"],
            "explain_threat": [
                r"\b(qu'est-ce|what is|c'est quoi|explain|expliquer)\b",
                r"\b(ransomware|phishing|malware|vulnerability|breach)\b"
            ],
            "mitigation": [
                r"\b(comment|how|protéger|protect|mitigation|防护)\b",
                r"\b(prevent|éviter|défense|defense)\b"
            ],
            "severity": [
                r"\b(gravité|severity|危险|危険|serious|grave)\b",
                r"\b(impact|risque|risk|danger)\b"
            ]
        }
        
        for intent, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, message):
                    return intent
        
        return "general"
    
    def _explain_threat(self, message: str, language: str) -> str:
        """Explique un type de menace"""
        
        # Identifier le type de menace
        for threat_type, info in self.knowledge_base.items():
            if threat_type in message:
                if language == "fr":
                    return f"{info['definition']}\n\nMesures de protection recommandées:\n" + \
                           "\n".join([f"• {m}" for m in info['mitigation'][:3]])
                else:
                    return f"{info['definition']}\n\nRecommended protections:\n" + \
                           "\n".join([f"• {m}" for m in info['mitigation'][:3]])
        
        # Réponse générique
        if language == "fr":
            return "Je peux vous expliquer différents types de menaces : ransomware, phishing, vulnerabilités, fuites de données, et zero-day. Quelle menace vous intéresse ?"
        else:
            return "I can explain different types of threats: ransomware, phishing, vulnerabilities, data breaches, and zero-day. Which threat are you interested in?"
    
    def _provide_mitigation(self, message: str, language: str) -> str:
        """Fournit des conseils de mitigation"""
        
        # Identifier le type de menace
        for threat_type, info in self.knowledge_base.items():
            if threat_type in message:
                if language == "fr":
                    return f"Pour se protéger contre {threat_type}:\n\n" + \
                           "\n".join([f"{i+1}. {m}" for i, m in enumerate(info['mitigation'])])
                else:
                    return f"To protect against {threat_type}:\n\n" + \
                           "\n".join([f"{i+1}. {m}" for i, m in enumerate(info['mitigation'])])
        
        # Conseils généraux
        if language == "fr":
            return """Mesures de protection générales:

1. Maintenir tous les systèmes à jour
2. Utiliser l'authentification multi-facteurs (MFA)
3. Effectuer des sauvegardes régulières
4. Former les utilisateurs à la sécurité
5. Implémenter le principe du moindre privilège
6. Surveiller les logs et activités suspectes
7. Avoir un plan de réponse aux incidents"""
        else:
            return """General security measures:

1. Keep all systems updated
2. Use multi-factor authentication (MFA)
3. Perform regular backups
4. Train users on security
5. Implement least privilege principle
6. Monitor logs and suspicious activities
7. Have an incident response plan"""
    
    def _explain_severity(self, message: str, language: str) -> str:
        """Explique les niveaux de gravité"""
        if language == "fr":
            return """Niveaux de gravité des menaces:

🔴 CRITIQUE: Menace immédiate nécessitant une action urgente
- Exploitation active en cours
- Impact majeur sur l'activité
- Données sensibles exposées

🟠 ÉLEVÉ: Menace sérieuse nécessitant une attention rapide
- Vulnérabilité facilement exploitable
- Impact significatif possible
- Patch disponible

🟡 MOYEN: Menace modérée à surveiller
- Exploitation complexe
- Impact limité
- Mitigation disponible

🟢 FAIBLE: Menace mineure
- Exploitation très difficile
- Impact minimal
- Information uniquement"""
        else:
            return """Threat severity levels:

🔴 CRITICAL: Immediate threat requiring urgent action
- Active exploitation ongoing
- Major business impact
- Sensitive data exposed

🟠 HIGH: Serious threat requiring quick attention
- Easily exploitable vulnerability
- Significant impact possible
- Patch available

🟡 MEDIUM: Moderate threat to monitor
- Complex exploitation
- Limited impact
- Mitigation available

🟢 LOW: Minor threat
- Very difficult to exploit
- Minimal impact
- Informational only"""
    
    def _get_greeting(self, language: str) -> str:
        """Retourne un message de bienvenue"""
        if language == "fr":
            return """Bonjour ! Je suis CyberRadar Assistant, votre expert en cybersécurité.

Je peux vous aider à:
• Comprendre les menaces cybersécurité
• Obtenir des conseils de protection
• Évaluer la gravité des risques
• Répondre à vos questions de sécurité

Comment puis-je vous aider aujourd'hui ?"""
        else:
            return """Hello! I'm CyberRadar Assistant, your cybersecurity expert.

I can help you:
• Understand cybersecurity threats
• Get protection advice
• Evaluate risk severity
• Answer your security questions

How can I help you today?"""
    
    def _get_default_response(self, language: str) -> str:
        """Réponse par défaut"""
        if language == "fr":
            return "Je suis là pour vous aider avec vos questions de cybersécurité. Vous pouvez me demander d'expliquer des menaces, de fournir des conseils de protection, ou d'évaluer des risques."
        else:
            return "I'm here to help with your cybersecurity questions. You can ask me to explain threats, provide protection advice, or evaluate risks."
    
    def _get_error_message(self, language: str) -> str:
        """Message d'erreur"""
        if language == "fr":
            return "Désolé, j'ai rencontré une erreur. Pouvez-vous reformuler votre question ?"
        else:
            return "Sorry, I encountered an error. Could you rephrase your question?"
    
    def _format_context(self, context: Dict, language: str) -> str:
        """Formate le contexte pour GPT"""
        context_str = "Context information:\n"
        
        if "threat" in context:
            threat = context["threat"]
            context_str += f"Threat: {threat.get('title', '')}\n"
            context_str += f"Category: {threat.get('category', '')}\n"
            context_str += f"Severity: {threat.get('severity', '')}\n"
        
        return context_str
    
    def _extract_actions(self, response: str) -> List[str]:
        """Extrait les actions suggérées de la réponse"""
        actions = []
        
        # Chercher des patterns de recommandations
        lines = response.split('\n')
        for line in lines:
            if any(marker in line for marker in ['•', '-', '1.', '2.', '3.', 'Recommandation', 'Action']):
                action = line.strip().lstrip('•-123456789. ')
                if len(action) > 10 and len(action) < 200:
                    actions.append(action)
        
        return actions[:5]  # Max 5 actions
    
    def _extract_threat_references(self, message: str, context: Optional[Dict]) -> List[int]:
        """Extrait les références aux menaces"""
        threat_ids = []
        
        # CVE IDs
        cves = re.findall(r'CVE-\d{4}-\d{4,}', message, re.IGNORECASE)
        
        # Si contexte fourni avec des menaces
        if context and "threat_id" in context:
            threat_ids.append(context["threat_id"])
        
        return threat_ids
    
    def _get_general_actions(self, language: str) -> List[str]:
        """Actions générales suggérées"""
        if language == "fr":
            return [
                "Vérifier les dernières menaces critiques",
                "Consulter les alertes de votre secteur",
                "Mettre à jour vos systèmes"
            ]
        else:
            return [
                "Check latest critical threats",
                "Review alerts for your sector",
                "Update your systems"
            ]


# Instance globale
chatbot = CyberSecurityChatbot()

