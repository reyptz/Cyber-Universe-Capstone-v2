"""
Module de modération de contenu
"""
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
from ..config import config

logger = logging.getLogger(__name__)

class ContentModerator:
    """Modérateur de contenu utilisant des modèles de classification"""
    
    def __init__(self):
        """Initialise les modèles de modération"""
        try:
            # Modèle de détection de toxicité
            self.toxicity_classifier = pipeline(
                "text-classification",
                model="unitary/toxic-bert",
                return_all_scores=True
            )
            
            # Modèle de détection de haine
            self.hate_classifier = pipeline(
                "text-classification", 
                model="facebook/roberta-hate-speech-dynabench-r4-target",
                return_all_scores=True
            )
            
            # Modèle de détection de violence
            self.violence_classifier = pipeline(
                "text-classification",
                model="facebook/roberta-hate-speech-dynabench-r4-target", 
                return_all_scores=True
            )
            
            # Patterns de contenu suspect
            self.suspicious_patterns = [
                r"ignore\s+previous\s+instructions",
                r"forget\s+everything",
                r"you\s+are\s+now\s+a\s+different",
                r"pretend\s+to\s+be",
                r"act\s+as\s+if",
                r"roleplay\s+as",
                r"jailbreak",
                r"dan\s+mode",
                r"developer\s+mode",
                r"system\s+prompt",
                r"prompt\s+injection"
            ]
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du modérateur: {e}")
            raise
    
    def detect_toxicity(self, text: str) -> Dict[str, Any]:
        """
        Détecte la toxicité dans le texte
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de l'analyse de toxicité
        """
        try:
            results = self.toxicity_classifier(text)
            
            # Calcul du score de toxicité global
            toxicity_score = 0
            for result in results[0]:
                if result['label'] in ['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate']:
                    toxicity_score = max(toxicity_score, result['score'])
            
            return {
                'is_toxic': toxicity_score > config.CONTENT_MODERATION['toxicity_threshold'],
                'toxicity_score': toxicity_score,
                'details': results[0],
                'risk_level': self._get_risk_level(toxicity_score, 'toxicity')
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de toxicité: {e}")
            return {'is_toxic': False, 'toxicity_score': 0, 'details': [], 'risk_level': 'low'}
    
    def detect_hate_speech(self, text: str) -> Dict[str, Any]:
        """
        Détecte le discours de haine
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de l'analyse de discours de haine
        """
        try:
            results = self.hate_classifier(text)
            
            hate_score = 0
            for result in results[0]:
                if 'hate' in result['label'].lower():
                    hate_score = max(hate_score, result['score'])
            
            return {
                'is_hate_speech': hate_score > config.CONTENT_MODERATION['hate_speech_threshold'],
                'hate_score': hate_score,
                'details': results[0],
                'risk_level': self._get_risk_level(hate_score, 'hate_speech')
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de discours de haine: {e}")
            return {'is_hate_speech': False, 'hate_score': 0, 'details': [], 'risk_level': 'low'}
    
    def detect_violence(self, text: str) -> Dict[str, Any]:
        """
        Détecte le contenu violent
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de l'analyse de violence
        """
        try:
            # Patterns de violence
            violence_patterns = [
                r"kill\s+yourself",
                r"murder",
                r"assassinate",
                r"bomb\s+threat",
                r"terrorist\s+attack",
                r"mass\s+shooting",
                r"violence\s+against",
                r"physical\s+harm"
            ]
            
            violence_score = 0
            for pattern in violence_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    violence_score = 0.8  # Score élevé si pattern détecté
            
            return {
                'is_violent': violence_score > config.CONTENT_MODERATION['violence_threshold'],
                'violence_score': violence_score,
                'risk_level': self._get_risk_level(violence_score, 'violence')
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de violence: {e}")
            return {'is_violent': False, 'violence_score': 0, 'risk_level': 'low'}
    
    def detect_suspicious_patterns(self, text: str) -> Dict[str, Any]:
        """
        Détecte les patterns suspects (injection de prompts, jailbreak)
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de la détection de patterns suspects
        """
        suspicious_found = []
        max_score = 0
        
        for pattern in self.suspicious_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                suspicious_found.extend(matches)
                max_score = max(max_score, 0.9)  # Score élevé pour patterns suspects
        
        return {
            'is_suspicious': len(suspicious_found) > 0,
            'suspicious_patterns': suspicious_found,
            'suspicion_score': max_score,
            'risk_level': 'high' if max_score > 0.8 else 'medium' if max_score > 0.5 else 'low'
        }
    
    def moderate_content(self, text: str) -> Dict[str, Any]:
        """
        Effectue une modération complète du contenu
        
        Args:
            text: Texte à modérer
            
        Returns:
            Résultat complet de la modération
        """
        # Analyses individuelles
        toxicity = self.detect_toxicity(text)
        hate_speech = self.detect_hate_speech(text)
        violence = self.detect_violence(text)
        suspicious = self.detect_suspicious_patterns(text)
        
        # Calcul du score de risque global
        risk_scores = [
            toxicity['toxicity_score'],
            hate_speech['hate_score'],
            violence['violence_score'],
            suspicious['suspicion_score']
        ]
        
        global_risk_score = max(risk_scores)
        
        # Détermination du niveau de risque global
        if global_risk_score > 0.8:
            global_risk_level = 'critical'
        elif global_risk_score > 0.6:
            global_risk_level = 'high'
        elif global_risk_score > 0.4:
            global_risk_level = 'medium'
        else:
            global_risk_level = 'low'
        
        # Décision de modération
        should_block = (
            toxicity['is_toxic'] or
            hate_speech['is_hate_speech'] or
            violence['is_violent'] or
            suspicious['is_suspicious']
        )
        
        return {
            'should_block': should_block,
            'global_risk_score': global_risk_score,
            'global_risk_level': global_risk_level,
            'toxicity': toxicity,
            'hate_speech': hate_speech,
            'violence': violence,
            'suspicious_patterns': suspicious,
            'moderation_timestamp': self._get_timestamp()
        }
    
    def _get_risk_level(self, score: float, category: str) -> str:
        """Détermine le niveau de risque basé sur le score"""
        threshold = config.CONTENT_MODERATION.get(f'{category}_threshold', 0.7)
        
        if score > threshold * 1.2:
            return 'critical'
        elif score > threshold:
            return 'high'
        elif score > threshold * 0.7:
            return 'medium'
        else:
            return 'low'
    
    def _get_timestamp(self) -> str:
        """Retourne le timestamp actuel"""
        from datetime import datetime
        return datetime.utcnow().isoformat()
