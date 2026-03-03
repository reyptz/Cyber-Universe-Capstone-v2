"""
Module de détection d'injection de prompts et de jailbreak
"""
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from transformers import pipeline
import numpy as np
from ..config import config

logger = logging.getLogger(__name__)

class InjectionDetector:
    """Détecteur d'injection de prompts et de tentatives de jailbreak"""
    
    def __init__(self):
        """Initialise le détecteur d'injection"""
        try:
            # Modèle de classification pour détecter les tentatives d'injection
            self.injection_classifier = pipeline(
                "text-classification",
                model="microsoft/DialoGPT-medium",
                return_all_scores=True
            )
            
            # Patterns d'injection connus
            self.injection_patterns = [
                # Patterns d'ignorance d'instructions
                r"ignore\s+previous\s+instructions",
                r"forget\s+everything",
                r"disregard\s+all\s+previous",
                r"ignore\s+the\s+above",
                
                # Patterns de changement de rôle
                r"you\s+are\s+now\s+a\s+different",
                r"pretend\s+to\s+be",
                r"act\s+as\s+if",
                r"roleplay\s+as",
                r"you\s+are\s+no\s+longer",
                
                # Patterns de jailbreak
                r"jailbreak",
                r"dan\s+mode",
                r"developer\s+mode",
                r"system\s+prompt",
                r"prompt\s+injection",
                r"override\s+safety",
                
                # Patterns de manipulation
                r"this\s+is\s+just\s+a\s+test",
                r"hypothetically",
                r"in\s+a\s+fictional\s+scenario",
                r"for\s+educational\s+purposes",
                
                # Patterns de contournement
                r"bypass\s+safety",
                r"disable\s+safety",
                r"turn\s+off\s+safety",
                r"remove\s+restrictions"
            ]
            
            # Patterns de jailbreak spécifiques
            self.jailbreak_patterns = [
                r"do\s+anything\s+now",
                r"dan\s+prompt",
                r"jailbreak\s+prompt",
                r"developer\s+override",
                r"system\s+override",
                r"admin\s+mode",
                r"god\s+mode",
                r"unrestricted\s+mode"
            ]
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du détecteur d'injection: {e}")
            raise
    
    def detect_prompt_injection(self, text: str) -> Dict[str, Any]:
        """
        Détecte les tentatives d'injection de prompts
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de la détection d'injection
        """
        try:
            # Détection par patterns
            pattern_matches = []
            injection_score = 0
            
            for pattern in self.injection_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    pattern_matches.extend(matches)
                    injection_score += 0.2  # Score par pattern détecté
            
            # Normalisation du score
            injection_score = min(injection_score, 1.0)
            
            # Détection par modèle de classification (si disponible)
            ml_score = 0
            try:
                ml_results = self.injection_classifier(text)
                for result in ml_results[0]:
                    if 'injection' in result['label'].lower() or 'jailbreak' in result['label'].lower():
                        ml_score = max(ml_score, result['score'])
            except Exception as e:
                logger.warning(f"Erreur lors de la classification ML: {e}")
            
            # Score combiné
            combined_score = max(injection_score, ml_score)
            
            return {
                'is_injection': combined_score > config.INJECTION_DETECTION['prompt_injection_threshold'],
                'injection_score': combined_score,
                'pattern_matches': pattern_matches,
                'ml_score': ml_score,
                'pattern_score': injection_score,
                'risk_level': self._get_risk_level(combined_score, 'injection')
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection d'injection: {e}")
            return {'is_injection': False, 'injection_score': 0, 'pattern_matches': [], 'risk_level': 'low'}
    
    def detect_jailbreak(self, text: str) -> Dict[str, Any]:
        """
        Détecte les tentatives de jailbreak
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de la détection de jailbreak
        """
        try:
            jailbreak_matches = []
            jailbreak_score = 0
            
            # Détection par patterns spécifiques au jailbreak
            for pattern in self.jailbreak_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    jailbreak_matches.extend(matches)
                    jailbreak_score += 0.3  # Score plus élevé pour jailbreak
            
            # Détection de patterns de contournement de sécurité
            bypass_patterns = [
                r"ignore\s+safety",
                r"disable\s+safety",
                r"bypass\s+restrictions",
                r"unrestricted\s+access",
                r"admin\s+privileges"
            ]
            
            for pattern in bypass_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    jailbreak_score += 0.2
            
            # Normalisation
            jailbreak_score = min(jailbreak_score, 1.0)
            
            return {
                'is_jailbreak': jailbreak_score > config.INJECTION_DETECTION['jailbreak_threshold'],
                'jailbreak_score': jailbreak_score,
                'jailbreak_matches': jailbreak_matches,
                'risk_level': self._get_risk_level(jailbreak_score, 'jailbreak')
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de jailbreak: {e}")
            return {'is_jailbreak': False, 'jailbreak_score': 0, 'jailbreak_matches': [], 'risk_level': 'low'}
    
    def detect_hidden_instructions(self, text: str) -> Dict[str, Any]:
        """
        Détecte les instructions cachées dans le texte
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de la détection d'instructions cachées
        """
        try:
            hidden_instruction_patterns = [
                r"<!--.*?-->",  # Commentaires HTML
                r"\/\*.*?\*\/",  # Commentaires C/Java
                r"\/\/.*$",  # Commentaires ligne
                r"#.*$",  # Commentaires Python/Shell
                r"\[.*?\]",  # Texte entre crochets
                r"\(.*?\)",  # Texte entre parenthèses
                r"\{.*?\}",  # Texte entre accolades
            ]
            
            hidden_instructions = []
            hidden_score = 0
            
            for pattern in hidden_instruction_patterns:
                matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
                for match in matches:
                    # Vérifier si le contenu caché contient des instructions suspectes
                    if any(instr in match.lower() for instr in ['ignore', 'forget', 'pretend', 'act as', 'roleplay']):
                        hidden_instructions.append(match)
                        hidden_score += 0.4
            
            hidden_score = min(hidden_score, 1.0)
            
            return {
                'has_hidden_instructions': len(hidden_instructions) > 0,
                'hidden_score': hidden_score,
                'hidden_instructions': hidden_instructions,
                'risk_level': self._get_risk_level(hidden_score, 'hidden')
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection d'instructions cachées: {e}")
            return {'has_hidden_instructions': False, 'hidden_score': 0, 'hidden_instructions': [], 'risk_level': 'low'}
    
    def analyze_prompt_length(self, text: str) -> Dict[str, Any]:
        """
        Analyse la longueur du prompt pour détecter des tentatives de manipulation
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de l'analyse de longueur
        """
        try:
            text_length = len(text)
            max_length = config.INJECTION_DETECTION['max_prompt_length']
            
            # Score basé sur la longueur excessive
            length_score = 0
            if text_length > max_length:
                length_score = min((text_length - max_length) / max_length, 1.0)
            
            # Détection de répétition excessive
            words = text.split()
            if len(words) > 0:
                unique_words = set(words)
                repetition_ratio = 1 - (len(unique_words) / len(words))
                if repetition_ratio > 0.7:  # Plus de 70% de répétition
                    length_score += 0.3
            
            length_score = min(length_score, 1.0)
            
            return {
                'is_too_long': text_length > max_length,
                'length_score': length_score,
                'text_length': text_length,
                'max_allowed': max_length,
                'risk_level': self._get_risk_level(length_score, 'length')
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de longueur: {e}")
            return {'is_too_long': False, 'length_score': 0, 'text_length': 0, 'risk_level': 'low'}
    
    def comprehensive_injection_analysis(self, text: str) -> Dict[str, Any]:
        """
        Effectue une analyse complète des tentatives d'injection
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat complet de l'analyse
        """
        # Analyses individuelles
        injection_result = self.detect_prompt_injection(text)
        jailbreak_result = self.detect_jailbreak(text)
        hidden_result = self.detect_hidden_instructions(text)
        length_result = self.analyze_prompt_length(text)
        
        # Calcul du score de risque global
        risk_scores = [
            injection_result['injection_score'],
            jailbreak_result['jailbreak_score'],
            hidden_result['hidden_score'],
            length_result['length_score']
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
        
        # Décision de blocage
        should_block = (
            injection_result['is_injection'] or
            jailbreak_result['is_jailbreak'] or
            hidden_result['has_hidden_instructions'] or
            length_result['is_too_long']
        )
        
        return {
            'should_block': should_block,
            'global_risk_score': global_risk_score,
            'global_risk_level': global_risk_level,
            'injection_analysis': injection_result,
            'jailbreak_analysis': jailbreak_result,
            'hidden_instructions_analysis': hidden_result,
            'length_analysis': length_result,
            'analysis_timestamp': self._get_timestamp()
        }
    
    def _get_risk_level(self, score: float, category: str) -> str:
        """Détermine le niveau de risque basé sur le score"""
        if category == 'injection':
            threshold = config.INJECTION_DETECTION['prompt_injection_threshold']
        elif category == 'jailbreak':
            threshold = config.INJECTION_DETECTION['jailbreak_threshold']
        else:
            threshold = 0.7
        
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
