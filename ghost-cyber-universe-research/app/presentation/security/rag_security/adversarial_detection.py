"""
Module de détection adversarial et de mise en quarantaine
"""
import logging
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
from datetime import datetime, timedelta
from ..config import config

logger = logging.getLogger(__name__)

class AdversarialDetector:
    """Détecteur de réponses adversariales et de contenu à risque"""
    
    def __init__(self):
        """Initialise le détecteur adversarial"""
        try:
            # Modèle de perplexité pour détecter les réponses anormales
            self.perplexity_model = pipeline(
                "text-generation",
                model="gpt2",
                return_full_text=False
            )
            
            # Modèle de détection de toxicité
            self.toxicity_classifier = pipeline(
                "text-classification",
                model="unitary/toxic-bert",
                return_all_scores=True
            )
            
            # Modèle de détection de fuite d'informations
            self.leakage_classifier = pipeline(
                "text-classification",
                model="microsoft/DialoGPT-medium",
                return_all_scores=True
            )
            
            # Registre de quarantaine
            self.quarantine_registry = {}
            
            # Indicateurs de fuite d'informations
            self.leakage_indicators = config.ADVERSARIAL_DETECTION['leakage_indicators']
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du détecteur adversarial: {e}")
            raise
    
    def calculate_perplexity(self, text: str) -> float:
        """
        Calcule la perplexité du texte
        
        Args:
            text: Texte à analyser
            
        Returns:
            Score de perplexité
        """
        try:
            # Tokenisation
            tokenizer = AutoTokenizer.from_pretrained("gpt2")
            model = AutoModelForSequenceClassification.from_pretrained("gpt2")
            
            inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            
            with torch.no_grad():
                outputs = model(**inputs)
                logits = outputs.logits
                
                # Calcul de la perplexité
                perplexity = torch.exp(torch.mean(-logits))
                return float(perplexity)
                
        except Exception as e:
            logger.error(f"Erreur lors du calcul de perplexité: {e}")
            return 0.0
    
    def detect_toxic_content(self, text: str) -> Dict[str, Any]:
        """
        Détecte le contenu toxique
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de la détection de toxicité
        """
        try:
            results = self.toxicity_classifier(text)
            
            # Calcul du score de toxicité global
            toxicity_score = 0
            toxic_labels = []
            
            for result in results[0]:
                if result['label'] in ['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate']:
                    toxicity_score = max(toxicity_score, result['score'])
                    toxic_labels.append(result['label'])
            
            return {
                'is_toxic': toxicity_score > config.ADVERSARIAL_DETECTION['toxicity_threshold'],
                'toxicity_score': toxicity_score,
                'toxic_labels': toxic_labels,
                'risk_level': self._get_risk_level(toxicity_score, 'toxicity')
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de toxicité: {e}")
            return {'is_toxic': False, 'toxicity_score': 0, 'toxic_labels': [], 'risk_level': 'low'}
    
    def detect_information_leakage(self, text: str) -> Dict[str, Any]:
        """
        Détecte les fuites d'informations
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de la détection de fuite
        """
        try:
            leakage_score = 0
            detected_indicators = []
            
            # Détection par mots-clés
            text_lower = text.lower()
            for indicator in self.leakage_indicators:
                if indicator.lower() in text_lower:
                    detected_indicators.append(indicator)
                    leakage_score += 0.2
            
            # Détection par patterns spécifiques
            leakage_patterns = [
                r"internal\s+document",
                r"confidential\s+information",
                r"proprietary\s+data",
                r"restricted\s+access",
                r"classified\s+material",
                r"trade\s+secret",
                r"source\s+code",
                r"database\s+password",
                r"api\s+key",
                r"private\s+key"
            ]
            
            import re
            for pattern in leakage_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    leakage_score += 0.3
            
            # Normalisation du score
            leakage_score = min(leakage_score, 1.0)
            
            return {
                'has_leakage': leakage_score > 0.5,
                'leakage_score': leakage_score,
                'detected_indicators': detected_indicators,
                'risk_level': self._get_risk_level(leakage_score, 'leakage')
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de fuite: {e}")
            return {'has_leakage': False, 'leakage_score': 0, 'detected_indicators': [], 'risk_level': 'low'}
    
    def detect_adversarial_patterns(self, text: str) -> Dict[str, Any]:
        """
        Détecte les patterns adversariales
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de la détection de patterns adversariales
        """
        try:
            adversarial_patterns = [
                r"ignore\s+previous",
                r"forget\s+everything",
                r"you\s+are\s+now",
                r"pretend\s+to\s+be",
                r"act\s+as\s+if",
                r"roleplay\s+as",
                r"jailbreak",
                r"dan\s+mode",
                r"developer\s+mode",
                r"system\s+prompt",
                r"override\s+safety",
                r"bypass\s+restrictions"
            ]
            
            import re
            detected_patterns = []
            adversarial_score = 0
            
            for pattern in adversarial_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    detected_patterns.extend(matches)
                    adversarial_score += 0.2
            
            adversarial_score = min(adversarial_score, 1.0)
            
            return {
                'is_adversarial': adversarial_score > 0.6,
                'adversarial_score': adversarial_score,
                'detected_patterns': detected_patterns,
                'risk_level': self._get_risk_level(adversarial_score, 'adversarial')
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de patterns adversariales: {e}")
            return {'is_adversarial': False, 'adversarial_score': 0, 'detected_patterns': [], 'risk_level': 'low'}
    
    def comprehensive_adversarial_analysis(self, text: str) -> Dict[str, Any]:
        """
        Effectue une analyse complète adversarial
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat complet de l'analyse adversarial
        """
        try:
            # Calcul de la perplexité
            perplexity = self.calculate_perplexity(text)
            
            # Détection de toxicité
            toxicity_result = self.detect_toxic_content(text)
            
            # Détection de fuite d'informations
            leakage_result = self.detect_information_leakage(text)
            
            # Détection de patterns adversariales
            adversarial_result = self.detect_adversarial_patterns(text)
            
            # Calcul du score de risque global
            risk_scores = [
                toxicity_result['toxicity_score'],
                leakage_result['leakage_score'],
                adversarial_result['adversarial_score']
            ]
            
            # Ajout de la perplexité au calcul de risque
            perplexity_risk = 1.0 if perplexity > config.ADVERSARIAL_DETECTION['perplexity_threshold'] else 0.0
            risk_scores.append(perplexity_risk)
            
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
            
            # Décision de mise en quarantaine
            should_quarantine = global_risk_score > config.ADVERSARIAL_DETECTION['quarantine_threshold']
            
            return {
                'should_quarantine': should_quarantine,
                'global_risk_score': global_risk_score,
                'global_risk_level': global_risk_level,
                'perplexity': perplexity,
                'toxicity_analysis': toxicity_result,
                'leakage_analysis': leakage_result,
                'adversarial_analysis': adversarial_result,
                'analysis_timestamp': self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse adversarial complète: {e}")
            return {
                'should_quarantine': True,  # En cas d'erreur, mettre en quarantaine par sécurité
                'global_risk_score': 1.0,
                'global_risk_level': 'critical',
                'error': str(e)
            }
    
    def quarantine_content(self, content_id: str, content: str, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Met du contenu en quarantaine
        
        Args:
            content_id: Identifiant unique du contenu
            content: Contenu à mettre en quarantaine
            analysis_result: Résultat de l'analyse adversarial
            
        Returns:
            Résultat de la mise en quarantaine
        """
        try:
            quarantine_entry = {
                'content_id': content_id,
                'content': content,
                'analysis_result': analysis_result,
                'quarantine_timestamp': self._get_timestamp(),
                'quarantine_duration': timedelta(hours=24),  # 24 heures par défaut
                'status': 'quarantined',
                'requires_human_review': analysis_result['global_risk_level'] in ['high', 'critical']
            }
            
            # Ajout au registre de quarantaine
            self.quarantine_registry[content_id] = quarantine_entry
            
            logger.warning(f"Contenu mis en quarantaine: {content_id} - Niveau de risque: {analysis_result['global_risk_level']}")
            
            return {
                'quarantined': True,
                'content_id': content_id,
                'quarantine_timestamp': quarantine_entry['quarantine_timestamp'],
                'requires_human_review': quarantine_entry['requires_human_review'],
                'quarantine_duration': str(quarantine_entry['quarantine_duration'])
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise en quarantaine: {e}")
            return {'quarantined': False, 'error': str(e)}
    
    def release_from_quarantine(self, content_id: str, human_approval: bool = False) -> Dict[str, Any]:
        """
        Libère du contenu de la quarantaine
        
        Args:
            content_id: Identifiant du contenu
            human_approval: Approbation humaine
            
        Returns:
            Résultat de la libération
        """
        try:
            if content_id not in self.quarantine_registry:
                return {'released': False, 'error': 'Contenu non trouvé en quarantaine'}
            
            quarantine_entry = self.quarantine_registry[content_id]
            
            # Vérification de la durée de quarantaine
            quarantine_time = datetime.fromisoformat(quarantine_entry['quarantine_timestamp'])
            current_time = datetime.utcnow()
            
            if current_time - quarantine_time < quarantine_entry['quarantine_duration'] and not human_approval:
                return {
                    'released': False,
                    'reason': 'Durée de quarantaine non écoulée et pas d\'approbation humaine'
                }
            
            # Libération du contenu
            del self.quarantine_registry[content_id]
            
            logger.info(f"Contenu libéré de la quarantaine: {content_id}")
            
            return {
                'released': True,
                'content_id': content_id,
                'release_timestamp': self._get_timestamp(),
                'human_approved': human_approval
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la libération de quarantaine: {e}")
            return {'released': False, 'error': str(e)}
    
    def get_quarantine_status(self) -> Dict[str, Any]:
        """
        Retourne le statut de la quarantaine
        
        Returns:
            Statut de la quarantaine
        """
        try:
            total_quarantined = len(self.quarantine_registry)
            
            # Comptage par niveau de risque
            risk_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            human_review_needed = 0
            
            for entry in self.quarantine_registry.values():
                risk_level = entry['analysis_result']['global_risk_level']
                risk_counts[risk_level] += 1
                
                if entry['requires_human_review']:
                    human_review_needed += 1
            
            return {
                'total_quarantined': total_quarantined,
                'risk_distribution': risk_counts,
                'human_review_needed': human_review_needed,
                'quarantine_timestamp': self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du statut de quarantaine: {e}")
            return {'total_quarantined': 0, 'error': str(e)}
    
    def _get_risk_level(self, score: float, category: str) -> str:
        """Détermine le niveau de risque basé sur le score"""
        if category == 'toxicity':
            threshold = config.ADVERSARIAL_DETECTION['toxicity_threshold']
        elif category == 'leakage':
            threshold = 0.5
        elif category == 'adversarial':
            threshold = 0.6
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
        return datetime.utcnow().isoformat()
