"""
Module de filtrage et anonymisation PII
"""
import re
import logging
from typing import List, Dict, Any, Optional
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
import spacy
from ..config import config

logger = logging.getLogger(__name__)

class PIIFilter:
    """Filtre et anonymise les données PII"""
    
    def __init__(self):
        """Initialise le moteur d'analyse PII"""
        try:
            # Configuration du moteur NLP
            provider = NlpEngineProvider(conf_file=None)
            nlp_engine = provider.create_engine()
            
            self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            self.anonymizer = AnonymizerEngine()
            
            # Chargement du modèle spaCy français
            try:
                spacy.load("fr_core_news_sm")
            except OSError:
                logger.warning("Modèle français non trouvé, utilisation du modèle anglais")
                spacy.load("en_core_web_sm")
                
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du filtre PII: {e}")
            raise
    
    def detect_pii(self, text: str) -> List[Dict[str, Any]]:
        """
        Détecte les entités PII dans le texte
        
        Args:
            text: Texte à analyser
            
        Returns:
            Liste des entités PII détectées
        """
        try:
            results = self.analyzer.analyze(
                text=text,
                entities=config.PII_ENTITIES,
                language='fr'
            )
            
            pii_entities = []
            for result in results:
                pii_entities.append({
                    'entity_type': result.entity_type,
                    'start': result.start,
                    'end': result.end,
                    'score': result.score,
                    'text': text[result.start:result.end]
                })
            
            return pii_entities
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection PII: {e}")
            return []
    
    def anonymize_text(self, text: str, custom_operators: Optional[Dict] = None) -> str:
        """
        Anonymise le texte en remplaçant les entités PII
        
        Args:
            text: Texte à anonymiser
            custom_operators: Opérateurs d'anonymisation personnalisés
            
        Returns:
            Texte anonymisé
        """
        try:
            # Détection des entités PII
            results = self.analyzer.analyze(
                text=text,
                entities=config.PII_ENTITIES,
                language='fr'
            )
            
            # Configuration des opérateurs d'anonymisation
            operators = {
                "PERSON": {"type": "replace", "new_value": "[PERSONNE]"},
                "EMAIL_ADDRESS": {"type": "replace", "new_value": "[EMAIL]"},
                "PHONE_NUMBER": {"type": "replace", "new_value": "[TÉLÉPHONE]"},
                "CREDIT_CARD": {"type": "replace", "new_value": "[CARTE_CRÉDIT]"},
                "IBAN_CODE": {"type": "replace", "new_value": "[IBAN]"},
                "IP_ADDRESS": {"type": "replace", "new_value": "[IP]"},
                "LOCATION": {"type": "replace", "new_value": "[LIEU]"},
                "DATE_TIME": {"type": "replace", "new_value": "[DATE]"},
                "US_SSN": {"type": "replace", "new_value": "[SSN]"},
                "US_PASSPORT": {"type": "replace", "new_value": "[PASSEPORT]"},
                "US_DRIVER_LICENSE": {"type": "replace", "new_value": "[PERMIS]"},
                "MEDICAL_LICENSE": {"type": "replace", "new_value": "[LICENCE_MÉDICALE]"},
                "NRP": {"type": "replace", "new_value": "[NRP]"}
            }
            
            if custom_operators:
                operators.update(custom_operators)
            
            # Anonymisation
            anonymized_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=results,
                operators=operators
            )
            
            return anonymized_result.text
            
        except Exception as e:
            logger.error(f"Erreur lors de l'anonymisation: {e}")
            return text
    
    def check_privacy_compliance(self, text: str) -> Dict[str, Any]:
        """
        Vérifie la conformité aux règles de confidentialité
        
        Args:
            text: Texte à vérifier
            
        Returns:
            Résultat de la vérification de conformité
        """
        pii_entities = self.detect_pii(text)
        
        compliance_result = {
            'is_compliant': len(pii_entities) == 0,
            'pii_count': len(pii_entities),
            'entities_found': pii_entities,
            'risk_level': 'low' if len(pii_entities) == 0 else 'high',
            'requires_consent': len(pii_entities) > 0 and config.PRIVACY_RULES['require_consent']
        }
        
        # Log de l'accès aux PII si configuré
        if config.PRIVACY_RULES['log_pii_access'] and pii_entities:
            logger.warning(f"Accès PII détecté: {len(pii_entities)} entités trouvées")
        
        return compliance_result
    
    def sanitize_for_rag(self, text: str) -> Dict[str, Any]:
        """
        Nettoie le texte pour l'utilisation dans RAG
        
        Args:
            text: Texte à nettoyer
            
        Returns:
            Dictionnaire avec le texte nettoyé et les métadonnées
        """
        # Vérification de conformité
        compliance = self.check_privacy_compliance(text)
        
        # Anonymisation si nécessaire
        if config.PRIVACY_RULES['auto_anonymize'] and not compliance['is_compliant']:
            cleaned_text = self.anonymize_text(text)
        else:
            cleaned_text = text
        
        return {
            'cleaned_text': cleaned_text,
            'original_text': text,
            'compliance': compliance,
            'anonymized': cleaned_text != text
        }
