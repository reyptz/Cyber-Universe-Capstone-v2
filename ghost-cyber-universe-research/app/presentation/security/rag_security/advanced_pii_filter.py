"""
Filtrage PII avancé avec ML et conformité RGPD
Détection et anonymisation intelligente des données personnelles
"""

import re
import logging
import hashlib
import json
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest
import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from ..config import config

logger = logging.getLogger(__name__)

class AdvancedPIIFilter:
    """Filtre PII avancé avec ML et conformité RGPD"""
    
    def __init__(self):
        """Initialise le filtre PII avancé"""
        try:
            # Configuration du moteur NLP
            provider = NlpEngineProvider(conf_file=None)
            nlp_engine = provider.create_engine()
            
            self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
            self.anonymizer = AnonymizerEngine()
            
            # Modèles ML pour la détection avancée
            self._initialize_ml_models()
            
            # Cache de conformité RGPD
            self.compliance_cache = {}
            
            # Patterns de détection avancés
            self._initialize_detection_patterns()
            
            logger.info("Filtre PII avancé initialisé avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du filtre PII avancé: {e}")
            raise
    
    def _initialize_ml_models(self):
        """Initialise les modèles ML pour la détection PII"""
        try:
            # Vectoriseur TF-IDF pour la détection de patterns
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=1000,
                ngram_range=(1, 3),
                stop_words='english'
            )
            
            # Modèle d'isolation pour détecter les anomalies PII
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            
            # Modèle spaCy pour l'analyse linguistique
            try:
                self.nlp = spacy.load("fr_core_news_sm")
            except OSError:
                logger.warning("Modèle français non trouvé, utilisation du modèle anglais")
                self.nlp = spacy.load("en_core_web_sm")
            
            # Entraînement initial du modèle d'anomalie
            self._train_anomaly_detector()
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation des modèles ML: {e}")
            raise
    
    def _initialize_detection_patterns(self):
        """Initialise les patterns de détection avancés"""
        self.advanced_patterns = {
            # Patterns de numéros de sécurité sociale
            'ssn_patterns': [
                r'\b\d{3}-\d{2}-\d{4}\b',  # Format standard US
                r'\b\d{3}\s\d{2}\s\d{4}\b',  # Format avec espaces
                r'\b\d{9}\b'  # Format compact
            ],
            
            # Patterns de cartes de crédit
            'credit_card_patterns': [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Format standard
                r'\b\d{13,19}\b'  # Format numérique
            ],
            
            # Patterns de numéros de téléphone
            'phone_patterns': [
                r'\b\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
                r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'
            ],
            
            # Patterns d'emails
            'email_patterns': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ],
            
            # Patterns d'adresses IP
            'ip_patterns': [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'  # IPv6
            ],
            
            # Patterns de mots de passe
            'password_patterns': [
                r'\bpassword\s*[:=]\s*["\']?[^"\'\s]+["\']?',
                r'\bpwd\s*[:=]\s*["\']?[^"\'\s]+["\']?',
                r'\bpass\s*[:=]\s*["\']?[^"\'\s]+["\']?'
            ],
            
            # Patterns de tokens API
            'api_token_patterns': [
                r'\b[A-Za-z0-9]{32,}\b',  # Tokens génériques
                r'\bghp_[A-Za-z0-9]{36}\b',  # GitHub tokens
                r'\bgho_[A-Za-z0-9]{36}\b',  # GitHub OAuth
                r'\bghu_[A-Za-z0-9]{36}\b',  # GitHub user tokens
                r'\bghs_[A-Za-z0-9]{36}\b',  # GitHub server tokens
                r'\bghr_[A-Za-z0-9]{36}\b'   # GitHub refresh tokens
            ]
        }
    
    def _train_anomaly_detector(self):
        """Entraîne le détecteur d'anomalies sur des données de référence"""
        try:
            # Données d'entraînement synthétiques
            training_data = [
                "John Doe, 123 Main St, New York, NY 10001",
                "Jane Smith, 456 Oak Ave, Los Angeles, CA 90210",
                "Bob Johnson, 789 Pine Rd, Chicago, IL 60601",
                "Alice Brown, 321 Elm St, Houston, TX 77001",
                "Charlie Wilson, 654 Maple Dr, Phoenix, AZ 85001"
            ]
            
            # Vectorisation des données d'entraînement
            if training_data:
                X = self.tfidf_vectorizer.fit_transform(training_data)
                self.anomaly_detector.fit(X)
                logger.info("Détecteur d'anomalies entraîné avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement du détecteur d'anomalies: {e}")
    
    def comprehensive_pii_detection(self, text: str) -> Dict[str, Any]:
        """
        Détection PII complète avec ML et patterns avancés
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat complet de la détection PII
        """
        try:
            # Détection Presidio standard
            presidio_results = self.analyzer.analyze(
                text=text,
                entities=config.PII_ENTITIES,
                language='fr'
            )
            
            # Détection par patterns avancés
            pattern_results = self._detect_with_advanced_patterns(text)
            
            # Détection par ML
            ml_results = self._detect_with_ml(text)
            
            # Détection de contexte sémantique
            semantic_results = self._detect_semantic_pii(text)
            
            # Fusion des résultats
            all_entities = []
            
            # Ajout des résultats Presidio
            for result in presidio_results:
                all_entities.append({
                    'entity_type': result.entity_type,
                    'start': result.start,
                    'end': result.end,
                    'score': result.score,
                    'text': text[result.start:result.end],
                    'detection_method': 'presidio'
                })
            
            # Ajout des résultats de patterns
            all_entities.extend(pattern_results)
            
            # Ajout des résultats ML
            all_entities.extend(ml_results)
            
            # Ajout des résultats sémantiques
            all_entities.extend(semantic_results)
            
            # Déduplication des entités
            deduplicated_entities = self._deduplicate_entities(all_entities)
            
            # Calcul du score de risque
            risk_score = self._calculate_pii_risk_score(deduplicated_entities)
            
            # Vérification de conformité RGPD
            gdpr_compliance = self._check_gdpr_compliance(deduplicated_entities)
            
            return {
                'entities_found': deduplicated_entities,
                'total_entities': len(deduplicated_entities),
                'risk_score': risk_score,
                'gdpr_compliance': gdpr_compliance,
                'detection_timestamp': datetime.utcnow().isoformat(),
                'requires_consent': gdpr_compliance['requires_consent'],
                'data_categories': self._categorize_pii_data(deduplicated_entities)
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection PII complète: {e}")
            return {
                'entities_found': [],
                'total_entities': 0,
                'risk_score': 0.0,
                'error': str(e)
            }
    
    def _detect_with_advanced_patterns(self, text: str) -> List[Dict[str, Any]]:
        """Détection par patterns avancés"""
        entities = []
        
        for category, patterns in self.advanced_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    entities.append({
                        'entity_type': category.replace('_patterns', '').upper(),
                        'start': match.start(),
                        'end': match.end(),
                        'score': 0.9,  # Score élevé pour les patterns
                        'text': match.group(),
                        'detection_method': 'advanced_pattern',
                        'pattern_used': pattern
                    })
        
        return entities
    
    def _detect_with_ml(self, text: str) -> List[Dict[str, Any]]:
        """Détection par modèles ML"""
        entities = []
        
        try:
            # Vectorisation du texte
            text_vector = self.tfidf_vectorizer.transform([text])
            
            # Détection d'anomalie
            anomaly_score = self.anomaly_detector.decision_function(text_vector)[0]
            
            if anomaly_score < -0.5:  # Seuil d'anomalie
                # Analyse linguistique avec spaCy
                doc = self.nlp(text)
                
                for ent in doc.ents:
                    if ent.label_ in ['PERSON', 'ORG', 'GPE', 'MONEY', 'DATE']:
                        entities.append({
                            'entity_type': ent.label_,
                            'start': ent.start_char,
                            'end': ent.end_char,
                            'score': abs(anomaly_score),
                            'text': ent.text,
                            'detection_method': 'ml_anomaly',
                            'anomaly_score': anomaly_score
                        })
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection ML: {e}")
        
        return entities
    
    def _detect_semantic_pii(self, text: str) -> List[Dict[str, Any]]:
        """Détection sémantique de PII"""
        entities = []
        
        try:
            # Analyse sémantique avec spaCy
            doc = self.nlp(text)
            
            # Patterns sémantiques pour détecter des informations sensibles
            semantic_patterns = [
                (r'\b(?:mon|ma|mes)\s+(?:nom|prénom|adresse|téléphone|email)\b', 'PERSONAL_INFO'),
                (r'\b(?:mon|ma|mes)\s+(?:compte|mot de passe|identifiant)\b', 'CREDENTIALS'),
                (r'\b(?:numéro|code)\s+(?:de sécurité|de carte|de compte)\b', 'IDENTIFIER'),
                (r'\b(?:date|année)\s+(?:de naissance|de mariage)\b', 'DATE_PERSONAL')
            ]
            
            for pattern, entity_type in semantic_patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    entities.append({
                        'entity_type': entity_type,
                        'start': match.start(),
                        'end': match.end(),
                        'score': 0.8,
                        'text': match.group(),
                        'detection_method': 'semantic',
                        'pattern_used': pattern
                    })
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection sémantique: {e}")
        
        return entities
    
    def _deduplicate_entities(self, entities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Déduplique les entités détectées"""
        deduplicated = []
        seen_positions = set()
        
        for entity in entities:
            position_key = (entity['start'], entity['end'])
            if position_key not in seen_positions:
                deduplicated.append(entity)
                seen_positions.add(position_key)
        
        return deduplicated
    
    def _calculate_pii_risk_score(self, entities: List[Dict[str, Any]]) -> float:
        """Calcule le score de risque PII"""
        if not entities:
            return 0.0
        
        # Poids par type d'entité
        entity_weights = {
            'PERSON': 0.3,
            'EMAIL_ADDRESS': 0.4,
            'PHONE_NUMBER': 0.3,
            'CREDIT_CARD': 0.9,
            'IBAN_CODE': 0.8,
            'IP_ADDRESS': 0.5,
            'US_SSN': 0.9,
            'API_TOKEN': 0.8,
            'PASSWORD': 0.9
        }
        
        total_score = 0.0
        for entity in entities:
            entity_type = entity['entity_type']
            weight = entity_weights.get(entity_type, 0.2)
            score = entity['score'] * weight
            total_score += score
        
        # Normalisation
        return min(total_score / len(entities), 1.0)
    
    def _check_gdpr_compliance(self, entities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Vérifie la conformité RGPD"""
        if not entities:
            return {
                'is_compliant': True,
                'requires_consent': False,
                'data_categories': [],
                'retention_period': None
            }
        
        # Catégorisation des données selon RGPD
        data_categories = []
        for entity in entities:
            entity_type = entity['entity_type']
            
            if entity_type in ['PERSON', 'EMAIL_ADDRESS', 'PHONE_NUMBER']:
                data_categories.append('personal_data')
            elif entity_type in ['CREDIT_CARD', 'IBAN_CODE']:
                data_categories.append('financial_data')
            elif entity_type in ['US_SSN', 'API_TOKEN', 'PASSWORD']:
                data_categories.append('sensitive_data')
        
        # Détermination de la conformité
        requires_consent = len(data_categories) > 0
        is_compliant = not requires_consent or config.PRIVACY_RULES['require_consent']
        
        return {
            'is_compliant': is_compliant,
            'requires_consent': requires_consent,
            'data_categories': list(set(data_categories)),
            'retention_period': config.PRIVACY_RULES['max_retention_days']
        }
    
    def _categorize_pii_data(self, entities: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Catégorise les données PII selon RGPD"""
        categories = {
            'personal_data': [],
            'financial_data': [],
            'sensitive_data': [],
            'technical_data': []
        }
        
        for entity in entities:
            entity_type = entity['entity_type']
            text = entity['text']
            
            if entity_type in ['PERSON', 'EMAIL_ADDRESS', 'PHONE_NUMBER']:
                categories['personal_data'].append(text)
            elif entity_type in ['CREDIT_CARD', 'IBAN_CODE']:
                categories['financial_data'].append(text)
            elif entity_type in ['US_SSN', 'API_TOKEN', 'PASSWORD']:
                categories['sensitive_data'].append(text)
            else:
                categories['technical_data'].append(text)
        
        return categories
    
    def advanced_anonymization(self, text: str, anonymization_strategy: str = "standard") -> Dict[str, Any]:
        """
        Anonymisation avancée avec différentes stratégies
        
        Args:
            text: Texte à anonymiser
            anonymization_strategy: Stratégie d'anonymisation (standard, aggressive, gdpr)
            
        Returns:
            Résultat de l'anonymisation
        """
        try:
            # Détection PII complète
            detection_result = self.comprehensive_pii_detection(text)
            
            if not detection_result['entities_found']:
                return {
                    'anonymized_text': text,
                    'original_text': text,
                    'entities_removed': 0,
                    'anonymization_applied': False
                }
            
            # Configuration des opérateurs selon la stratégie
            operators = self._get_anonymization_operators(anonymization_strategy)
            
            # Anonymisation avec Presidio
            presidio_results = self.analyzer.analyze(
                text=text,
                entities=config.PII_ENTITIES,
                language='fr'
            )
            
            anonymized_result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=presidio_results,
                operators=operators
            )
            
            # Anonymisation supplémentaire pour les patterns avancés
            final_text = self._apply_advanced_anonymization(
                anonymized_result.text,
                detection_result['entities_found']
            )
            
            return {
                'anonymized_text': final_text,
                'original_text': text,
                'entities_removed': len(detection_result['entities_found']),
                'anonymization_applied': True,
                'strategy_used': anonymization_strategy,
                'gdpr_compliant': detection_result['gdpr_compliance']['is_compliant']
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'anonymisation avancée: {e}")
            return {
                'anonymized_text': text,
                'original_text': text,
                'entities_removed': 0,
                'anonymization_applied': False,
                'error': str(e)
            }
    
    def _get_anonymization_operators(self, strategy: str) -> Dict[str, Dict]:
        """Retourne les opérateurs d'anonymisation selon la stratégie"""
        if strategy == "aggressive":
            return {
                "PERSON": {"type": "replace", "new_value": "[PERSONNE]"},
                "EMAIL_ADDRESS": {"type": "replace", "new_value": "[EMAIL]"},
                "PHONE_NUMBER": {"type": "replace", "new_value": "[TÉLÉPHONE]"},
                "CREDIT_CARD": {"type": "replace", "new_value": "[CARTE_CRÉDIT]"},
                "IBAN_CODE": {"type": "replace", "new_value": "[IBAN]"},
                "IP_ADDRESS": {"type": "replace", "new_value": "[IP]"},
                "LOCATION": {"type": "replace", "new_value": "[LIEU]"},
                "DATE_TIME": {"type": "replace", "new_value": "[DATE]"},
                "US_SSN": {"type": "replace", "new_value": "[SSN]"},
                "API_TOKEN": {"type": "replace", "new_value": "[TOKEN]"},
                "PASSWORD": {"type": "replace", "new_value": "[MOT_DE_PASSE]"}
            }
        elif strategy == "gdpr":
            return {
                "PERSON": {"type": "replace", "new_value": "[PERSONNE_RGPD]"},
                "EMAIL_ADDRESS": {"type": "replace", "new_value": "[EMAIL_RGPD]"},
                "PHONE_NUMBER": {"type": "replace", "new_value": "[TÉLÉPHONE_RGPD]"},
                "CREDIT_CARD": {"type": "replace", "new_value": "[CARTE_CRÉDIT_RGPD]"},
                "IBAN_CODE": {"type": "replace", "new_value": "[IBAN_RGPD]"},
                "IP_ADDRESS": {"type": "replace", "new_value": "[IP_RGPD]"},
                "LOCATION": {"type": "replace", "new_value": "[LIEU_RGPD]"},
                "DATE_TIME": {"type": "replace", "new_value": "[DATE_RGPD]"},
                "US_SSN": {"type": "replace", "new_value": "[SSN_RGPD]"},
                "API_TOKEN": {"type": "replace", "new_value": "[TOKEN_RGPD]"},
                "PASSWORD": {"type": "replace", "new_value": "[MOT_DE_PASSE_RGPD]"}
            }
        else:  # standard
            return {
                "PERSON": {"type": "replace", "new_value": "[PERSONNE]"},
                "EMAIL_ADDRESS": {"type": "replace", "new_value": "[EMAIL]"},
                "PHONE_NUMBER": {"type": "replace", "new_value": "[TÉLÉPHONE]"},
                "CREDIT_CARD": {"type": "replace", "new_value": "[CARTE_CRÉDIT]"},
                "IBAN_CODE": {"type": "replace", "new_value": "[IBAN]"},
                "IP_ADDRESS": {"type": "replace", "new_value": "[IP]"},
                "LOCATION": {"type": "replace", "new_value": "[LIEU]"},
                "DATE_TIME": {"type": "replace", "new_value": "[DATE]"},
                "US_SSN": {"type": "replace", "new_value": "[SSN]"},
                "API_TOKEN": {"type": "replace", "new_value": "[TOKEN]"},
                "PASSWORD": {"type": "replace", "new_value": "[MOT_DE_PASSE]"}
            }
    
    def _apply_advanced_anonymization(self, text: str, entities: List[Dict[str, Any]]) -> str:
        """Applique l'anonymisation avancée pour les patterns détectés"""
        anonymized_text = text
        
        for entity in entities:
            if entity['detection_method'] in ['advanced_pattern', 'ml_anomaly', 'semantic']:
                # Remplacement par placeholder approprié
                placeholder = f"[{entity['entity_type']}]"
                anonymized_text = anonymized_text.replace(entity['text'], placeholder)
        
        return anonymized_text
    
    def generate_privacy_report(self, text: str) -> Dict[str, Any]:
        """Génère un rapport de confidentialité complet"""
        try:
            # Détection PII complète
            detection_result = self.comprehensive_pii_detection(text)
            
            # Calcul des métriques
            total_entities = detection_result['total_entities']
            risk_score = detection_result['risk_score']
            gdpr_compliance = detection_result['gdpr_compliance']
            
            # Recommandations
            recommendations = []
            if risk_score > 0.7:
                recommendations.append("Risque élevé de fuite de données - Anonymisation recommandée")
            if gdpr_compliance['requires_consent']:
                recommendations.append("Consentement utilisateur requis")
            if total_entities > 5:
                recommendations.append("Nombre élevé d'entités PII détectées - Révision recommandée")
            
            return {
                'privacy_score': 1.0 - risk_score,
                'gdpr_compliance': gdpr_compliance,
                'entities_summary': {
                    'total_entities': total_entities,
                    'risk_score': risk_score,
                    'data_categories': detection_result['data_categories']
                },
                'recommendations': recommendations,
                'report_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport de confidentialité: {e}")
            return {'error': str(e)}
