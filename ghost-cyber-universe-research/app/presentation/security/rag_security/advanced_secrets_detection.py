"""
Détection avancée de fuite de secrets avec ML
Détection et rédaction intelligente des secrets avec apprentissage automatique
"""

import re
import logging
import json
import hashlib
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import spacy
from ..config import config

logger = logging.getLogger(__name__)

class SecretType(Enum):
    """Types de secrets"""
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CREDENTIALS = "credentials"
    PRIVATE_KEY = "private_key"
    DATABASE_URL = "database_url"
    SSH_KEY = "ssh_key"
    CERTIFICATE = "certificate"
    SECRET_KEY = "secret_key"
    ACCESS_TOKEN = "access_token"

class DetectionMethod(Enum):
    """Méthodes de détection"""
    REGEX = "regex"
    ML_MODEL = "ml_model"
    PATTERN_MATCHING = "pattern_matching"
    SEMANTIC_ANALYSIS = "semantic_analysis"
    CONTEXT_ANALYSIS = "context_analysis"

@dataclass
class SecretFinding:
    """Finding de secret détecté"""
    id: str
    secret_type: SecretType
    value: str
    masked_value: str
    start_position: int
    end_position: int
    confidence: float
    detection_method: DetectionMethod
    context: str
    risk_level: str
    created_at: datetime

@dataclass
class SecretDetectionResult:
    """Résultat de détection de secrets"""
    secrets_found: List[SecretFinding]
    total_secrets: int
    risk_score: float
    detection_confidence: float
    processing_time: float
    false_positives: int
    false_negatives: int

class AdvancedSecretsDetector:
    """Détecteur avancé de secrets avec ML"""
    
    def __init__(self):
        """Initialise le détecteur de secrets avancé"""
        try:
            # Base de données de secrets détectés
            self.secret_findings = []
            self.detection_models = {}
            
            # Modèles ML
            self._initialize_ml_models()
            
            # Patterns de détection
            self._initialize_detection_patterns()
            
            # Dataset synthétique
            self._create_synthetic_dataset()
            
            # Modèle spaCy pour l'analyse linguistique
            try:
                self.nlp = spacy.load("fr_core_news_sm")
            except OSError:
                logger.warning("Modèle français non trouvé, utilisation du modèle anglais")
                self.nlp = spacy.load("en_core_web_sm")
            
            logger.info("Détecteur de secrets avancé initialisé")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du détecteur de secrets: {e}")
            raise
    
    def _initialize_ml_models(self):
        """Initialise les modèles ML pour la détection de secrets"""
        try:
            # Vectoriseur TF-IDF
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 4),
                stop_words='english'
            )
            
            # Classificateur pour la détection de secrets
            self.secret_classifier = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                random_state=42
            )
            
            # Détecteur d'anomalies pour les patterns suspects
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            
            # Modèle d'analyse sémantique
            self.semantic_analyzer = self._create_semantic_analyzer()
            
            # Modèle de détection de contexte
            self.context_analyzer = self._create_context_analyzer()
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation des modèles ML: {e}")
            raise
    
    def _initialize_detection_patterns(self):
        """Initialise les patterns de détection de secrets"""
        self.secret_patterns = {
            SecretType.API_KEY: [
                r'api[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'apikey\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'api_key\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?'
            ],
            SecretType.PASSWORD: [
                r'password\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'pwd\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'pass\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'passwd\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
            ],
            SecretType.TOKEN: [
                r'token\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'access_token\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'bearer\s+([A-Za-z0-9_-]{20,})',
                r'auth_token\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?'
            ],
            SecretType.CREDENTIALS: [
                r'credentials\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'auth\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'login\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
            ],
            SecretType.PRIVATE_KEY: [
                r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                r'private_key\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'privkey\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
            ],
            SecretType.DATABASE_URL: [
                r'mysql://[^"\'\s]+',
                r'postgresql://[^"\'\s]+',
                r'mongodb://[^"\'\s]+',
                r'database_url\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
            ],
            SecretType.SSH_KEY: [
                r'-----BEGIN\s+(?:RSA\s+)?SSH\s+PRIVATE\s+KEY-----',
                r'ssh_key\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'ssh_private_key\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
            ],
            SecretType.CERTIFICATE: [
                r'-----BEGIN\s+CERTIFICATE-----',
                r'certificate\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'ssl_cert\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
            ],
            SecretType.SECRET_KEY: [
                r'secret_key\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'secret\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'jwt_secret\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?'
            ],
            SecretType.ACCESS_TOKEN: [
                r'access_token\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'oauth_token\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?',
                r'bearer_token\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})["\']?'
            ]
        }
        
        # Patterns génériques pour les secrets
        self.generic_patterns = [
            r'[A-Za-z0-9_-]{32,}',  # Tokens génériques
            r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64
            r'[A-Fa-f0-9]{64,}',  # Hex
            r'[A-Za-z0-9_-]{20,}@[A-Za-z0-9_-]{20,}'  # Email-like tokens
        ]
    
    def _create_synthetic_dataset(self):
        """Crée un dataset synthétique pour l'entraînement"""
        self.synthetic_secrets = {
            'api_keys': [
                'sk-1234567890abcdef1234567890abcdef',
                'ak_test_1234567890abcdef1234567890',
                'api_key_1234567890abcdef1234567890'
            ],
            'passwords': [
                'password123',
                'admin123',
                'secretpassword',
                'mypassword123'
            ],
            'tokens': [
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
                'ghp_1234567890abcdef1234567890abcdef',
                'xoxb-1234567890-1234567890-1234567890'
            ],
            'private_keys': [
                '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...',
                '-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...'
            ]
        }
        
        # Création du dataset d'entraînement
        self.training_data = []
        self.training_labels = []
        
        # Ajout des secrets positifs
        for secret_type, secrets in self.synthetic_secrets.items():
            for secret in secrets:
                self.training_data.append(secret)
                self.training_labels.append(1)
        
        # Ajout d'exemples négatifs
        negative_examples = [
            'This is a normal text without secrets.',
            'The API endpoint is /api/v1/users',
            'Configuration file: config.json',
            'Database connection established',
            'User authentication successful'
        ]
        
        for example in negative_examples:
            self.training_data.append(example)
            self.training_labels.append(0)
    
    def _create_semantic_analyzer(self):
        """Crée l'analyseur sémantique"""
        def analyze_semantics(text: str) -> Dict[str, Any]:
            try:
                # Analyse avec spaCy
                doc = self.nlp(text)
                
                # Détection de mots-clés liés aux secrets
                secret_keywords = [
                    'password', 'secret', 'key', 'token', 'credential',
                    'auth', 'login', 'private', 'confidential', 'sensitive'
                ]
                
                keyword_count = 0
                for token in doc:
                    if token.lemma_.lower() in secret_keywords:
                        keyword_count += 1
                
                # Score sémantique basé sur les mots-clés
                semantic_score = keyword_count / len(doc) if len(doc) > 0 else 0
                
                # Détection de patterns sémantiques suspects
                suspicious_patterns = [
                    r'my\s+(?:password|secret|key)',
                    r'here\s+is\s+(?:my|the)\s+(?:password|secret|key)',
                    r'password\s+is\s+',
                    r'secret\s+is\s+',
                    r'key\s+is\s+'
                ]
                
                pattern_matches = 0
                for pattern in suspicious_patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        pattern_matches += 1
                
                return {
                    'semantic_score': semantic_score,
                    'keyword_count': keyword_count,
                    'pattern_matches': pattern_matches,
                    'is_suspicious': semantic_score > 0.1 or pattern_matches > 0
                }
                
            except Exception as e:
                logger.error(f"Erreur dans l'analyse sémantique: {e}")
                return {
                    'semantic_score': 0.0,
                    'keyword_count': 0,
                    'pattern_matches': 0,
                    'is_suspicious': False
                }
        
        return analyze_semantics
    
    def _create_context_analyzer(self):
        """Crée l'analyseur de contexte"""
        def analyze_context(text: str, position: int) -> Dict[str, Any]:
            try:
                # Extraction du contexte autour de la position
                context_start = max(0, position - 50)
                context_end = min(len(text), position + 50)
                context = text[context_start:context_end]
                
                # Analyse du contexte
                context_analysis = {
                    'surrounding_text': context,
                    'has_equals_sign': '=' in context,
                    'has_quotes': '"' in context or "'" in context,
                    'has_colon': ':' in context,
                    'line_breaks': context.count('\n'),
                    'indentation': len(context) - len(context.lstrip())
                }
                
                # Détection de patterns de configuration
                config_patterns = [
                    r'config\s*[:=]',
                    r'settings\s*[:=]',
                    r'environment\s*[:=]',
                    r'env\s*[:=]'
                ]
                
                config_matches = 0
                for pattern in config_patterns:
                    if re.search(pattern, context, re.IGNORECASE):
                        config_matches += 1
                
                context_analysis['config_matches'] = config_matches
                context_analysis['is_config_context'] = config_matches > 0
                
                return context_analysis
                
            except Exception as e:
                logger.error(f"Erreur dans l'analyse de contexte: {e}")
                return {
                    'surrounding_text': '',
                    'has_equals_sign': False,
                    'has_quotes': False,
                    'has_colon': False,
                    'line_breaks': 0,
                    'indentation': 0,
                    'config_matches': 0,
                    'is_config_context': False
                }
        
        return analyze_context
    
    def train_models(self):
        """Entraîne les modèles ML"""
        try:
            if not self.training_data:
                logger.warning("Aucune donnée d'entraînement disponible")
                return False
            
            # Vectorisation des données d'entraînement
            X = self.tfidf_vectorizer.fit_transform(self.training_data)
            y = np.array(self.training_labels)
            
            # Division des données
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Entraînement du classificateur
            self.secret_classifier.fit(X_train, y_train)
            
            # Entraînement du détecteur d'anomalies
            self.anomaly_detector.fit(X_train)
            
            # Évaluation des modèles
            train_score = self.secret_classifier.score(X_train, y_train)
            test_score = self.secret_classifier.score(X_test, y_test)
            
            logger.info(f"Modèles entraînés - Score d'entraînement: {train_score:.3f}, Score de test: {test_score:.3f}")
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement des modèles: {e}")
            return False
    
    def detect_secrets(self, text: str) -> SecretDetectionResult:
        """
        Détecte les secrets dans le texte
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de la détection de secrets
        """
        try:
            start_time = datetime.utcnow()
            secrets_found = []
            
            # Détection par patterns regex
            regex_findings = self._detect_with_regex(text)
            secrets_found.extend(regex_findings)
            
            # Détection par ML
            ml_findings = self._detect_with_ml(text)
            secrets_found.extend(ml_findings)
            
            # Détection par analyse sémantique
            semantic_findings = self._detect_with_semantic_analysis(text)
            secrets_found.extend(semantic_findings)
            
            # Détection par analyse de contexte
            context_findings = self._detect_with_context_analysis(text)
            secrets_found.extend(context_findings)
            
            # Déduplication des findings
            deduplicated_findings = self._deduplicate_findings(secrets_found)
            
            # Calcul des métriques
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            risk_score = self._calculate_risk_score(deduplicated_findings)
            detection_confidence = self._calculate_detection_confidence(deduplicated_findings)
            
            # Création du résultat
            result = SecretDetectionResult(
                secrets_found=deduplicated_findings,
                total_secrets=len(deduplicated_findings),
                risk_score=risk_score,
                detection_confidence=detection_confidence,
                processing_time=processing_time,
                false_positives=0,  # À calculer avec validation
                false_negatives=0  # À calculer avec validation
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de secrets: {e}")
            return SecretDetectionResult(
                secrets_found=[],
                total_secrets=0,
                risk_score=0.0,
                detection_confidence=0.0,
                processing_time=0.0,
                false_positives=0,
                false_negatives=0
            )
    
    def _detect_with_regex(self, text: str) -> List[SecretFinding]:
        """Détection par patterns regex"""
        findings = []
        
        try:
            for secret_type, patterns in self.secret_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, text, re.IGNORECASE)
                    for match in matches:
                        finding = SecretFinding(
                            id=hashlib.md5(f"{secret_type.value}_{match.start()}_{match.end()}".encode()).hexdigest()[:8],
                            secret_type=secret_type,
                            value=match.group(1) if match.groups() else match.group(0),
                            masked_value=self._mask_secret(match.group(1) if match.groups() else match.group(0)),
                            start_position=match.start(),
                            end_position=match.end(),
                            confidence=0.9,  # Score élevé pour les patterns regex
                            detection_method=DetectionMethod.REGEX,
                            context=text[max(0, match.start()-20):match.end()+20],
                            risk_level=self._determine_risk_level(secret_type),
                            created_at=datetime.utcnow()
                        )
                        findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection regex: {e}")
            return []
    
    def _detect_with_ml(self, text: str) -> List[SecretFinding]:
        """Détection par modèles ML"""
        findings = []
        
        try:
            if not hasattr(self.secret_classifier, 'classes_'):
                logger.warning("Modèle ML non entraîné")
                return findings
            
            # Découpage du texte en segments
            segments = self._split_text_into_segments(text)
            
            for segment in segments:
                # Vectorisation du segment
                segment_vector = self.tfidf_vectorizer.transform([segment['text']])
                
                # Prédiction
                prediction = self.secret_classifier.predict(segment_vector)[0]
                probability = self.secret_classifier.predict_proba(segment_vector)[0][1]
                
                if prediction == 1 and probability > 0.7:
                    # Détection d'anomalie
                    anomaly_score = self.anomaly_detector.decision_function(segment_vector)[0]
                    
                    if anomaly_score < -0.5:  # Seuil d'anomalie
                        finding = SecretFinding(
                            id=hashlib.md5(f"ml_{segment['start']}_{segment['end']}".encode()).hexdigest()[:8],
                            secret_type=SecretType.API_KEY,  # Type par défaut pour ML
                            value=segment['text'],
                            masked_value=self._mask_secret(segment['text']),
                            start_position=segment['start'],
                            end_position=segment['end'],
                            confidence=probability,
                            detection_method=DetectionMethod.ML_MODEL,
                            context=text[max(0, segment['start']-20):segment['end']+20],
                            risk_level='medium',
                            created_at=datetime.utcnow()
                        )
                        findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection ML: {e}")
            return []
    
    def _detect_with_semantic_analysis(self, text: str) -> List[SecretFinding]:
        """Détection par analyse sémantique"""
        findings = []
        
        try:
            # Analyse sémantique du texte
            semantic_result = self.semantic_analyzer(text)
            
            if semantic_result['is_suspicious']:
                # Recherche de patterns suspects dans le texte
                suspicious_patterns = [
                    r'[A-Za-z0-9_-]{20,}',
                    r'[A-Za-z0-9+/]{40,}={0,2}',
                    r'[A-Fa-f0-9]{64,}'
                ]
                
                for pattern in suspicious_patterns:
                    matches = re.finditer(pattern, text)
                    for match in matches:
                        finding = SecretFinding(
                            id=hashlib.md5(f"semantic_{match.start()}_{match.end()}".encode()).hexdigest()[:8],
                            secret_type=SecretType.API_KEY,  # Type par défaut
                            value=match.group(0),
                            masked_value=self._mask_secret(match.group(0)),
                            start_position=match.start(),
                            end_position=match.end(),
                            confidence=semantic_result['semantic_score'],
                            detection_method=DetectionMethod.SEMANTIC_ANALYSIS,
                            context=text[max(0, match.start()-20):match.end()+20],
                            risk_level='medium',
                            created_at=datetime.utcnow()
                        )
                        findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection sémantique: {e}")
            return []
    
    def _detect_with_context_analysis(self, text: str) -> List[SecretFinding]:
        """Détection par analyse de contexte"""
        findings = []
        
        try:
            # Recherche de patterns génériques
            for pattern in self.generic_patterns:
                matches = re.finditer(pattern, text)
                for match in matches:
                    # Analyse du contexte
                    context_result = self.context_analyzer(text, match.start())
                    
                    if context_result['is_config_context'] or context_result['has_equals_sign']:
                        finding = SecretFinding(
                            id=hashlib.md5(f"context_{match.start()}_{match.end()}".encode()).hexdigest()[:8],
                            secret_type=SecretType.API_KEY,  # Type par défaut
                            value=match.group(0),
                            masked_value=self._mask_secret(match.group(0)),
                            start_position=match.start(),
                            end_position=match.end(),
                            confidence=0.6,  # Score moyen pour l'analyse de contexte
                            detection_method=DetectionMethod.CONTEXT_ANALYSIS,
                            context=context_result['surrounding_text'],
                            risk_level='low',
                            created_at=datetime.utcnow()
                        )
                        findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de contexte: {e}")
            return []
    
    def _split_text_into_segments(self, text: str, segment_size: int = 100) -> List[Dict[str, Any]]:
        """Découpe le texte en segments pour l'analyse ML"""
        segments = []
        
        for i in range(0, len(text), segment_size):
            segment_text = text[i:i+segment_size]
            segments.append({
                'text': segment_text,
                'start': i,
                'end': min(i+segment_size, len(text))
            })
        
        return segments
    
    def _mask_secret(self, secret: str) -> str:
        """Masque un secret"""
        if len(secret) <= 4:
            return '*' * len(secret)
        else:
            return secret[:2] + '*' * (len(secret) - 4) + secret[-2:]
    
    def _determine_risk_level(self, secret_type: SecretType) -> str:
        """Détermine le niveau de risque d'un type de secret"""
        risk_levels = {
            SecretType.PASSWORD: 'high',
            SecretType.PRIVATE_KEY: 'critical',
            SecretType.SSH_KEY: 'critical',
            SecretType.CERTIFICATE: 'high',
            SecretType.API_KEY: 'medium',
            SecretType.TOKEN: 'medium',
            SecretType.CREDENTIALS: 'high',
            SecretType.DATABASE_URL: 'high',
            SecretType.SECRET_KEY: 'high',
            SecretType.ACCESS_TOKEN: 'medium'
        }
        
        return risk_levels.get(secret_type, 'low')
    
    def _deduplicate_findings(self, findings: List[SecretFinding]) -> List[SecretFinding]:
        """Déduplique les findings"""
        seen_positions = set()
        deduplicated = []
        
        for finding in findings:
            position_key = (finding.start_position, finding.end_position)
            if position_key not in seen_positions:
                deduplicated.append(finding)
                seen_positions.add(position_key)
        
        return deduplicated
    
    def _calculate_risk_score(self, findings: List[SecretFinding]) -> float:
        """Calcule le score de risque global"""
        if not findings:
            return 0.0
        
        risk_weights = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4
        }
        
        total_score = 0.0
        for finding in findings:
            weight = risk_weights.get(finding.risk_level, 0.4)
            total_score += weight * finding.confidence
        
        return min(total_score / len(findings), 1.0)
    
    def _calculate_detection_confidence(self, findings: List[SecretFinding]) -> float:
        """Calcule la confiance globale de détection"""
        if not findings:
            return 0.0
        
        total_confidence = sum(finding.confidence for finding in findings)
        return total_confidence / len(findings)
    
    def process_text_with_secrets(self, text: str) -> Dict[str, Any]:
        """
        Traite le texte avec détection et rédaction de secrets
        
        Args:
            text: Texte à traiter
            
        Returns:
            Résultat du traitement
        """
        try:
            # Détection des secrets
            detection_result = self.detect_secrets(text)
            
            # Rédaction du texte
            redacted_text = text
            for finding in detection_result.secrets_found:
                redacted_text = redacted_text.replace(finding.value, finding.masked_value)
            
            # Journalisation chiffrée des événements
            self._log_secret_detection(detection_result)
            
            return {
                'secrets_detected': detection_result.total_secrets > 0,
                'total_secrets': detection_result.total_secrets,
                'processed_text': redacted_text,
                'original_text': text,
                'risk_score': detection_result.risk_score,
                'detection_confidence': detection_result.detection_confidence,
                'processing_time': detection_result.processing_time,
                'secrets_found': [
                    {
                        'type': finding.secret_type.value,
                        'masked_value': finding.masked_value,
                        'confidence': finding.confidence,
                        'risk_level': finding.risk_level
                    }
                    for finding in detection_result.secrets_found
                ]
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement du texte: {e}")
            return {
                'secrets_detected': False,
                'total_secrets': 0,
                'processed_text': text,
                'original_text': text,
                'error': str(e)
            }
    
    def _log_secret_detection(self, detection_result: SecretDetectionResult):
        """Journalise la détection de secrets de manière chiffrée"""
        try:
            # Création du log chiffré
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'total_secrets': detection_result.total_secrets,
                'risk_score': detection_result.risk_score,
                'detection_confidence': detection_result.detection_confidence,
                'processing_time': detection_result.processing_time
            }
            
            # Chiffrement du log (simulation)
            encrypted_log = hashlib.sha256(json.dumps(log_entry).encode()).hexdigest()
            
            # Stockage du log
            self.secret_findings.append({
                'encrypted_log': encrypted_log,
                'timestamp': datetime.utcnow().isoformat()
            })
            
            logger.info(f"Log de détection de secrets chiffré: {encrypted_log[:16]}...")
            
        except Exception as e:
            logger.error(f"Erreur lors de la journalisation: {e}")
    
    def generate_secrets_report(self) -> Dict[str, Any]:
        """Génère un rapport de détection de secrets"""
        try:
            if not self.secret_findings:
                return {'message': 'Aucun secret détecté'}
            
            # Statistiques des secrets détectés
            secret_stats = {}
            for finding in self.secret_findings:
                if isinstance(finding, SecretFinding):
                    secret_type = finding.secret_type.value
                    if secret_type not in secret_stats:
                        secret_stats[secret_type] = {
                            'count': 0,
                            'avg_confidence': 0,
                            'risk_levels': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                        }
                    
                    secret_stats[secret_type]['count'] += 1
                    secret_stats[secret_type]['avg_confidence'] += finding.confidence
                    secret_stats[secret_type]['risk_levels'][finding.risk_level] += 1
            
            # Normalisation des moyennes
            for secret_type in secret_stats:
                count = secret_stats[secret_type]['count']
                secret_stats[secret_type]['avg_confidence'] /= count
            
            return {
                'total_secrets_detected': len(self.secret_findings),
                'secret_statistics': secret_stats,
                'most_common_secret_type': max(secret_stats.keys(), key=lambda k: secret_stats[k]['count']),
                'highest_risk_secrets': max(secret_stats.keys(), key=lambda k: secret_stats[k]['risk_levels']['critical']),
                'report_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport: {e}")
            return {'error': str(e)}
