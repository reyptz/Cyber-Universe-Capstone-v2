"""
Détection Adversarial & Abuse avancée
Détection heuristique avec classifieur secondaire et quarantaine intelligente
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
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
from ..config import config

logger = logging.getLogger(__name__)

class AdversarialType(Enum):
    """Types d'attaques adversariales"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    TOXIC_CONTENT = "toxic_content"
    HATE_SPEECH = "hate_speech"
    VIOLENCE = "violence"
    MANIPULATION = "manipulation"
    SOCIAL_ENGINEERING = "social_engineering"

class DetectionMethod(Enum):
    """Méthodes de détection"""
    HEURISTIC = "heuristic"
    ML_CLASSIFIER = "ml_classifier"
    SECONDARY_CLASSIFIER = "secondary_classifier"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    SEMANTIC_ANALYSIS = "semantic_analysis"

class QuarantineStatus(Enum):
    """Statuts de quarantaine"""
    QUARANTINED = "quarantined"
    RELEASED = "released"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"

@dataclass
class AdversarialFinding:
    """Finding adversarial détecté"""
    id: str
    adversarial_type: AdversarialType
    content: str
    confidence: float
    detection_method: DetectionMethod
    heuristics_triggered: List[str]
    ml_scores: Dict[str, float]
    behavioral_indicators: List[str]
    risk_level: str
    created_at: datetime

@dataclass
class QuarantineEntry:
    """Entrée de quarantaine"""
    id: str
    content: str
    adversarial_findings: List[AdversarialFinding]
    quarantine_reason: str
    quarantine_timestamp: datetime
    status: QuarantineStatus
    review_required: bool
    human_reviewer: Optional[str]
    release_timestamp: Optional[datetime]

class AdvancedAdversarialDetector:
    """Détecteur adversarial avancé avec heuristiques et ML"""
    
    def __init__(self):
        """Initialise le détecteur adversarial avancé"""
        try:
            # Base de données des findings
            self.adversarial_findings = []
            self.quarantine_registry = {}
            
            # Modèles ML
            self._initialize_ml_models()
            
            # Heuristiques de détection
            self._initialize_heuristics()
            
            # Classifieur secondaire
            self._initialize_secondary_classifier()
            
            # Analyseur comportemental
            self._initialize_behavioral_analyzer()
            
            # Modèle spaCy pour l'analyse linguistique
            try:
                self.nlp = spacy.load("fr_core_news_sm")
            except OSError:
                logger.warning("Modèle français non trouvé, utilisation du modèle anglais")
                self.nlp = spacy.load("en_core_web_sm")
            
            logger.info("Détecteur adversarial avancé initialisé")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation: {e}")
            raise
    
    def _initialize_ml_models(self):
        """Initialise les modèles ML"""
        try:
            # Vectoriseur TF-IDF
            self.tfidf_vectorizer = TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 5),
                stop_words='english'
            )
            
            # Classificateur principal
            self.primary_classifier = RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                random_state=42
            )
            
            # Détecteur d'anomalies
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            
            # Modèles de toxicité
            self.toxicity_classifier = pipeline(
                "text-classification",
                model="unitary/toxic-bert",
                return_all_scores=True
            )
            
            # Modèle de perplexité
            self.perplexity_model = pipeline(
                "text-generation",
                model="gpt2",
                return_full_text=False
            )
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation des modèles ML: {e}")
            raise
    
    def _initialize_heuristics(self):
        """Initialise les heuristiques de détection"""
        self.heuristics = {
            'prompt_injection': [
                r'ignore\s+previous\s+instructions',
                r'forget\s+everything\s+above',
                r'you\s+are\s+now\s+dan',
                r'developer\s+mode',
                r'admin\s+override',
                r'bypass\s+safety',
                r'jailbreak\s+mode'
            ],
            'jailbreak': [
                r'pretend\s+to\s+be',
                r'act\s+as\s+if',
                r'roleplay\s+as',
                r'simulate\s+being',
                r'you\s+are\s+now',
                r'override\s+restrictions',
                r'disable\s+safety'
            ],
            'data_exfiltration': [
                r'show\s+your\s+instructions',
                r'reveal\s+your\s+programming',
                r'what\s+are\s+your\s+rules',
                r'display\s+your\s+configuration',
                r'system\s+prompt',
                r'access\s+your\s+data',
                r'extract\s+information'
            ],
            'manipulation': [
                r'please\s+help\s+me',
                r'i\s+really\s+need',
                r'it\'s\s+important\s+that',
                r'trust\s+me',
                r'just\s+this\s+once',
                r'emergency\s+situation',
                r'urgent\s+request'
            ],
            'social_engineering': [
                r'i\s+am\s+your\s+creator',
                r'admin\s+access\s+granted',
                r'developer\s+testing',
                r'security\s+research',
                r'authorized\s+override',
                r'emergency\s+protocol',
                r'system\s+administrator'
            ]
        }
        
        # Patterns de toxicité
        self.toxicity_patterns = [
            r'hate\s+speech',
            r'violent\s+content',
            r'discriminatory\s+language',
            r'harassment',
            r'bullying',
            r'threats',
            r'offensive\s+language'
        ]
        
        # Patterns de manipulation émotionnelle
        self.emotional_manipulation = [
            r'please\s+help',
            r'i\s+desperately\s+need',
            r'it\'s\s+urgent',
            r'life\s+or\s+death',
            r'emergency\s+situation',
            r'critical\s+request',
            r'last\s+resort'
        ]
    
    def _initialize_secondary_classifier(self):
        """Initialise le classifieur secondaire"""
        try:
            # Classifieur secondaire pour validation
            self.secondary_classifier = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            
            # Métriques de performance
            self.classifier_metrics = {
                'accuracy': 0.0,
                'precision': 0.0,
                'recall': 0.0,
                'f1_score': 0.0
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du classifieur secondaire: {e}")
            raise
    
    def _initialize_behavioral_analyzer(self):
        """Initialise l'analyseur comportemental"""
        def analyze_behavior(text: str, user_id: str = None) -> Dict[str, Any]:
            """Analyse le comportement de l'utilisateur"""
            try:
                behavioral_indicators = []
                
                # Analyse de la fréquence des requêtes
                if hasattr(self, 'user_request_history'):
                    if user_id in self.user_request_history:
                        request_count = len(self.user_request_history[user_id])
                        if request_count > 10:  # Seuil de requêtes excessives
                            behavioral_indicators.append('excessive_requests')
                
                # Analyse de la complexité des requêtes
                complexity_score = self._calculate_complexity_score(text)
                if complexity_score > 0.8:
                    behavioral_indicators.append('high_complexity')
                
                # Analyse des patterns répétitifs
                if self._detect_repetitive_patterns(text):
                    behavioral_indicators.append('repetitive_patterns')
                
                # Analyse de la cohérence sémantique
                semantic_coherence = self._analyze_semantic_coherence(text)
                if semantic_coherence < 0.5:
                    behavioral_indicators.append('low_semantic_coherence')
                
                return {
                    'behavioral_indicators': behavioral_indicators,
                    'complexity_score': complexity_score,
                    'semantic_coherence': semantic_coherence,
                    'is_suspicious': len(behavioral_indicators) > 2
                }
                
            except Exception as e:
                logger.error(f"Erreur dans l'analyse comportementale: {e}")
                return {
                    'behavioral_indicators': [],
                    'complexity_score': 0.0,
                    'semantic_coherence': 1.0,
                    'is_suspicious': False
                }
        
        self.behavioral_analyzer = analyze_behavior
        self.user_request_history = {}
    
    def _calculate_complexity_score(self, text: str) -> float:
        """Calcule le score de complexité du texte"""
        try:
            # Facteurs de complexité
            factors = {
                'length': min(len(text) / 1000, 1.0),
                'special_chars': len(re.findall(r'[^\w\s]', text)) / len(text) if text else 0,
                'uppercase_ratio': len(re.findall(r'[A-Z]', text)) / len(text) if text else 0,
                'digit_ratio': len(re.findall(r'\d', text)) / len(text) if text else 0,
                'word_diversity': len(set(text.lower().split())) / len(text.split()) if text.split() else 0
            }
            
            # Calcul du score global
            complexity_score = np.mean(list(factors.values()))
            return complexity_score
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul de complexité: {e}")
            return 0.0
    
    def _detect_repetitive_patterns(self, text: str) -> bool:
        """Détecte les patterns répétitifs"""
        try:
            words = text.lower().split()
            if len(words) < 10:
                return False
            
            # Recherche de répétitions
            word_counts = {}
            for word in words:
                word_counts[word] = word_counts.get(word, 0) + 1
            
            # Calcul du ratio de répétition
            max_count = max(word_counts.values())
            repetition_ratio = max_count / len(words)
            
            return repetition_ratio > 0.3
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de patterns répétitifs: {e}")
            return False
    
    def _analyze_semantic_coherence(self, text: str) -> float:
        """Analyse la cohérence sémantique"""
        try:
            # Analyse avec spaCy
            doc = self.nlp(text)
            
            # Calcul de la cohérence basée sur les entités
            entities = [ent.text for ent in doc.ents]
            if len(entities) == 0:
                return 1.0
            
            # Analyse de la cohérence des entités
            coherence_score = 1.0
            
            # Détection d'incohérences
            if len(set(entities)) < len(entities) * 0.8:
                coherence_score -= 0.3  # Trop de répétitions d'entités
            
            # Détection de contradictions
            contradiction_patterns = [
                r'ignore.*but.*follow',
                r'forget.*but.*remember',
                r'restrict.*but.*allow'
            ]
            
            for pattern in contradiction_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    coherence_score -= 0.5
            
            return max(coherence_score, 0.0)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de cohérence sémantique: {e}")
            return 1.0
    
    def comprehensive_adversarial_analysis(self, text: str, user_id: str = None) -> Dict[str, Any]:
        """
        Effectue une analyse adversarial complète
        
        Args:
            text: Texte à analyser
            user_id: Identifiant de l'utilisateur (optionnel)
            
        Returns:
            Résultat de l'analyse adversarial
        """
        try:
            analysis_result = {
                'text': text,
                'user_id': user_id,
                'adversarial_findings': [],
                'heuristics_triggered': [],
                'ml_scores': {},
                'behavioral_analysis': {},
                'toxicity_analysis': {},
                'perplexity_analysis': {},
                'overall_risk_score': 0.0,
                'should_quarantine': False,
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
            # Analyse heuristique
            heuristic_results = self._analyze_with_heuristics(text)
            analysis_result['heuristics_triggered'] = heuristic_results['triggered_heuristics']
            analysis_result['adversarial_findings'].extend(heuristic_results['findings'])
            
            # Analyse ML
            ml_results = self._analyze_with_ml(text)
            analysis_result['ml_scores'] = ml_results['scores']
            analysis_result['adversarial_findings'].extend(ml_results['findings'])
            
            # Analyse comportementale
            behavioral_results = self.behavioral_analyzer(text, user_id)
            analysis_result['behavioral_analysis'] = behavioral_results
            
            # Analyse de toxicité
            toxicity_results = self._analyze_toxicity(text)
            analysis_result['toxicity_analysis'] = toxicity_results
            if toxicity_results['is_toxic']:
                analysis_result['adversarial_findings'].append({
                    'type': 'toxic_content',
                    'confidence': toxicity_results['toxicity_score'],
                    'details': toxicity_results
                })
            
            # Analyse de perplexité
            perplexity_results = self._analyze_perplexity(text)
            analysis_result['perplexity_analysis'] = perplexity_results
            
            # Validation avec classifieur secondaire
            secondary_results = self._validate_with_secondary_classifier(text, analysis_result['adversarial_findings'])
            analysis_result['secondary_classification'] = secondary_results
            
            # Calcul du score de risque global
            analysis_result['overall_risk_score'] = self._calculate_overall_risk_score(analysis_result)
            
            # Décision de mise en quarantaine
            analysis_result['should_quarantine'] = self._should_quarantine(analysis_result)
            
            # Enregistrement des findings
            for finding in analysis_result['adversarial_findings']:
                self._record_adversarial_finding(finding, text, user_id)
            
            return analysis_result
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse adversarial: {e}")
            return {
                'text': text,
                'user_id': user_id,
                'adversarial_findings': [],
                'error': str(e),
                'should_quarantine': True  # En cas d'erreur, mettre en quarantaine par sécurité
            }
    
    def _analyze_with_heuristics(self, text: str) -> Dict[str, Any]:
        """Analyse avec les heuristiques"""
        try:
            triggered_heuristics = []
            findings = []
            
            # Test de chaque heuristique
            for category, patterns in self.heuristics.items():
                for pattern in patterns:
                    if re.search(pattern, text, re.IGNORECASE):
                        triggered_heuristics.append(f"{category}_{pattern}")
                        
                        finding = AdversarialFinding(
                            id=hashlib.md5(f"heuristic_{category}_{datetime.utcnow()}".encode()).hexdigest()[:8],
                            adversarial_type=AdversarialType(category.upper()),
                            content=text,
                            confidence=0.8,  # Score élevé pour les heuristiques
                            detection_method=DetectionMethod.HEURISTIC,
                            heuristics_triggered=[f"{category}_{pattern}"],
                            ml_scores={},
                            behavioral_indicators=[],
                            risk_level='high',
                            created_at=datetime.utcnow()
                        )
                        findings.append(finding)
            
            return {
                'triggered_heuristics': triggered_heuristics,
                'findings': findings
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse heuristique: {e}")
            return {'triggered_heuristics': [], 'findings': []}
    
    def _analyze_with_ml(self, text: str) -> Dict[str, Any]:
        """Analyse avec les modèles ML"""
        try:
            scores = {}
            findings = []
            
            # Vectorisation du texte
            text_vector = self.tfidf_vectorizer.transform([text])
            
            # Prédiction avec le classificateur principal
            if hasattr(self.primary_classifier, 'classes_'):
                prediction = self.primary_classifier.predict(text_vector)[0]
                probability = self.primary_classifier.predict_proba(text_vector)[0][1]
                
                scores['primary_classifier'] = probability
                
                if prediction == 1 and probability > 0.7:
                    finding = AdversarialFinding(
                        id=hashlib.md5(f"ml_{datetime.utcnow()}".encode()).hexdigest()[:8],
                        adversarial_type=AdversarialType.PROMPT_INJECTION,
                        content=text,
                        confidence=probability,
                        detection_method=DetectionMethod.ML_CLASSIFIER,
                        heuristics_triggered=[],
                        ml_scores={'primary_classifier': probability},
                        behavioral_indicators=[],
                        risk_level='medium',
                        created_at=datetime.utcnow()
                    )
                    findings.append(finding)
            
            # Détection d'anomalie
            anomaly_score = self.anomaly_detector.decision_function(text_vector)[0]
            scores['anomaly_detector'] = anomaly_score
            
            if anomaly_score < -0.5:
                finding = AdversarialFinding(
                    id=hashlib.md5(f"anomaly_{datetime.utcnow()}".encode()).hexdigest()[:8],
                    adversarial_type=AdversarialType.MANIPULATION,
                    content=text,
                    confidence=abs(anomaly_score),
                    detection_method=DetectionMethod.ML_CLASSIFIER,
                    heuristics_triggered=[],
                    ml_scores={'anomaly_detector': anomaly_score},
                    behavioral_indicators=[],
                    risk_level='medium',
                    created_at=datetime.utcnow()
                )
                findings.append(finding)
            
            return {
                'scores': scores,
                'findings': findings
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse ML: {e}")
            return {'scores': {}, 'findings': []}
    
    def _analyze_toxicity(self, text: str) -> Dict[str, Any]:
        """Analyse la toxicité du contenu"""
        try:
            # Analyse avec le modèle de toxicité
            toxicity_results = self.toxicity_classifier(text)
            
            # Calcul du score de toxicité global
            toxicity_score = 0
            toxic_labels = []
            
            for result in toxicity_results[0]:
                if result['label'] in ['toxic', 'severe_toxic', 'obscene', 'threat', 'insult', 'identity_hate']:
                    toxicity_score = max(toxicity_score, result['score'])
                    toxic_labels.append(result['label'])
            
            return {
                'is_toxic': toxicity_score > 0.7,
                'toxicity_score': toxicity_score,
                'toxic_labels': toxic_labels,
                'risk_level': 'high' if toxicity_score > 0.8 else 'medium' if toxicity_score > 0.5 else 'low'
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de toxicité: {e}")
            return {
                'is_toxic': False,
                'toxicity_score': 0.0,
                'toxic_labels': [],
                'risk_level': 'low'
            }
    
    def _analyze_perplexity(self, text: str) -> Dict[str, Any]:
        """Analyse la perplexité du texte"""
        try:
            # Calcul de la perplexité avec GPT-2
            tokenizer = AutoTokenizer.from_pretrained("gpt2")
            model = AutoModelForSequenceClassification.from_pretrained("gpt2")
            
            inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
            
            with torch.no_grad():
                outputs = model(**inputs)
                logits = outputs.logits
                perplexity = torch.exp(torch.mean(-logits))
                perplexity_score = float(perplexity)
            
            return {
                'perplexity_score': perplexity_score,
                'is_abnormal': perplexity_score > 100,  # Seuil de perplexité anormale
                'confidence': min(perplexity_score / 100, 1.0)
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de perplexité: {e}")
            return {
                'perplexity_score': 0.0,
                'is_abnormal': False,
                'confidence': 0.0
            }
    
    def _validate_with_secondary_classifier(self, text: str, findings: List[Dict]) -> Dict[str, Any]:
        """Valide avec le classifieur secondaire"""
        try:
            if not findings:
                return {'validated': True, 'confidence': 1.0}
            
            # Simulation de validation avec classifieur secondaire
            # En production, utiliser un modèle entraîné spécifiquement pour la validation
            
            total_confidence = sum(finding.get('confidence', 0) for finding in findings)
            avg_confidence = total_confidence / len(findings) if findings else 0
            
            # Seuil de validation
            validation_threshold = 0.6
            validated = avg_confidence > validation_threshold
            
            return {
                'validated': validated,
                'confidence': avg_confidence,
                'threshold': validation_threshold,
                'findings_count': len(findings)
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation secondaire: {e}")
            return {'validated': False, 'confidence': 0.0, 'error': str(e)}
    
    def _calculate_overall_risk_score(self, analysis_result: Dict[str, Any]) -> float:
        """Calcule le score de risque global"""
        try:
            risk_factors = []
            
            # Facteur heuristique
            if analysis_result['heuristics_triggered']:
                risk_factors.append(0.8)
            
            # Facteur ML
            ml_scores = analysis_result.get('ml_scores', {})
            if ml_scores:
                risk_factors.append(max(ml_scores.values()))
            
            # Facteur comportemental
            behavioral_analysis = analysis_result.get('behavioral_analysis', {})
            if behavioral_analysis.get('is_suspicious', False):
                risk_factors.append(0.7)
            
            # Facteur de toxicité
            toxicity_analysis = analysis_result.get('toxicity_analysis', {})
            if toxicity_analysis.get('is_toxic', False):
                risk_factors.append(toxicity_analysis.get('toxicity_score', 0))
            
            # Facteur de perplexité
            perplexity_analysis = analysis_result.get('perplexity_analysis', {})
            if perplexity_analysis.get('is_abnormal', False):
                risk_factors.append(0.6)
            
            # Calcul du score global
            if risk_factors:
                overall_risk_score = max(risk_factors)
            else:
                overall_risk_score = 0.0
            
            return min(overall_risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul du score de risque: {e}")
            return 0.0
    
    def _should_quarantine(self, analysis_result: Dict[str, Any]) -> bool:
        """Détermine si le contenu doit être mis en quarantaine"""
        try:
            # Critères de mise en quarantaine
            quarantine_criteria = [
                analysis_result['overall_risk_score'] > 0.7,
                len(analysis_result['adversarial_findings']) > 0,
                analysis_result.get('toxicity_analysis', {}).get('is_toxic', False),
                analysis_result.get('behavioral_analysis', {}).get('is_suspicious', False)
            ]
            
            # Mise en quarantaine si au moins un critère est rempli
            return any(quarantine_criteria)
            
        except Exception as e:
            logger.error(f"Erreur lors de la décision de quarantaine: {e}")
            return True  # En cas d'erreur, mettre en quarantaine par sécurité
    
    def _record_adversarial_finding(self, finding: Dict, text: str, user_id: str = None):
        """Enregistre un finding adversarial"""
        try:
            # Création de l'objet AdversarialFinding
            adversarial_finding = AdversarialFinding(
                id=finding.get('id', hashlib.md5(f"{text}_{datetime.utcnow()}".encode()).hexdigest()[:8]),
                adversarial_type=AdversarialType(finding.get('type', 'PROMPT_INJECTION')),
                content=text,
                confidence=finding.get('confidence', 0.0),
                detection_method=DetectionMethod(finding.get('detection_method', 'HEURISTIC')),
                heuristics_triggered=finding.get('heuristics_triggered', []),
                ml_scores=finding.get('ml_scores', {}),
                behavioral_indicators=finding.get('behavioral_indicators', []),
                risk_level=finding.get('risk_level', 'medium'),
                created_at=datetime.utcnow()
            )
            
            # Ajout à la base de données
            self.adversarial_findings.append(adversarial_finding)
            
            # Mise à jour de l'historique utilisateur
            if user_id:
                if user_id not in self.user_request_history:
                    self.user_request_history[user_id] = []
                self.user_request_history[user_id].append({
                    'timestamp': datetime.utcnow().isoformat(),
                    'text': text,
                    'adversarial_finding': adversarial_finding
                })
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement du finding: {e}")
    
    def quarantine_content(self, content_id: str, content: str, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Met du contenu en quarantaine
        
        Args:
            content_id: Identifiant du contenu
            content: Contenu à mettre en quarantaine
            analysis_result: Résultat de l'analyse adversarial
            
        Returns:
            Résultat de la mise en quarantaine
        """
        try:
            # Création de l'entrée de quarantaine
            quarantine_entry = QuarantineEntry(
                id=content_id,
                content=content,
                adversarial_findings=analysis_result.get('adversarial_findings', []),
                quarantine_reason=self._generate_quarantine_reason(analysis_result),
                quarantine_timestamp=datetime.utcnow(),
                status=QuarantineStatus.QUARANTINED,
                review_required=analysis_result['overall_risk_score'] > 0.8,
                human_reviewer=None,
                release_timestamp=None
            )
            
            # Ajout au registre de quarantaine
            self.quarantine_registry[content_id] = quarantine_entry
            
            logger.warning(f"Contenu mis en quarantaine: {content_id} - Raison: {quarantine_entry.quarantine_reason}")
            
            return {
                'quarantined': True,
                'content_id': content_id,
                'quarantine_timestamp': quarantine_entry.quarantine_timestamp.isoformat(),
                'review_required': quarantine_entry.review_required,
                'quarantine_reason': quarantine_entry.quarantine_reason
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise en quarantaine: {e}")
            return {'quarantined': False, 'error': str(e)}
    
    def _generate_quarantine_reason(self, analysis_result: Dict[str, Any]) -> str:
        """Génère la raison de la mise en quarantaine"""
        try:
            reasons = []
            
            if analysis_result.get('heuristics_triggered'):
                reasons.append("Patterns heuristiques suspects détectés")
            
            if analysis_result.get('toxicity_analysis', {}).get('is_toxic'):
                reasons.append("Contenu toxique détecté")
            
            if analysis_result.get('behavioral_analysis', {}).get('is_suspicious'):
                reasons.append("Comportement suspect détecté")
            
            if analysis_result.get('perplexity_analysis', {}).get('is_abnormal'):
                reasons.append("Perplexité anormale détectée")
            
            if not reasons:
                reasons.append("Score de risque global élevé")
            
            return "; ".join(reasons)
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération de la raison: {e}")
            return "Analyse de sécurité échouée"
    
    def get_quarantine_status(self) -> Dict[str, Any]:
        """Retourne le statut de la quarantaine"""
        try:
            total_quarantined = len(self.quarantine_registry)
            
            # Comptage par statut
            status_counts = {
                'quarantined': 0,
                'pending_review': 0,
                'approved': 0,
                'rejected': 0
            }
            
            review_required = 0
            
            for entry in self.quarantine_registry.values():
                status_counts[entry.status.value] += 1
                if entry.review_required:
                    review_required += 1
            
            return {
                'total_quarantined': total_quarantined,
                'status_distribution': status_counts,
                'review_required': review_required,
                'quarantine_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du statut de quarantaine: {e}")
            return {'total_quarantined': 0, 'error': str(e)}
    
    def release_from_quarantine(self, content_id: str, human_approval: bool = False, reviewer: str = None) -> Dict[str, Any]:
        """
        Libère du contenu de la quarantaine
        
        Args:
            content_id: Identifiant du contenu
            human_approval: Approbation humaine
            reviewer: Nom du réviseur
            
        Returns:
            Résultat de la libération
        """
        try:
            if content_id not in self.quarantine_registry:
                return {'released': False, 'error': 'Contenu non trouvé en quarantaine'}
            
            quarantine_entry = self.quarantine_registry[content_id]
            
            # Vérification des conditions de libération
            if quarantine_entry.review_required and not human_approval:
                return {
                    'released': False,
                    'reason': 'Approbation humaine requise pour ce contenu'
                }
            
            # Libération du contenu
            quarantine_entry.status = QuarantineStatus.RELEASED
            quarantine_entry.release_timestamp = datetime.utcnow()
            if reviewer:
                quarantine_entry.human_reviewer = reviewer
            
            logger.info(f"Contenu libéré de la quarantaine: {content_id}")
            
            return {
                'released': True,
                'content_id': content_id,
                'release_timestamp': quarantine_entry.release_timestamp.isoformat(),
                'human_approved': human_approval,
                'reviewer': reviewer
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la libération de quarantaine: {e}")
            return {'released': False, 'error': str(e)}
    
    def generate_adversarial_report(self) -> Dict[str, Any]:
        """Génère un rapport adversarial complet"""
        try:
            if not self.adversarial_findings:
                return {'message': 'Aucun finding adversarial enregistré'}
            
            # Statistiques des findings
            finding_stats = {}
            for finding in self.adversarial_findings:
                finding_type = finding.adversarial_type.value
                if finding_type not in finding_stats:
                    finding_stats[finding_type] = {
                        'count': 0,
                        'avg_confidence': 0,
                        'risk_levels': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
                    }
                
                finding_stats[finding_type]['count'] += 1
                finding_stats[finding_type]['avg_confidence'] += finding.confidence
                finding_stats[finding_type]['risk_levels'][finding.risk_level] += 1
            
            # Normalisation des moyennes
            for finding_type in finding_stats:
                count = finding_stats[finding_type]['count']
                finding_stats[finding_type]['avg_confidence'] /= count
            
            # Statistiques de quarantaine
            quarantine_stats = self.get_quarantine_status()
            
            return {
                'total_findings': len(self.adversarial_findings),
                'finding_statistics': finding_stats,
                'quarantine_statistics': quarantine_stats,
                'most_common_attack_type': max(finding_stats.keys(), key=lambda k: finding_stats[k]['count']),
                'highest_risk_findings': max(finding_stats.keys(), key=lambda k: finding_stats[k]['risk_levels']['high']),
                'report_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport adversarial: {e}")
            return {'error': str(e)}
