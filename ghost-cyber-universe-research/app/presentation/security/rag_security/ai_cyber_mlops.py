"""
AI pour la Cyber avec MLOps
Détection & classification, NLP & LLMs, MLOps pipeline
Anomalies, toxicité, fuite, MLOps complet
"""

import json
import logging
import hashlib
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Optional, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import joblib
import pickle
from pathlib import Path

# ML Libraries
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
import xgboost as xgb
import tensorflow as tf
import torch
import torch.nn as nn

# NLP & LLMs
import spacy
from transformers import pipeline, AutoTokenizer, AutoModel
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import Chroma
from langchain.chains import RetrievalQA
from langchain.llms import OpenAI

# MLOps
import mlflow
import mlflow.sklearn
import mlflow.tensorflow
import mlflow.pytorch
from mlflow.tracking import MlflowClient
import wandb
from wandb.integration.mlflow import WandbMlflowLogger

logger = logging.getLogger(__name__)

class ModelType(Enum):
    """Types de modèles ML"""
    CLASSIFICATION = "classification"
    ANOMALY_DETECTION = "anomaly_detection"
    NLP_CLASSIFICATION = "nlp_classification"
    TOXICITY_DETECTION = "toxicity_detection"
    SECRETS_DETECTION = "secrets_detection"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"

class DataType(Enum):
    """Types de données"""
    NETWORK_LOGS = "network_logs"
    SYSTEM_LOGS = "system_logs"
    TEXT_DATA = "text_data"
    BEHAVIORAL_DATA = "behavioral_data"
    SECURITY_EVENTS = "security_events"

@dataclass
class MLModel:
    """Modèle ML"""
    id: str
    name: str
    model_type: ModelType
    version: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    created_at: datetime
    last_trained: datetime
    model_path: str
    metadata: Dict[str, Any]

@dataclass
class TrainingDataset:
    """Dataset d'entraînement"""
    id: str
    name: str
    data_type: DataType
    size: int
    features: List[str]
    target_column: str
    created_at: datetime
    file_path: str
    metadata: Dict[str, Any]

@dataclass
class MLPipeline:
    """Pipeline ML"""
    id: str
    name: str
    model_type: ModelType
    data_preprocessing: Dict[str, Any]
    feature_engineering: Dict[str, Any]
    model_training: Dict[str, Any]
    evaluation: Dict[str, Any]
    deployment: Dict[str, Any]
    created_at: datetime
    status: str

class AICyberMLOps:
    """Plateforme AI pour la Cyber avec MLOps"""
    
    def __init__(self):
        """Initialise la plateforme AI Cyber MLOps"""
        try:
            # Configuration MLflow
            self._initialize_mlflow()
            
            # Configuration W&B
            self._initialize_wandb()
            
            # Modèles ML
            self.ml_models = {}
            self.training_datasets = {}
            self.ml_pipelines = {}
            
            # Moteurs de détection
            self._initialize_detection_engines()
            
            # Configuration NLP
            self._initialize_nlp_engines()
            
            # MLOps pipeline
            self._initialize_mlops_pipeline()
            
            logger.info("AI Cyber MLOps Platform initialisée")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation: {e}")
            raise
    
    def _initialize_mlflow(self):
        """Initialise MLflow"""
        try:
            # Configuration MLflow
            mlflow.set_tracking_uri("http://localhost:5000")
            mlflow.set_experiment("ai_cyber_security")
            
            self.mlflow_client = MlflowClient()
            
            logger.info("MLflow initialisé")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation MLflow: {e}")
    
    def _initialize_wandb(self):
        """Initialise W&B"""
        try:
            # Configuration W&B
            wandb.init(
                project="ai-cyber-security",
                entity="cyber-team",
                config={
                    "learning_rate": 0.01,
                    "epochs": 100,
                    "batch_size": 32
                }
            )
            
            logger.info("W&B initialisé")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation W&B: {e}")
    
    def _initialize_detection_engines(self):
        """Initialise les moteurs de détection"""
        self.detection_engines = {
            'anomaly_detector': self._create_anomaly_detector(),
            'toxicity_classifier': self._create_toxicity_classifier(),
            'secrets_detector': self._create_secrets_detector(),
            'behavioral_analyzer': self._create_behavioral_analyzer(),
            'network_analyzer': self._create_network_analyzer()
        }
    
    def _create_anomaly_detector(self):
        """Crée le détecteur d'anomalies"""
        try:
            # Isolation Forest pour détection d'anomalies
            detector = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            
            return detector
            
        except Exception as e:
            logger.error(f"Erreur lors de la création du détecteur d'anomalies: {e}")
            return None
    
    def _create_toxicity_classifier(self):
        """Crée le classifieur de toxicité"""
        try:
            # Pipeline de détection de toxicité avec Transformers
            toxicity_pipeline = pipeline(
                "text-classification",
                model="unitary/toxic-bert",
                return_all_scores=True
            )
            
            return toxicity_pipeline
            
        except Exception as e:
            logger.error(f"Erreur lors de la création du classifieur de toxicité: {e}")
            return None
    
    def _create_secrets_detector(self):
        """Crée le détecteur de secrets"""
        try:
            # Modèle de détection de secrets (simulation)
            # En production, utiliser un modèle entraîné sur des patterns de secrets
            
            secrets_patterns = [
                r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64
                r'[A-Za-z0-9]{32}',  # MD5
                r'[A-Za-z0-9]{40}',  # SHA1
                r'[A-Za-z0-9]{64}',  # SHA256
                r'sk-[A-Za-z0-9]{48}',  # OpenAI API key
                r'[A-Za-z0-9]{20,}',  # Generic API key
            ]
            
            return {
                'patterns': secrets_patterns,
                'model_type': 'regex_ml_hybrid'
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la création du détecteur de secrets: {e}")
            return None
    
    def _create_behavioral_analyzer(self):
        """Crée l'analyseur comportemental"""
        try:
            # Modèle d'analyse comportementale
            # En production, utiliser un modèle entraîné sur des données comportementales
            
            behavioral_features = [
                'login_frequency',
                'session_duration',
                'page_views',
                'click_patterns',
                'navigation_path',
                'time_patterns'
            ]
            
            return {
                'features': behavioral_features,
                'model_type': 'behavioral_analysis'
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la création de l'analyseur comportemental: {e}")
            return None
    
    def _create_network_analyzer(self):
        """Crée l'analyseur réseau"""
        try:
            # Modèle d'analyse réseau
            # En production, utiliser un modèle entraîné sur des logs réseau
            
            network_features = [
                'packet_size',
                'protocol_type',
                'connection_duration',
                'bytes_transferred',
                'packet_frequency',
                'destination_port'
            ]
            
            return {
                'features': network_features,
                'model_type': 'network_analysis'
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la création de l'analyseur réseau: {e}")
            return None
    
    def _initialize_nlp_engines(self):
        """Initialise les moteurs NLP"""
        try:
            # Configuration spaCy
            self.nlp = spacy.load("en_core_web_sm")
            
            # Configuration Transformers
            self.tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
            self.bert_model = AutoModel.from_pretrained("bert-base-uncased")
            
            # Configuration LangChain
            self.embeddings = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-MiniLM-L6-v2"
            )
            
            # Configuration Chroma
            self.vector_store = Chroma(
                collection_name="cyber_documents",
                embedding_function=self.embeddings
            )
            
            logger.info("Moteurs NLP initialisés")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation des moteurs NLP: {e}")
    
    def _initialize_mlops_pipeline(self):
        """Initialise le pipeline MLOps"""
        try:
            # Configuration du pipeline MLOps
            self.mlops_config = {
                'data_validation': {
                    'schema_validation': True,
                    'data_quality_checks': True,
                    'drift_detection': True
                },
                'model_training': {
                    'hyperparameter_tuning': True,
                    'cross_validation': True,
                    'model_selection': True
                },
                'model_evaluation': {
                    'performance_metrics': True,
                    'bias_detection': True,
                    'explainability': True
                },
                'model_deployment': {
                    'a_b_testing': True,
                    'canary_deployment': True,
                    'rollback_capability': True
                },
                'model_monitoring': {
                    'performance_monitoring': True,
                    'drift_monitoring': True,
                    'alerting': True
                }
            }
            
            logger.info("Pipeline MLOps initialisé")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du pipeline MLOps: {e}")
    
    def create_training_dataset(self, name: str, data_type: DataType, file_path: str) -> TrainingDataset:
        """
        Crée un dataset d'entraînement
        
        Args:
            name: Nom du dataset
            data_type: Type de données
            file_path: Chemin vers le fichier de données
            
        Returns:
            Dataset d'entraînement créé
        """
        try:
            dataset_id = hashlib.md5(f"{name}_{datetime.utcnow()}".encode()).hexdigest()[:8]
            
            # Chargement et analyse des données
            df = pd.read_csv(file_path)
            
            # Extraction des caractéristiques
            features = df.columns.tolist()
            target_column = features[-1] if features else 'target'
            
            dataset = TrainingDataset(
                id=dataset_id,
                name=name,
                data_type=data_type,
                size=len(df),
                features=features,
                target_column=target_column,
                created_at=datetime.utcnow(),
                file_path=file_path,
                metadata={
                    'shape': df.shape,
                    'dtypes': df.dtypes.to_dict(),
                    'missing_values': df.isnull().sum().to_dict(),
                    'unique_values': df.nunique().to_dict()
                }
            )
            
            # Enregistrement du dataset
            self.training_datasets[dataset_id] = dataset
            
            logger.info(f"Dataset d'entraînement créé: {dataset_id} - {name}")
            
            return dataset
            
        except Exception as e:
            logger.error(f"Erreur lors de la création du dataset: {e}")
            raise
    
    def train_ml_model(self, dataset_id: str, model_type: ModelType, model_name: str) -> MLModel:
        """
        Entraîne un modèle ML
        
        Args:
            dataset_id: ID du dataset d'entraînement
            model_name: Nom du modèle
            model_type: Type de modèle
            
        Returns:
            Modèle ML entraîné
        """
        try:
            if dataset_id not in self.training_datasets:
                raise ValueError("Dataset non trouvé")
            
            dataset = self.training_datasets[dataset_id]
            
            # Chargement des données
            df = pd.read_csv(dataset.file_path)
            
            # Préparation des données
            X = df.drop(columns=[dataset.target_column])
            y = df[dataset.target_column]
            
            # Division train/test
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Normalisation des caractéristiques
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            
            # Entraînement du modèle selon le type
            if model_type == ModelType.CLASSIFICATION:
                model = self._train_classification_model(X_train_scaled, y_train)
            elif model_type == ModelType.ANOMALY_DETECTION:
                model = self._train_anomaly_model(X_train_scaled)
            elif model_type == ModelType.TOXICITY_DETECTION:
                model = self._train_toxicity_model(X_train, y_train)
            elif model_type == ModelType.SECRETS_DETECTION:
                model = self._train_secrets_model(X_train, y_train)
            elif model_type == ModelType.BEHAVIORAL_ANALYSIS:
                model = self._train_behavioral_model(X_train_scaled, y_train)
            else:
                raise ValueError(f"Type de modèle non supporté: {model_type}")
            
            # Évaluation du modèle
            metrics = self._evaluate_model(model, X_test_scaled, y_test, model_type)
            
            # Sauvegarde du modèle
            model_id = hashlib.md5(f"{model_name}_{datetime.utcnow()}".encode()).hexdigest()[:8]
            model_path = f"models/{model_id}.pkl"
            
            # Création du répertoire si nécessaire
            Path("models").mkdir(exist_ok=True)
            
            # Sauvegarde
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            
            # Sauvegarde du scaler
            scaler_path = f"models/{model_id}_scaler.pkl"
            with open(scaler_path, 'wb') as f:
                pickle.dump(scaler, f)
            
            # Enregistrement MLflow
            with mlflow.start_run():
                mlflow.log_params({
                    'model_type': model_type.value,
                    'dataset_id': dataset_id,
                    'model_name': model_name
                })
                
                mlflow.log_metrics(metrics)
                
                mlflow.sklearn.log_model(
                    model,
                    "model",
                    registered_model_name=model_name
                )
            
            # Création de l'objet modèle
            ml_model = MLModel(
                id=model_id,
                name=model_name,
                model_type=model_type,
                version="1.0.0",
                accuracy=metrics.get('accuracy', 0.0),
                precision=metrics.get('precision', 0.0),
                recall=metrics.get('recall', 0.0),
                f1_score=metrics.get('f1_score', 0.0),
                created_at=datetime.utcnow(),
                last_trained=datetime.utcnow(),
                model_path=model_path,
                metadata={
                    'dataset_id': dataset_id,
                    'scaler_path': scaler_path,
                    'mlflow_run_id': mlflow.active_run().info.run_id
                }
            )
            
            # Enregistrement du modèle
            self.ml_models[model_id] = ml_model
            
            logger.info(f"Modèle ML entraîné: {model_id} - {model_name}")
            
            return ml_model
            
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement du modèle: {e}")
            raise
    
    def _train_classification_model(self, X_train, y_train):
        """Entraîne un modèle de classification"""
        try:
            # Random Forest Classifier
            model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10
            )
            
            model.fit(X_train, y_train)
            
            return model
            
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement du modèle de classification: {e}")
            raise
    
    def _train_anomaly_model(self, X_train):
        """Entraîne un modèle de détection d'anomalies"""
        try:
            # Isolation Forest
            model = IsolationForest(
                contamination=0.1,
                random_state=42
            )
            
            model.fit(X_train)
            
            return model
            
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement du modèle d'anomalies: {e}")
            raise
    
    def _train_toxicity_model(self, X_train, y_train):
        """Entraîne un modèle de détection de toxicité"""
        try:
            # XGBoost pour classification de toxicité
            model = xgb.XGBClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=6
            )
            
            model.fit(X_train, y_train)
            
            return model
            
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement du modèle de toxicité: {e}")
            raise
    
    def _train_secrets_model(self, X_train, y_train):
        """Entraîne un modèle de détection de secrets"""
        try:
            # Random Forest pour détection de secrets
            model = RandomForestClassifier(
                n_estimators=50,
                random_state=42,
                max_depth=8
            )
            
            model.fit(X_train, y_train)
            
            return model
            
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement du modèle de secrets: {e}")
            raise
    
    def _train_behavioral_model(self, X_train, y_train):
        """Entraîne un modèle d'analyse comportementale"""
        try:
            # Random Forest pour analyse comportementale
            model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=12
            )
            
            model.fit(X_train, y_train)
            
            return model
            
        except Exception as e:
            logger.error(f"Erreur lors de l'entraînement du modèle comportemental: {e}")
            raise
    
    def _evaluate_model(self, model, X_test, y_test, model_type: ModelType):
        """Évalue un modèle ML"""
        try:
            metrics = {}
            
            if model_type == ModelType.CLASSIFICATION:
                # Prédictions
                y_pred = model.predict(X_test)
                y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
                
                # Métriques de classification
                metrics['accuracy'] = model.score(X_test, y_test)
                
                # Rapport de classification
                report = classification_report(y_test, y_pred, output_dict=True)
                metrics['precision'] = report['weighted avg']['precision']
                metrics['recall'] = report['weighted avg']['recall']
                metrics['f1_score'] = report['weighted avg']['f1-score']
                
                # AUC-ROC si disponible
                if y_pred_proba is not None:
                    metrics['auc_roc'] = roc_auc_score(y_test, y_pred_proba)
                
            elif model_type == ModelType.ANOMALY_DETECTION:
                # Prédictions d'anomalies
                anomaly_scores = model.decision_function(X_test)
                predictions = model.predict(X_test)
                
                # Métriques d'anomalie
                metrics['anomaly_score_mean'] = np.mean(anomaly_scores)
                metrics['anomaly_score_std'] = np.std(anomaly_scores)
                metrics['anomaly_rate'] = np.sum(predictions == -1) / len(predictions)
                
            else:
                # Métriques génériques
                metrics['accuracy'] = model.score(X_test, y_test) if hasattr(model, 'score') else 0.0
            
            return metrics
            
        except Exception as e:
            logger.error(f"Erreur lors de l'évaluation du modèle: {e}")
            return {}
    
    def detect_anomalies(self, data: np.ndarray, model_id: str) -> Dict[str, Any]:
        """
        Détecte les anomalies avec un modèle entraîné
        
        Args:
            data: Données à analyser
            model_id: ID du modèle à utiliser
            
        Returns:
            Résultats de détection d'anomalies
        """
        try:
            if model_id not in self.ml_models:
                return {'success': False, 'error': 'Modèle non trouvé'}
            
            model_info = self.ml_models[model_id]
            
            # Chargement du modèle
            with open(model_info.model_path, 'rb') as f:
                model = pickle.load(f)
            
            # Chargement du scaler
            scaler_path = model_info.metadata.get('scaler_path')
            if scaler_path and Path(scaler_path).exists():
                with open(scaler_path, 'rb') as f:
                    scaler = pickle.load(f)
                data_scaled = scaler.transform(data)
            else:
                data_scaled = data
            
            # Prédictions d'anomalies
            anomaly_scores = model.decision_function(data_scaled)
            predictions = model.predict(data_scaled)
            
            # Analyse des résultats
            anomalies = np.where(predictions == -1)[0]
            normal = np.where(predictions == 1)[0]
            
            return {
                'success': True,
                'model_id': model_id,
                'total_samples': len(data),
                'anomalies_detected': len(anomalies),
                'normal_samples': len(normal),
                'anomaly_rate': len(anomalies) / len(data),
                'anomaly_scores': anomaly_scores.tolist(),
                'anomaly_indices': anomalies.tolist(),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection d'anomalies: {e}")
            return {'success': False, 'error': str(e)}
    
    def detect_toxicity(self, text: str) -> Dict[str, Any]:
        """
        Détecte la toxicité dans un texte
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultats de détection de toxicité
        """
        try:
            if not self.detection_engines.get('toxicity_classifier'):
                return {'success': False, 'error': 'Classifieur de toxicité non disponible'}
            
            # Détection de toxicité
            results = self.detection_engines['toxicity_classifier'](text)
            
            # Analyse des résultats
            toxicity_scores = {}
            for result in results:
                label = result['label']
                score = result['score']
                toxicity_scores[label] = score
            
            # Détermination du niveau de toxicité
            max_score = max(toxicity_scores.values())
            max_label = max(toxicity_scores, key=toxicity_scores.get)
            
            toxicity_level = 'low'
            if max_score > 0.8:
                toxicity_level = 'high'
            elif max_score > 0.5:
                toxicity_level = 'medium'
            
            return {
                'success': True,
                'text': text,
                'toxicity_level': toxicity_level,
                'max_score': max_score,
                'max_label': max_label,
                'all_scores': toxicity_scores,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de toxicité: {e}")
            return {'success': False, 'error': str(e)}
    
    def detect_secrets(self, text: str) -> Dict[str, Any]:
        """
        Détecte les secrets dans un texte
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultats de détection de secrets
        """
        try:
            import re
            
            secrets_detector = self.detection_engines.get('secrets_detector')
            if not secrets_detector:
                return {'success': False, 'error': 'Détecteur de secrets non disponible'}
            
            detected_secrets = []
            patterns = secrets_detector.get('patterns', [])
            
            # Recherche de patterns de secrets
            for pattern in patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    detected_secrets.append({
                        'pattern': pattern,
                        'match': match,
                        'position': text.find(match)
                    })
            
            # Classification des secrets
            secret_types = {
                'api_key': len([s for s in detected_secrets if 'sk-' in s['match']]),
                'hash': len([s for s in detected_secrets if len(s['match']) in [32, 40, 64]]),
                'base64': len([s for s in detected_secrets if '+' in s['match'] or '/' in s['match']]),
                'generic': len([s for s in detected_secrets if s['pattern'] == r'[A-Za-z0-9]{20,}'])
            }
            
            return {
                'success': True,
                'text': text,
                'secrets_detected': len(detected_secrets),
                'secret_types': secret_types,
                'secrets': detected_secrets,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de secrets: {e}")
            return {'success': False, 'error': str(e)}
    
    def analyze_behavior(self, behavioral_data: Dict[str, Any], model_id: str) -> Dict[str, Any]:
        """
        Analyse le comportement avec un modèle entraîné
        
        Args:
            behavioral_data: Données comportementales
            model_id: ID du modèle à utiliser
            
        Returns:
            Résultats d'analyse comportementale
        """
        try:
            if model_id not in self.ml_models:
                return {'success': False, 'error': 'Modèle non trouvé'}
            
            model_info = self.ml_models[model_id]
            
            # Chargement du modèle
            with open(model_info.model_path, 'rb') as f:
                model = pickle.load(f)
            
            # Préparation des données comportementales
            features = self._extract_behavioral_features(behavioral_data)
            
            # Prédiction
            prediction = model.predict([features])[0]
            prediction_proba = model.predict_proba([features])[0] if hasattr(model, 'predict_proba') else None
            
            # Interprétation des résultats
            behavior_analysis = {
                'prediction': prediction,
                'confidence': max(prediction_proba) if prediction_proba is not None else 0.0,
                'risk_level': 'low' if prediction == 0 else 'high',
                'features_analyzed': features,
                'model_used': model_info.name
            }
            
            return {
                'success': True,
                'behavioral_analysis': behavior_analysis,
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse comportementale: {e}")
            return {'success': False, 'error': str(e)}
    
    def _extract_behavioral_features(self, behavioral_data: Dict[str, Any]) -> List[float]:
        """Extrait les caractéristiques comportementales"""
        try:
            features = []
            
            # Extraction des caractéristiques comportementales
            behavioral_analyzer = self.detection_engines.get('behavioral_analyzer', {})
            feature_names = behavioral_analyzer.get('features', [])
            
            for feature_name in feature_names:
                if feature_name in behavioral_data:
                    features.append(float(behavioral_data[feature_name]))
                else:
                    features.append(0.0)  # Valeur par défaut
            
            return features
            
        except Exception as e:
            logger.error(f"Erreur lors de l'extraction des caractéristiques comportementales: {e}")
            return [0.0] * 10  # Features par défaut
    
    def create_ml_pipeline(self, name: str, model_type: ModelType, dataset_id: str) -> MLPipeline:
        """
        Crée un pipeline ML
        
        Args:
            name: Nom du pipeline
            model_type: Type de modèle
            dataset_id: ID du dataset
            
        Returns:
            Pipeline ML créé
        """
        try:
            pipeline_id = hashlib.md5(f"{name}_{datetime.utcnow()}".encode()).hexdigest()[:8]
            
            # Configuration du pipeline
            pipeline_config = {
                'data_preprocessing': {
                    'normalization': True,
                    'feature_selection': True,
                    'data_validation': True
                },
                'feature_engineering': {
                    'feature_extraction': True,
                    'feature_scaling': True,
                    'dimensionality_reduction': True
                },
                'model_training': {
                    'hyperparameter_tuning': True,
                    'cross_validation': True,
                    'model_selection': True
                },
                'evaluation': {
                    'performance_metrics': True,
                    'bias_detection': True,
                    'explainability': True
                },
                'deployment': {
                    'model_serving': True,
                    'a_b_testing': True,
                    'monitoring': True
                }
            }
            
            pipeline = MLPipeline(
                id=pipeline_id,
                name=name,
                model_type=model_type,
                data_preprocessing=pipeline_config['data_preprocessing'],
                feature_engineering=pipeline_config['feature_engineering'],
                model_training=pipeline_config['model_training'],
                evaluation=pipeline_config['evaluation'],
                deployment=pipeline_config['deployment'],
                created_at=datetime.utcnow(),
                status='created'
            )
            
            # Enregistrement du pipeline
            self.ml_pipelines[pipeline_id] = pipeline
            
            logger.info(f"Pipeline ML créé: {pipeline_id} - {name}")
            
            return pipeline
            
        except Exception as e:
            logger.error(f"Erreur lors de la création du pipeline: {e}")
            raise
    
    def get_model_performance(self, model_id: str) -> Dict[str, Any]:
        """Retourne les performances d'un modèle"""
        try:
            if model_id not in self.ml_models:
                return {'error': 'Modèle non trouvé'}
            
            model = self.ml_models[model_id]
            
            return {
                'model_id': model_id,
                'model_name': model.name,
                'model_type': model.model_type.value,
                'version': model.version,
                'accuracy': model.accuracy,
                'precision': model.precision,
                'recall': model.recall,
                'f1_score': model.f1_score,
                'created_at': model.created_at.isoformat(),
                'last_trained': model.last_trained.isoformat(),
                'metadata': model.metadata
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des performances: {e}")
            return {'error': str(e)}
    
    def get_mlops_dashboard(self) -> Dict[str, Any]:
        """Retourne le tableau de bord MLOps"""
        try:
            # Statistiques des modèles
            model_stats = {
                'total_models': len(self.ml_models),
                'models_by_type': {},
                'average_accuracy': 0.0,
                'models_with_high_accuracy': 0
            }
            
            total_accuracy = 0.0
            for model in self.ml_models.values():
                model_type = model.model_type.value
                if model_type not in model_stats['models_by_type']:
                    model_stats['models_by_type'][model_type] = 0
                model_stats['models_by_type'][model_type] += 1
                
                total_accuracy += model.accuracy
                if model.accuracy > 0.8:
                    model_stats['models_with_high_accuracy'] += 1
            
            if len(self.ml_models) > 0:
                model_stats['average_accuracy'] = total_accuracy / len(self.ml_models)
            
            # Statistiques des datasets
            dataset_stats = {
                'total_datasets': len(self.training_datasets),
                'datasets_by_type': {},
                'total_samples': 0
            }
            
            for dataset in self.training_datasets.values():
                dataset_type = dataset.data_type.value
                if dataset_type not in dataset_stats['datasets_by_type']:
                    dataset_stats['datasets_by_type'][dataset_type] = 0
                dataset_stats['datasets_by_type'][dataset_type] += 1
                
                dataset_stats['total_samples'] += dataset.size
            
            # Statistiques des pipelines
            pipeline_stats = {
                'total_pipelines': len(self.ml_pipelines),
                'pipelines_by_status': {},
                'pipelines_by_type': {}
            }
            
            for pipeline in self.ml_pipelines.values():
                status = pipeline.status
                if status not in pipeline_stats['pipelines_by_status']:
                    pipeline_stats['pipelines_by_status'][status] = 0
                pipeline_stats['pipelines_by_status'][status] += 1
                
                pipeline_type = pipeline.model_type.value
                if pipeline_type not in pipeline_stats['pipelines_by_type']:
                    pipeline_stats['pipelines_by_type'][pipeline_type] = 0
                pipeline_stats['pipelines_by_type'][pipeline_type] += 1
            
            return {
                'dashboard_type': 'mlops',
                'generation_timestamp': datetime.utcnow().isoformat(),
                'model_statistics': model_stats,
                'dataset_statistics': dataset_stats,
                'pipeline_statistics': pipeline_stats,
                'mlops_configuration': self.mlops_config,
                'recommendations': [
                    "Surveillance continue des performances des modèles",
                    "Mise à jour régulière des datasets d'entraînement",
                    "Tests A/B pour les nouveaux modèles",
                    "Monitoring de la dérive des données"
                ]
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du tableau de bord: {e}")
            return {'error': str(e)}
