"""
Module de détection et rédaction de secrets
"""
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from cryptography.fernet import Fernet
import hashlib
import json
from datetime import datetime
from ..config import config

logger = logging.getLogger(__name__)

class SecretsDetector:
    """Détecteur et rédacteur de secrets"""
    
    def __init__(self):
        """Initialise le détecteur de secrets"""
        try:
            # Patterns de détection de secrets
            self.secret_patterns = {
                'api_key': [
                    r"api[_-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
                    r"apikey\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
                    r"api_key\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?"
                ],
                'password': [
                    r"password\s*[:=]\s*['\"]?([^\s]{8,})['\"]?",
                    r"passwd\s*[:=]\s*['\"]?([^\s]{8,})['\"]?",
                    r"pwd\s*[:=]\s*['\"]?([^\s]{8,})['\"]?"
                ],
                'secret': [
                    r"secret\s*[:=]\s*['\"]?([a-zA-Z0-9]{16,})['\"]?",
                    r"secret_key\s*[:=]\s*['\"]?([a-zA-Z0-9]{16,})['\"]?",
                    r"private_key\s*[:=]\s*['\"]?([a-zA-Z0-9]{16,})['\"]?"
                ],
                'token': [
                    r"token\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
                    r"access_token\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?",
                    r"bearer_token\s*[:=]\s*['\"]?([a-zA-Z0-9]{20,})['\"]?"
                ],
                'private_key': [
                    r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----.*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
                    r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----.*?-----END\s+EC\s+PRIVATE\s+KEY-----"
                ],
                'database_url': [
                    r"(?:mysql|postgresql|mongodb)://[^\s]+",
                    r"database_url\s*[:=]\s*['\"]?([^\s]+)['\"]?"
                ],
                'aws_credentials': [
                    r"aws_access_key_id\s*[:=]\s*['\"]?([A-Z0-9]{20})['\"]?",
                    r"aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
                ],
                'ssh_key': [
                    r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----.*?-----END\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----"
                ]
            }
            
            # Configuration du chiffrement pour les logs
            self.encryption_key = config.ENCRYPTION_KEY.encode()
            self.fernet = Fernet(self.encryption_key)
            
            # Cache des secrets détectés (chiffré)
            self.detected_secrets_cache = {}
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation du détecteur de secrets: {e}")
            raise
    
    def detect_secrets(self, text: str) -> Dict[str, Any]:
        """
        Détecte les secrets dans le texte
        
        Args:
            text: Texte à analyser
            
        Returns:
            Résultat de la détection de secrets
        """
        try:
            detected_secrets = []
            total_confidence = 0
            
            for secret_type, patterns in self.secret_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, text, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        secret_value = match.group(1) if match.groups() else match.group(0)
                        
                        # Calcul de la confiance basé sur le type et la longueur
                        confidence = self._calculate_confidence(secret_type, secret_value)
                        
                        if confidence >= config.SECRETS_DETECTION['confidence_threshold']:
                            detected_secrets.append({
                                'type': secret_type,
                                'value': secret_value,
                                'start': match.start(),
                                'end': match.end(),
                                'confidence': confidence,
                                'pattern': pattern
                            })
                            total_confidence = max(total_confidence, confidence)
            
            return {
                'has_secrets': len(detected_secrets) > 0,
                'secrets_count': len(detected_secrets),
                'secrets': detected_secrets,
                'max_confidence': total_confidence,
                'risk_level': self._get_risk_level(total_confidence)
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la détection de secrets: {e}")
            return {'has_secrets': False, 'secrets_count': 0, 'secrets': [], 'max_confidence': 0, 'risk_level': 'low'}
    
    def redact_secrets(self, text: str, detected_secrets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Rédige les secrets détectés dans le texte
        
        Args:
            text: Texte original
            detected_secrets: Liste des secrets détectés
            
        Returns:
            Texte rédigé et métadonnées
        """
        try:
            redacted_text = text
            redaction_log = []
            
            # Tri par position décroissante pour éviter les décalages
            sorted_secrets = sorted(detected_secrets, key=lambda x: x['start'], reverse=True)
            
            for secret in sorted_secrets:
                # Génération d'un placeholder
                placeholder = self._generate_placeholder(secret['type'])
                
                # Remplacement dans le texte
                redacted_text = (
                    redacted_text[:secret['start']] + 
                    placeholder + 
                    redacted_text[secret['end']:]
                )
                
                # Enregistrement de la rédaction
                redaction_log.append({
                    'type': secret['type'],
                    'original_length': secret['end'] - secret['start'],
                    'placeholder': placeholder,
                    'confidence': secret['confidence']
                })
            
            return {
                'redacted_text': redacted_text,
                'original_text': text,
                'redaction_log': redaction_log,
                'secrets_redacted': len(redaction_log)
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la rédaction de secrets: {e}")
            return {'redacted_text': text, 'original_text': text, 'redaction_log': [], 'secrets_redacted': 0}
    
    def process_text_with_secrets(self, text: str) -> Dict[str, Any]:
        """
        Traite un texte complet : détection et rédaction de secrets
        
        Args:
            text: Texte à traiter
            
        Returns:
            Résultat complet du traitement
        """
        try:
            # Détection des secrets
            detection_result = self.detect_secrets(text)
            
            # Rédaction si des secrets sont détectés
            if detection_result['has_secrets']:
                redaction_result = self.redact_secrets(text, detection_result['secrets'])
                
                # Log chiffré des secrets détectés
                self._log_detected_secrets(detection_result['secrets'])
                
                return {
                    'processed_text': redaction_result['redacted_text'],
                    'original_text': text,
                    'secrets_detected': True,
                    'detection_result': detection_result,
                    'redaction_result': redaction_result,
                    'risk_level': detection_result['risk_level']
                }
            else:
                return {
                    'processed_text': text,
                    'original_text': text,
                    'secrets_detected': False,
                    'detection_result': detection_result,
                    'redaction_result': None,
                    'risk_level': 'low'
                }
                
        except Exception as e:
            logger.error(f"Erreur lors du traitement des secrets: {e}")
            return {
                'processed_text': text,
                'original_text': text,
                'secrets_detected': False,
                'error': str(e),
                'risk_level': 'high'
            }
    
    def validate_secret_removal(self, original_text: str, processed_text: str) -> Dict[str, Any]:
        """
        Valide que les secrets ont été correctement supprimés
        
        Args:
            original_text: Texte original
            processed_text: Texte traité
            
        Returns:
            Résultat de la validation
        """
        try:
            # Vérification que le texte traité ne contient plus de secrets
            remaining_secrets = self.detect_secrets(processed_text)
            
            # Calcul du pourcentage de réduction
            original_length = len(original_text)
            processed_length = len(processed_text)
            length_reduction = (original_length - processed_length) / original_length if original_length > 0 else 0
            
            return {
                'secrets_removed': not remaining_secrets['has_secrets'],
                'remaining_secrets_count': remaining_secrets['secrets_count'],
                'length_reduction_percent': length_reduction * 100,
                'validation_passed': not remaining_secrets['has_secrets']
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation: {e}")
            return {
                'secrets_removed': False,
                'remaining_secrets_count': -1,
                'length_reduction_percent': 0,
                'validation_passed': False,
                'error': str(e)
            }
    
    def _calculate_confidence(self, secret_type: str, secret_value: str) -> float:
        """Calcule la confiance de détection d'un secret"""
        base_confidence = 0.5
        
        # Ajustement basé sur le type
        type_confidence = {
            'api_key': 0.8,
            'password': 0.7,
            'secret': 0.9,
            'token': 0.8,
            'private_key': 0.95,
            'database_url': 0.6,
            'aws_credentials': 0.9,
            'ssh_key': 0.95
        }
        
        base_confidence = type_confidence.get(secret_type, 0.5)
        
        # Ajustement basé sur la longueur
        length = len(secret_value)
        if length >= 32:
            base_confidence += 0.2
        elif length >= 16:
            base_confidence += 0.1
        
        # Ajustement basé sur la complexité
        if re.search(r'[A-Z]', secret_value) and re.search(r'[a-z]', secret_value) and re.search(r'[0-9]', secret_value):
            base_confidence += 0.1
        
        return min(base_confidence, 1.0)
    
    def _generate_placeholder(self, secret_type: str) -> str:
        """Génère un placeholder pour un type de secret"""
        placeholders = {
            'api_key': '[API_KEY_REDACTED]',
            'password': '[PASSWORD_REDACTED]',
            'secret': '[SECRET_REDACTED]',
            'token': '[TOKEN_REDACTED]',
            'private_key': '[PRIVATE_KEY_REDACTED]',
            'database_url': '[DATABASE_URL_REDACTED]',
            'aws_credentials': '[AWS_CREDENTIALS_REDACTED]',
            'ssh_key': '[SSH_KEY_REDACTED]'
        }
        return placeholders.get(secret_type, '[SECRET_REDACTED]')
    
    def _get_risk_level(self, confidence: float) -> str:
        """Détermine le niveau de risque basé sur la confiance"""
        if confidence >= 0.9:
            return 'critical'
        elif confidence >= 0.7:
            return 'high'
        elif confidence >= 0.5:
            return 'medium'
        else:
            return 'low'
    
    def _log_detected_secrets(self, secrets: List[Dict[str, Any]]):
        """Enregistre les secrets détectés de manière chiffrée"""
        try:
            log_entry = {
                'timestamp': datetime.utcnow().isoformat(),
                'secrets_count': len(secrets),
                'secret_types': [s['type'] for s in secrets],
                'confidences': [s['confidence'] for s in secrets]
            }
            
            # Chiffrement du log
            log_json = json.dumps(log_entry).encode()
            encrypted_log = self.fernet.encrypt(log_json)
            
            # Stockage dans le cache (en production, utiliser une base de données sécurisée)
            log_id = hashlib.sha256(log_json).hexdigest()
            self.detected_secrets_cache[log_id] = encrypted_log
            
            logger.warning(f"Secrets détectés et loggés: {len(secrets)} secrets de types {log_entry['secret_types']}")
            
        except Exception as e:
            logger.error(f"Erreur lors du logging des secrets: {e}")
