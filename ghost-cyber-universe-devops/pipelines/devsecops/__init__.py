"""
DevSecOps - Module de sécurité dans le cycle de développement

Ce module implémente :
- Pipeline CI/CD sécurisé
- Analyse statique et dynamique du code
- Gestion des secrets
- Scan de vulnérabilités
- Politiques de sécurité
- Intégration continue sécurisée
"""

__version__ = "1.0.0"
__author__ = "Ghost Cyber Universe Team"

from .pipeline import SecurePipeline
from .secrets import SecretsManager
from .scanner import VulnerabilityScanner
from .policies import SecurityPolicies

__all__ = [
    "SecurePipeline",
    "SecretsManager", 
    "VulnerabilityScanner",
    "SecurityPolicies"
]
