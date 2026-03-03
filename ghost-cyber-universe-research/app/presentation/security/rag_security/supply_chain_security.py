"""
Sécurité Supply Chain IA
Vérification d'intégrité des modèles, génération SBOM, sandboxing et politiques réseau
"""

import os
import json
import hashlib
import logging
import subprocess
import tempfile
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import requests
import yaml
from pathlib import Path
import docker
from ..config import config

logger = logging.getLogger(__name__)

class ComponentType(Enum):
    """Types de composants"""
    MODEL = "model"
    DATASET = "dataset"
    LIBRARY = "library"
    FRAMEWORK = "framework"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"

class RiskLevel(Enum):
    """Niveaux de risque"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VerificationStatus(Enum):
    """Statuts de vérification"""
    VERIFIED = "verified"
    FAILED = "failed"
    PENDING = "pending"
    UNKNOWN = "unknown"

@dataclass
class Component:
    """Composant de la chaîne d'approvisionnement"""
    name: str
    version: str
    component_type: ComponentType
    source: str
    integrity_hash: str
    verification_status: VerificationStatus
    risk_level: RiskLevel
    vulnerabilities: List[Dict[str, Any]]
    dependencies: List[str]
    metadata: Dict[str, Any]

@dataclass
class SBOMEntry:
    """Entrée SBOM"""
    component: Component
    license: str
    author: str
    created_at: datetime
    last_updated: datetime
    security_advisories: List[Dict[str, Any]]

@dataclass
class SandboxEnvironment:
    """Environnement sandbox"""
    id: str
    name: str
    image: str
    network_policies: List[Dict[str, Any]]
    resource_limits: Dict[str, Any]
    security_context: Dict[str, Any]
    created_at: datetime
    status: str

class SupplyChainSecurity:
    """Sécurité de la chaîne d'approvisionnement IA"""
    
    def __init__(self):
        """Initialise la sécurité de la chaîne d'approvisionnement"""
        try:
            # Base de données des composants
            self.components = {}
            self.sbom_entries = []
            self.sandbox_environments = {}
            
            # Clients pour les services externes
            self.docker_client = docker.from_env()
            self._initialize_verification_tools()
            
            # Configuration des politiques de sécurité
            self._initialize_security_policies()
            
            # Base de données de vulnérabilités
            self._initialize_vulnerability_database()
            
            logger.info("Sécurité de la chaîne d'approvisionnement initialisée")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation: {e}")
            raise
    
    def _initialize_verification_tools(self):
        """Initialise les outils de vérification"""
        self.verification_tools = {
            'hash_verification': self._verify_hash_integrity,
            'signature_verification': self._verify_digital_signature,
            'vulnerability_scan': self._scan_vulnerabilities,
            'license_check': self._check_license_compliance,
            'dependency_analysis': self._analyze_dependencies
        }
    
    def _initialize_security_policies(self):
        """Initialise les politiques de sécurité"""
        self.security_policies = {
            'allowed_licenses': [
                'MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause',
                'ISC', 'Unlicense', 'CC0-1.0'
            ],
            'blocked_licenses': [
                'GPL-3.0', 'AGPL-3.0', 'Copyleft', 'Proprietary'
            ],
            'trusted_sources': [
                'pypi.org', 'huggingface.co', 'github.com',
                'tensorflow.org', 'pytorch.org'
            ],
            'blocked_sources': [
                'unknown-source', 'unverified-repo'
            ],
            'max_vulnerability_score': 7.0,
            'required_verification_level': 'high'
        }
    
    def _initialize_vulnerability_database(self):
        """Initialise la base de données de vulnérabilités"""
        self.vulnerability_sources = {
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'osv': 'https://osv.dev/api/v1/query',
            'github': 'https://api.github.com/advisories'
        }
        
        # Cache local des vulnérabilités
        self.vulnerability_cache = {}
    
    def verify_model_integrity(self, model_name: str, model_path: str = None) -> Dict[str, Any]:
        """
        Vérifie l'intégrité d'un modèle
        
        Args:
            model_name: Nom du modèle
            model_path: Chemin vers le modèle (optionnel)
            
        Returns:
            Résultat de la vérification d'intégrité
        """
        try:
            verification_result = {
                'model_name': model_name,
                'verified': False,
                'verification_methods': [],
                'integrity_checks': {},
                'security_issues': [],
                'recommendations': []
            }
            
            # Vérification du hash d'intégrité
            if model_path and os.path.exists(model_path):
                file_hash = self._calculate_file_hash(model_path)
                verification_result['integrity_checks']['file_hash'] = file_hash
                verification_result['verification_methods'].append('hash_verification')
            
            # Vérification de la signature numérique
            signature_result = self._verify_digital_signature(model_name, model_path)
            verification_result['integrity_checks']['signature'] = signature_result
            if signature_result['verified']:
                verification_result['verification_methods'].append('signature_verification')
            
            # Vérification des vulnérabilités
            vulnerability_result = self._scan_vulnerabilities(model_name)
            verification_result['integrity_checks']['vulnerabilities'] = vulnerability_result
            if vulnerability_result['vulnerabilities_found']:
                verification_result['security_issues'].extend(vulnerability_result['vulnerabilities'])
            
            # Vérification de la licence
            license_result = self._check_license_compliance(model_name)
            verification_result['integrity_checks']['license'] = license_result
            if not license_result['compliant']:
                verification_result['security_issues'].append({
                    'type': 'license_compliance',
                    'severity': 'medium',
                    'description': f"Licence non conforme: {license_result['license']}"
                })
            
            # Détermination du statut de vérification
            verification_result['verified'] = (
                len(verification_result['verification_methods']) >= 2 and
                len(verification_result['security_issues']) == 0
            )
            
            # Génération des recommandations
            verification_result['recommendations'] = self._generate_verification_recommendations(verification_result)
            
            return verification_result
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification d'intégrité: {e}")
            return {
                'model_name': model_name,
                'verified': False,
                'error': str(e)
            }
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calcule le hash d'un fichier"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Erreur lors du calcul du hash: {e}")
            return ""
    
    def _verify_digital_signature(self, model_name: str, model_path: str = None) -> Dict[str, Any]:
        """Vérifie la signature numérique"""
        try:
            # Simulation de vérification de signature
            # En production, utiliser des outils comme GPG ou des certificats X.509
            
            signature_result = {
                'verified': False,
                'signature_method': 'unknown',
                'signer': 'unknown',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Vérification de la présence d'une signature
            if model_path and os.path.exists(f"{model_path}.sig"):
                signature_result['verified'] = True
                signature_result['signature_method'] = 'gpg'
                signature_result['signer'] = 'verified_signer'
            elif model_name in ['sentence-transformers/all-MiniLM-L6-v2', 'bert-base-uncased']:
                # Modèles de confiance connus
                signature_result['verified'] = True
                signature_result['signature_method'] = 'trusted_source'
                signature_result['signer'] = 'huggingface'
            
            return signature_result
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de signature: {e}")
            return {'verified': False, 'error': str(e)}
    
    def _scan_vulnerabilities(self, model_name: str) -> Dict[str, Any]:
        """Scanne les vulnérabilités"""
        try:
            vulnerabilities = []
            
            # Simulation de scan de vulnérabilités
            # En production, utiliser des outils comme Trivy, Snyk, ou des APIs de sécurité
            
            # Vérification des dépendances connues
            if 'tensorflow' in model_name.lower():
                vulnerabilities.append({
                    'cve_id': 'CVE-2023-1234',
                    'severity': 'medium',
                    'description': 'Vulnerability in TensorFlow dependency',
                    'score': 5.5
                })
            
            # Vérification des versions obsolètes
            if 'old-model' in model_name.lower():
                vulnerabilities.append({
                    'cve_id': 'CVE-2023-5678',
                    'severity': 'high',
                    'description': 'Outdated model version with known vulnerabilities',
                    'score': 7.2
                })
            
            return {
                'vulnerabilities_found': len(vulnerabilities) > 0,
                'vulnerabilities': vulnerabilities,
                'scan_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du scan de vulnérabilités: {e}")
            return {'vulnerabilities_found': False, 'vulnerabilities': [], 'error': str(e)}
    
    def _check_license_compliance(self, model_name: str) -> Dict[str, Any]:
        """Vérifie la conformité des licences"""
        try:
            # Simulation de vérification de licence
            # En production, utiliser des outils comme FOSSA, Snyk, ou des APIs de licence
            
            license_info = {
                'license': 'MIT',
                'compliant': True,
                'risk_level': 'low',
                'restrictions': []
            }
            
            # Vérification des licences autorisées
            if license_info['license'] in self.security_policies['allowed_licenses']:
                license_info['compliant'] = True
            elif license_info['license'] in self.security_policies['blocked_licenses']:
                license_info['compliant'] = False
                license_info['risk_level'] = 'high'
                license_info['restrictions'].append('Licence bloquée par la politique de sécurité')
            
            return license_info
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de licence: {e}")
            return {'license': 'unknown', 'compliant': False, 'error': str(e)}
    
    def generate_sbom(self, project_path: str) -> Dict[str, Any]:
        """
        Génère un SBOM (Software Bill of Materials)
        
        Args:
            project_path: Chemin vers le projet
            
        Returns:
            SBOM généré
        """
        try:
            sbom = {
                'metadata': {
                    'generated_at': datetime.utcnow().isoformat(),
                    'generator': 'SupplyChainSecurity',
                    'version': '1.0.0',
                    'project_path': project_path
                },
                'components': [],
                'dependencies': [],
                'vulnerabilities': [],
                'licenses': [],
                'security_summary': {}
            }
            
            # Analyse des composants Python
            python_components = self._analyze_python_components(project_path)
            sbom['components'].extend(python_components)
            
            # Analyse des modèles ML
            ml_components = self._analyze_ml_components(project_path)
            sbom['components'].extend(ml_components)
            
            # Analyse des dépendances
            dependencies = self._analyze_dependencies(project_path)
            sbom['dependencies'].extend(dependencies)
            
            # Analyse des vulnérabilités
            vulnerabilities = self._analyze_vulnerabilities(sbom['components'])
            sbom['vulnerabilities'].extend(vulnerabilities)
            
            # Analyse des licences
            licenses = self._analyze_licenses(sbom['components'])
            sbom['licenses'].extend(licenses)
            
            # Résumé de sécurité
            sbom['security_summary'] = self._generate_security_summary(sbom)
            
            return {
                'sbom_generated': True,
                'sbom': sbom,
                'components_count': len(sbom['components']),
                'vulnerabilities_count': len(sbom['vulnerabilities']),
                'generation_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du SBOM: {e}")
            return {'sbom_generated': False, 'error': str(e)}
    
    def _analyze_python_components(self, project_path: str) -> List[Dict[str, Any]]:
        """Analyse les composants Python"""
        components = []
        
        try:
            # Lecture du fichier requirements.txt
            requirements_file = os.path.join(project_path, 'requirements.txt')
            if os.path.exists(requirements_file):
                with open(requirements_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Parsing de la ligne requirements.txt
                            if '==' in line:
                                name, version = line.split('==', 1)
                            elif '>=' in line:
                                name, version = line.split('>=', 1)
                            else:
                                name, version = line, 'unknown'
                            
                            component = {
                                'name': name.strip(),
                                'version': version.strip(),
                                'type': 'python_package',
                                'source': 'pypi',
                                'license': 'unknown',
                                'vulnerabilities': [],
                                'dependencies': []
                            }
                            components.append(component)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des composants Python: {e}")
        
        return components
    
    def _analyze_ml_components(self, project_path: str) -> List[Dict[str, Any]]:
        """Analyse les composants ML"""
        components = []
        
        try:
            # Recherche de modèles dans le projet
            model_extensions = ['.pkl', '.joblib', '.h5', '.pb', '.onnx', '.pt', '.pth']
            
            for root, dirs, files in os.walk(project_path):
                for file in files:
                    if any(file.endswith(ext) for ext in model_extensions):
                        model_path = os.path.join(root, file)
                        model_hash = self._calculate_file_hash(model_path)
                        
                        component = {
                            'name': file,
                            'version': 'unknown',
                            'type': 'ml_model',
                            'source': 'local',
                            'license': 'unknown',
                            'integrity_hash': model_hash,
                            'vulnerabilities': [],
                            'dependencies': []
                        }
                        components.append(component)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des composants ML: {e}")
        
        return components
    
    def _analyze_dependencies(self, project_path: str) -> List[Dict[str, Any]]:
        """Analyse les dépendances"""
        dependencies = []
        
        try:
            # Analyse des dépendances Python
            if os.path.exists(os.path.join(project_path, 'requirements.txt')):
                dependencies.append({
                    'type': 'python_dependencies',
                    'file': 'requirements.txt',
                    'dependencies': self._parse_requirements_file(project_path)
                })
            
            # Analyse des dépendances Node.js
            if os.path.exists(os.path.join(project_path, 'package.json')):
                dependencies.append({
                    'type': 'nodejs_dependencies',
                    'file': 'package.json',
                    'dependencies': self._parse_package_json(project_path)
                })
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des dépendances: {e}")
        
        return dependencies
    
    def _parse_requirements_file(self, project_path: str) -> List[str]:
        """Parse le fichier requirements.txt"""
        dependencies = []
        
        try:
            requirements_file = os.path.join(project_path, 'requirements.txt')
            if os.path.exists(requirements_file):
                with open(requirements_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                                dependencies.append(line)
        except Exception as e:
            logger.error(f"Erreur lors du parsing de requirements.txt: {e}")
        
        return dependencies
    
    def _parse_package_json(self, project_path: str) -> List[str]:
        """Parse le fichier package.json"""
        dependencies = []
        
        try:
            package_json_file = os.path.join(project_path, 'package.json')
            if os.path.exists(package_json_file):
                with open(package_json_file, 'r') as f:
                    package_data = json.load(f)
                    dependencies.extend(package_data.get('dependencies', {}).keys())
                    dependencies.extend(package_data.get('devDependencies', {}).keys())
        except Exception as e:
            logger.error(f"Erreur lors du parsing de package.json: {e}")
        
        return dependencies
    
    def _analyze_vulnerabilities(self, components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyse les vulnérabilités des composants"""
        vulnerabilities = []
        
        try:
            for component in components:
                # Simulation de scan de vulnérabilités
                if component['name'] in ['tensorflow', 'torch', 'numpy']:
                    vulnerabilities.append({
                        'component': component['name'],
                        'cve_id': f"CVE-2023-{hash(component['name']) % 10000}",
                        'severity': 'medium',
                        'description': f"Vulnerability in {component['name']}",
                        'score': 5.5
                    })
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des vulnérabilités: {e}")
        
        return vulnerabilities
    
    def _analyze_licenses(self, components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyse les licences des composants"""
        licenses = []
        
        try:
            for component in components:
                license_info = {
                    'component': component['name'],
                    'license': component.get('license', 'unknown'),
                    'compliant': component.get('license', 'unknown') in self.security_policies['allowed_licenses']
                }
                licenses.append(license_info)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des licences: {e}")
        
        return licenses
    
    def _generate_security_summary(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé de sécurité"""
        try:
            total_components = len(sbom['components'])
            total_vulnerabilities = len(sbom['vulnerabilities'])
            compliant_licenses = sum(1 for lic in sbom['licenses'] if lic['compliant'])
            
            return {
                'total_components': total_components,
                'total_vulnerabilities': total_vulnerabilities,
                'compliant_licenses': compliant_licenses,
                'security_score': max(0, 100 - (total_vulnerabilities * 10)),
                'risk_level': 'high' if total_vulnerabilities > 5 else 'medium' if total_vulnerabilities > 2 else 'low'
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du résumé de sécurité: {e}")
            return {'error': str(e)}
    
    def setup_sandbox_environment(self, name: str, image: str = "python:3.9-slim") -> Dict[str, Any]:
        """
        Configure un environnement sandbox
        
        Args:
            name: Nom de l'environnement sandbox
            image: Image Docker à utiliser
        
        Returns:
            Résultat de la configuration du sandbox
        """
        try:
            sandbox_id = hashlib.md5(f"{name}_{datetime.utcnow()}".encode()).hexdigest()[:8]
            
            # Configuration du sandbox
            sandbox_config = {
                'id': sandbox_id,
                'name': name,
                'image': image,
                'network_policies': [
                    {
                        'type': 'deny_all',
                        'description': 'Deny all outbound connections by default'
                    },
                    {
                        'type': 'allow_https',
                        'description': 'Allow HTTPS connections to trusted sources'
                    }
                ],
                'resource_limits': {
                    'memory': '512Mi',
                    'cpu': '500m',
                    'storage': '1Gi'
                },
                'security_context': {
                    'run_as_non_root': True,
                    'read_only_root_filesystem': True,
                    'allow_privilege_escalation': False
                },
                'created_at': datetime.utcnow(),
                'status': 'creating'
            }
            
            # Création du conteneur sandbox
            try:
                container = self.docker_client.containers.create(
                    image=image,
                    name=f"sandbox-{sandbox_id}",
                    detach=True,
                    mem_limit='512m',
                    cpu_quota=50000,
                    security_opt=['no-new-privileges:true'],
                    read_only=True
                )
                
                sandbox_config['container_id'] = container.id
                sandbox_config['status'] = 'running'
                
                # Ajout au registre des sandboxes
                self.sandbox_environments[sandbox_id] = sandbox_config
            
                return {
                    'sandbox_configured': True,
                    'sandbox_id': sandbox_id,
                    'container_id': container.id,
                    'status': 'running',
                    'configuration': sandbox_config
                }
                
            except Exception as e:
                logger.error(f"Erreur lors de la création du conteneur sandbox: {e}")
                return {
                    'sandbox_configured': False,
                    'error': str(e)
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la configuration du sandbox: {e}")
            return {'sandbox_configured': False, 'error': str(e)}
    
    def monitor_supply_chain_risks(self) -> Dict[str, Any]:
        """Surveille les risques de la chaîne d'approvisionnement"""
        try:
            risk_analysis = {
                'total_components': len(self.components),
                'high_risk_components': 0,
                'vulnerabilities_detected': 0,
                'license_violations': 0,
                'integrity_failures': 0,
                'recommendations': []
            }
            
            # Analyse des composants
            for component_id, component in self.components.items():
                if component.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
                    risk_analysis['high_risk_components'] += 1
                
                if component.verification_status == VerificationStatus.FAILED:
                    risk_analysis['integrity_failures'] += 1
                
                risk_analysis['vulnerabilities_detected'] += len(component.vulnerabilities)
            
            # Génération des recommandations
            if risk_analysis['high_risk_components'] > 0:
                risk_analysis['recommendations'].append("Composants à haut risque détectés - Révision recommandée")
            
            if risk_analysis['vulnerabilities_detected'] > 0:
                risk_analysis['recommendations'].append("Vulnérabilités détectées - Mise à jour recommandée")
            
            if risk_analysis['integrity_failures'] > 0:
                risk_analysis['recommendations'].append("Échecs d'intégrité détectés - Vérification recommandée")
            
            return risk_analysis
            
        except Exception as e:
            logger.error(f"Erreur lors de la surveillance des risques: {e}")
            return {'error': str(e)}
    
    def _generate_verification_recommendations(self, verification_result: Dict[str, Any]) -> List[str]:
        """Génère des recommandations de vérification"""
        recommendations = []
        
        try:
            if not verification_result['verified']:
                recommendations.append("Vérification d'intégrité échouée - Révision recommandée")
            
            if verification_result['security_issues']:
                recommendations.append("Problèmes de sécurité détectés - Correction recommandée")
            
            if len(verification_result['verification_methods']) < 2:
                recommendations.append("Méthodes de vérification insuffisantes - Ajout recommandé")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération des recommandations: {e}")
            return ["Erreur lors de la génération des recommandations"]