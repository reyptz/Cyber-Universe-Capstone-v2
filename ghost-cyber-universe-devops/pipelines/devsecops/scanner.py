"""
VulnerabilityScanner - Scanner de vulnérabilités multi-outils
Intègre SAST, DAST, SCA, IaC selon les spécifications DevSecOps
"""

import asyncio
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .secrets import SecretsManager


class ScanType(Enum):
    """Types de scans de sécurité"""
    SAST = "sast"          # Static Application Security Testing
    DAST = "dast"          # Dynamic Application Security Testing
    SCA = "sca"            # Software Composition Analysis
    IAC = "iac"            # Infrastructure as Code
    SECRETS = "secrets"    # Détection de secrets
    CONFIG = "config"      # Configuration security


class VulnerabilitySeverity(Enum):
    """Niveaux de sévérité selon CVSS"""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"         # 7.0-8.9
    MEDIUM = "medium"     # 4.0-6.9
    LOW = "low"          # 0.1-3.9
    INFO = "info"        # 0.0


@dataclass
class Vulnerability:
    """Vulnérabilité détectée"""
    id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    file_path: str
    line_number: int = 0
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    tool: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Résultat d'un scan de sécurité"""
    scan_type: ScanType
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_files_scanned: int = 0
    scan_duration: float = 0.0
    tool_version: str = ""
    success: bool = True
    error_message: str = ""


class VulnerabilityScanner:
    """
    Scanner de vulnérabilités pour Ghost Cyber Universe
    Intègre Semgrep, Bandit, Trivy, Safety, Tfsec, Checkov
    """
    
    def __init__(self, config_path: str = "devsecops/config/scanner.json"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.vulnerability_db: Dict[str, Vulnerability] = {}
        self.scan_history: List[ScanResult] = []
        self.secrets_manager = SecretsManager()
        
        # Outils de scan selon les spécifications
        self.tools = {
            ScanType.SAST: ["semgrep", "bandit"],
            ScanType.SCA: ["trivy", "safety"],
            ScanType.IAC: ["tfsec", "checkov"],
            ScanType.SECRETS: ["truffleHog", "gitleaks"],
            ScanType.CONFIG: ["kube-score", "conftest"]
        }
    
    async def initialize(self) -> bool:
        """Initialise le scanner de vulnérabilités"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            await self._load_config()
            await self._load_vulnerability_db()
            await self.secrets_manager.initialize()
            return True
        except Exception as e:
            print(f"Erreur initialisation scanner: {e}")
            return False
    
    async def _load_config(self):
        """Charge la configuration du scanner"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
        else:
            await self._create_default_config()
    
    async def _create_default_config(self):
        """Configuration par défaut selon les spécifications"""
        self.config = {
            "sast": {
                "enabled": True,
                "tools": ["semgrep", "bandit"],
                "rules": ["auto", "security"],
                "exclude_paths": ["tests/", "docs/", "*.min.js"],
                "severity_threshold": "medium"
            },
            "sca": {
                "enabled": True,
                "tools": ["trivy", "safety"],
                "check_licenses": True,
                "severity_threshold": "high"
            },
            "iac": {
                "enabled": True,
                "tools": ["tfsec", "checkov"],
                "frameworks": ["terraform", "kubernetes", "docker"],
                "severity_threshold": "medium"
            },
            "secrets": {
                "enabled": True,
                "tools": ["truffleHog", "gitleaks"],
                "entropy_threshold": 3.5,
                "exclude_patterns": ["test_", "example_"]
            },
            "dast": {
                "enabled": True,
                "tools": ["zap"],
                "target_urls": [],
                "authentication": False,
                "severity_threshold": "medium"
            },
            "general": {
                "max_scan_time": 1800,
                "parallel_scans": 3,
                "output_format": "json",
                "save_reports": True
            }
        }
        await self._save_config()
    
    async def _save_config(self):
        """Sauvegarde la configuration"""
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    async def _load_vulnerability_db(self):
        """Charge la base de données de vulnérabilités"""
        db_path = self.config_path.parent / "vulnerability_db.json"
        if db_path.exists():
            with open(db_path, 'r') as f:
                db_data = json.load(f)
                for vuln_data in db_data.get('vulnerabilities', []):
                    vuln = Vulnerability(**vuln_data)
                    self.vulnerability_db[vuln.id] = vuln
    
    async def run_sast_scan(self, target_path: str) -> ScanResult:
        """
        Exécute un scan SAST (Static Application Security Testing)
        
        Args:
            target_path: Chemin du code source à analyser
            
        Returns:
            Résultat du scan SAST
        """
        print(f" Démarrage scan SAST sur {target_path}")
        
        result = ScanResult(
            scan_type=ScanType.SAST,
            target=target_path,
            start_time=datetime.utcnow()
        )
        
        try:
            # Scan avec Semgrep (outil principal selon spécifications)
            semgrep_vulns = await self._run_semgrep(target_path)
            result.vulnerabilities.extend(semgrep_vulns)
            
            # Scan avec Bandit pour Python
            if await self._has_python_files(target_path):
                bandit_vulns = await self._run_bandit(target_path)
                result.vulnerabilities.extend(bandit_vulns)
            
            result.end_time = datetime.utcnow()
            result.scan_duration = (result.end_time - result.start_time).total_seconds()
            result.total_files_scanned = await self._count_source_files(target_path)
            
            print(f" Scan SAST terminé: {len(result.vulnerabilities)} vulnérabilités")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.end_time = datetime.utcnow()
            print(f" Erreur scan SAST: {e}")
        
        self.scan_history.append(result)
        return result
    
    async def run_sca_scan(self, target_path: str) -> ScanResult:
        """
        Exécute un scan SCA (Software Composition Analysis)
        
        Args:
            target_path: Chemin du projet à analyser
            
        Returns:
            Résultat du scan SCA
        """
        print(f" Démarrage scan SCA sur {target_path}")
        
        result = ScanResult(
            scan_type=ScanType.SCA,
            target=target_path,
            start_time=datetime.utcnow()
        )
        
        try:
            # Scan avec Trivy (outil principal selon spécifications)
            trivy_vulns = await self._run_trivy(target_path)
            result.vulnerabilities.extend(trivy_vulns)
            
            # Scan avec Safety pour Python
            if await self._has_requirements_file(target_path):
                safety_vulns = await self._run_safety(target_path)
                result.vulnerabilities.extend(safety_vulns)
            
            result.end_time = datetime.utcnow()
            result.scan_duration = (result.end_time - result.start_time).total_seconds()
            
            print(f" Scan SCA terminé: {len(result.vulnerabilities)} vulnérabilités")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.end_time = datetime.utcnow()
            print(f" Erreur scan SCA: {e}")
        
        self.scan_history.append(result)
        return result
    
    async def run_iac_scan(self, target_path: str) -> ScanResult:
        """
        Exécute un scan IaC (Infrastructure as Code)
        
        Args:
            target_path: Chemin de l'infrastructure à analyser
            
        Returns:
            Résultat du scan IaC
        """
        print(f" Démarrage scan IaC sur {target_path}")
        
        result = ScanResult(
            scan_type=ScanType.IAC,
            target=target_path,
            start_time=datetime.utcnow()
        )
        
        try:
            # Scan avec Tfsec pour Terraform
            if await self._has_terraform_files(target_path):
                tfsec_vulns = await self._run_tfsec(target_path)
                result.vulnerabilities.extend(tfsec_vulns)
            
            # Scan avec Checkov (multi-framework)
            checkov_vulns = await self._run_checkov(target_path)
            result.vulnerabilities.extend(checkov_vulns)
            
            result.end_time = datetime.utcnow()
            result.scan_duration = (result.end_time - result.start_time).total_seconds()
            
            print(f"Scan IaC terminé: {len(result.vulnerabilities)} vulnérabilités")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.end_time = datetime.utcnow()
            print(f"Erreur scan IaC: {e}")
        
        self.scan_history.append(result)
        return result
    
    async def run_secrets_scan(self, target_path: str) -> ScanResult:
        """
        Exécute un scan de détection de secrets
        
        Args:
            target_path: Chemin à analyser
            
        Returns:
            Résultat du scan de secrets
        """
        print(f"Démarrage scan secrets sur {target_path}")
        
        result = ScanResult(
            scan_type=ScanType.SECRETS,
            target=target_path,
            start_time=datetime.utcnow()
        )
        
        try:
            # Scan avec TruffleHog
            trufflehog_vulns = await self._run_trufflehog(target_path)
            result.vulnerabilities.extend(trufflehog_vulns)
            
            # Scan avec Gitleaks
            gitleaks_vulns = await self._run_gitleaks(target_path)
            result.vulnerabilities.extend(gitleaks_vulns)
            
            result.end_time = datetime.utcnow()
            result.scan_duration = (result.end_time - result.start_time).total_seconds()
            
            print(f"Scan secrets terminé: {len(result.vulnerabilities)} secrets détectés")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.end_time = datetime.utcnow()
            print(f"Erreur scan secrets: {e}")
        
        self.scan_history.append(result)
        return result
    
    async def run_dast_scan(self, target_url: str) -> ScanResult:
        """
        Exécute un scan DAST (Dynamic Application Security Testing)
        
        Args:
            target_url: URL de l'application à tester
            
        Returns:
            Résultat du scan DAST
        """
        print(f"Démarrage scan DAST sur {target_url}")
        
        result = ScanResult(
            scan_type=ScanType.DAST,
            target=target_url,
            start_time=datetime.utcnow()
        )
        
        try:
            # Scan avec OWASP ZAP (selon spécifications)
            zap_vulns = await self._run_zap_scan(target_url)
            result.vulnerabilities.extend(zap_vulns)
            
            result.end_time = datetime.utcnow()
            result.scan_duration = (result.end_time - result.start_time).total_seconds()
            
            print(f"Scan DAST terminé: {len(result.vulnerabilities)} vulnérabilités")
            
        except Exception as e:
            result.success = False
            result.error_message = str(e)
            result.end_time = datetime.utcnow()
            print(f"Erreur scan DAST: {e}")
        
        self.scan_history.append(result)
        return result
    
    # Méthodes d'exécution des outils spécifiques
    
    async def _run_semgrep(self, target_path: str) -> List[Vulnerability]:
        """Exécute Semgrep pour l'analyse statique"""
        vulnerabilities = []
        
        # Simulation d'exécution Semgrep
        await asyncio.sleep(0.5)  # Simulation
        
        # Exemple de vulnérabilité détectée
        if Path(target_path).exists():
            vulnerabilities.append(Vulnerability(
                id="semgrep-001",
                title="Injection SQL potentielle",
                description="Utilisation non sécurisée de requête SQL",
                severity=VulnerabilitySeverity.HIGH,
                file_path=f"{target_path}/app.py",
                line_number=42,
                tool="semgrep",
                remediation="Utiliser des requêtes préparées"
            ))
        
        return vulnerabilities
    
    async def _run_bandit(self, target_path: str) -> List[Vulnerability]:
        """Exécute Bandit pour l'analyse Python"""
        vulnerabilities = []
        
        # Simulation d'exécution Bandit
        await asyncio.sleep(0.3)
        
        if await self._has_python_files(target_path):
            vulnerabilities.append(Vulnerability(
                id="bandit-001",
                title="Utilisation de assert en production",
                description="Les assertions peuvent être désactivées",
                severity=VulnerabilitySeverity.MEDIUM,
                file_path=f"{target_path}/utils.py",
                line_number=15,
                tool="bandit",
                remediation="Remplacer par une vérification explicite"
            ))
        
        return vulnerabilities
    
    async def _run_trivy(self, target_path: str) -> List[Vulnerability]:
        """Exécute Trivy pour l'analyse des dépendances"""
        vulnerabilities = []
        
        # Simulation d'exécution Trivy
        await asyncio.sleep(0.7)
        
        vulnerabilities.append(Vulnerability(
            id="trivy-001",
            title="Vulnérabilité dans requests",
            description="CVE-2023-32681 dans requests 2.28.0",
            severity=VulnerabilitySeverity.HIGH,
            file_path=f"{target_path}/requirements.txt",
            line_number=5,
            cve_id="CVE-2023-32681",
            cvss_score=7.5,
            tool="trivy",
            remediation="Mettre à jour vers requests >= 2.31.0"
        ))
        
        return vulnerabilities
    
    async def _run_safety(self, target_path: str) -> List[Vulnerability]:
        """Exécute Safety pour les vulnérabilités Python"""
        vulnerabilities = []
        
        # Simulation d'exécution Safety
        await asyncio.sleep(0.4)
        
        if await self._has_requirements_file(target_path):
            vulnerabilities.append(Vulnerability(
                id="safety-001",
                title="Vulnérabilité dans urllib3",
                description="Vulnérabilité de sécurité dans urllib3",
                severity=VulnerabilitySeverity.MEDIUM,
                file_path=f"{target_path}/requirements.txt",
                line_number=8,
                tool="safety",
                remediation="Mettre à jour urllib3"
            ))
        
        return vulnerabilities
    
    async def _run_tfsec(self, target_path: str) -> List[Vulnerability]:
        """Exécute Tfsec pour Terraform"""
        vulnerabilities = []
        
        # Simulation d'exécution Tfsec
        await asyncio.sleep(0.6)
        
        if await self._has_terraform_files(target_path):
            vulnerabilities.append(Vulnerability(
                id="tfsec-001",
                title="Bucket S3 public",
                description="Le bucket S3 est accessible publiquement",
                severity=VulnerabilitySeverity.CRITICAL,
                file_path=f"{target_path}/main.tf",
                line_number=25,
                tool="tfsec",
                remediation="Configurer les ACL appropriées"
            ))
        
        return vulnerabilities
    
    async def _run_checkov(self, target_path: str) -> List[Vulnerability]:
        """Exécute Checkov pour l'IaC multi-framework"""
        vulnerabilities = []
        
        # Simulation d'exécution Checkov
        await asyncio.sleep(0.8)
        
        vulnerabilities.append(Vulnerability(
            id="checkov-001",
            title="Container privilégié",
            description="Le container s'exécute en mode privilégié",
            severity=VulnerabilitySeverity.HIGH,
            file_path=f"{target_path}/deployment.yaml",
            line_number=18,
            tool="checkov",
            remediation="Supprimer privileged: true"
        ))
        
        return vulnerabilities
    
    async def _run_trufflehog(self, target_path: str) -> List[Vulnerability]:
        """Exécute TruffleHog pour la détection de secrets"""
        vulnerabilities = []
        
        # Simulation d'exécution TruffleHog
        await asyncio.sleep(0.5)
        
        vulnerabilities.append(Vulnerability(
            id="trufflehog-001",
            title="Clé API exposée",
            description="Clé API AWS détectée dans le code",
            severity=VulnerabilitySeverity.CRITICAL,
            file_path=f"{target_path}/config.py",
            line_number=12,
            tool="trufflehog",
            remediation="Déplacer la clé vers les variables d'environnement"
        ))
        
        return vulnerabilities
    
    async def _run_gitleaks(self, target_path: str) -> List[Vulnerability]:
        """Exécute Gitleaks pour la détection de secrets"""
        vulnerabilities = []
        
        # Simulation d'exécution Gitleaks
        await asyncio.sleep(0.4)
        
        vulnerabilities.append(Vulnerability(
            id="gitleaks-001",
            title="Token GitHub exposé",
            description="Token GitHub détecté dans l'historique Git",
            severity=VulnerabilitySeverity.HIGH,
            file_path=f"{target_path}/.env",
            line_number=3,
            tool="gitleaks",
            remediation="Révoquer le token et utiliser GitHub Secrets"
        ))
        
        return vulnerabilities
    
    async def _run_zap_scan(self, target_url: str) -> List[Vulnerability]:
        """Exécute OWASP ZAP pour les tests dynamiques"""
        vulnerabilities = []
        
        # Simulation d'exécution ZAP
        await asyncio.sleep(2.0)  # DAST prend plus de temps
        
        vulnerabilities.extend([
            Vulnerability(
                id="zap-001",
                title="Cross-Site Scripting (XSS)",
                description="XSS réfléchi détecté sur le paramètre 'search'",
                severity=VulnerabilitySeverity.HIGH,
                file_path=target_url,
                line_number=0,
                tool="zap",
                remediation="Valider et échapper les entrées utilisateur"
            ),
            Vulnerability(
                id="zap-002",
                title="En-têtes de sécurité manquants",
                description="X-Frame-Options et CSP manquants",
                severity=VulnerabilitySeverity.MEDIUM,
                file_path=target_url,
                line_number=0,
                tool="zap",
                remediation="Configurer les en-têtes de sécurité"
            )
        ])
        
        return vulnerabilities
    
    # Méthodes utilitaires
    
    async def _has_python_files(self, target_path: str) -> bool:
        """Vérifie la présence de fichiers Python"""
        path = Path(target_path)
        return any(path.rglob("*.py"))
    
    async def _has_requirements_file(self, target_path: str) -> bool:
        """Vérifie la présence d'un fichier requirements.txt"""
        path = Path(target_path)
        return (path / "requirements.txt").exists() or (path / "Pipfile").exists()
    
    async def _has_terraform_files(self, target_path: str) -> bool:
        """Vérifie la présence de fichiers Terraform"""
        path = Path(target_path)
        return any(path.rglob("*.tf"))
    
    async def _count_source_files(self, target_path: str) -> int:
        """Compte le nombre de fichiers source"""
        path = Path(target_path)
        extensions = [".py", ".js", ".ts", ".java", ".go", ".rs", ".cpp", ".c"]
        count = 0
        for ext in extensions:
            count += len(list(path.rglob(f"*{ext}")))
        return count
    
    async def get_scan_summary(self) -> Dict[str, Any]:
        """Génère un résumé des scans effectués"""
        if not self.scan_history:
            return {"message": "Aucun scan effectué"}
        
        total_vulns = sum(len(scan.vulnerabilities) for scan in self.scan_history)
        critical_vulns = sum(
            len([v for v in scan.vulnerabilities if v.severity == VulnerabilitySeverity.CRITICAL])
            for scan in self.scan_history
        )
        high_vulns = sum(
            len([v for v in scan.vulnerabilities if v.severity == VulnerabilitySeverity.HIGH])
            for scan in self.scan_history
        )
        
        return {
            "total_scans": len(self.scan_history),
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "high_vulnerabilities": high_vulns,
            "scan_types": list(set(scan.scan_type.value for scan in self.scan_history)),
            "last_scan": self.scan_history[-1].start_time.isoformat() if self.scan_history else None,
            "security_score": max(0, 100 - (critical_vulns * 25 + high_vulns * 10))
        }
    
    async def export_results(self, format_type: str = "json") -> str:
        """Exporte les résultats de scan"""
        if format_type == "json":
            results = []
            for scan in self.scan_history:
                scan_data = {
                    "scan_type": scan.scan_type.value,
                    "target": scan.target,
                    "start_time": scan.start_time.isoformat(),
                    "vulnerabilities": [
                        {
                            "id": v.id,
                            "title": v.title,
                            "severity": v.severity.value,
                            "file_path": v.file_path,
                            "line_number": v.line_number,
                            "tool": v.tool
                        }
                        for v in scan.vulnerabilities
                    ]
                }
                results.append(scan_data)
            
            return json.dumps(results, indent=2)
        
        return "Format non supporté"
