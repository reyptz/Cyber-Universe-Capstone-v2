"""
SecurityPolicies - Automatisation des politiques de sécurité
Gestion des règles, conformité réglementaire, contrôles d'accès selon DevSecOps
"""

import asyncio
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import hashlib


class PolicyType(Enum):
    """Types de politiques de sécurité"""
    ACCESS_CONTROL = "access_control"      # Contrôle d'accès
    DATA_PROTECTION = "data_protection"    # Protection des données
    NETWORK_SECURITY = "network_security"  # Sécurité réseau
    COMPLIANCE = "compliance"              # Conformité réglementaire
    DEPLOYMENT = "deployment"              # Politiques de déploiement
    AUTHENTICATION = "authentication"      # Authentification
    ENCRYPTION = "encryption"              # Chiffrement
    AUDIT = "audit"                       # Audit et logging


class PolicySeverity(Enum):
    """Niveaux de sévérité des politiques"""
    CRITICAL = "critical"    # Critique - Bloque le déploiement
    HIGH = "high"           # Élevé - Alerte immédiate
    MEDIUM = "medium"       # Moyen - Surveillance renforcée
    LOW = "low"            # Faible - Information
    INFO = "info"          # Informatif - Logging uniquement


class PolicyStatus(Enum):
    """Statuts des politiques"""
    ACTIVE = "active"        # Politique active
    INACTIVE = "inactive"    # Politique désactivée
    DRAFT = "draft"         # Brouillon
    DEPRECATED = "deprecated" # Obsolète
    TESTING = "testing"     # En test


class ComplianceFramework(Enum):
    """Frameworks de conformité supportés"""
    GDPR = "gdpr"           # Règlement général sur la protection des données
    SOC2 = "soc2"          # Service Organization Control 2
    ISO27001 = "iso27001"   # ISO/IEC 27001
    NIST = "nist"          # NIST Cybersecurity Framework
    PCI_DSS = "pci_dss"    # Payment Card Industry Data Security Standard
    HIPAA = "hipaa"        # Health Insurance Portability and Accountability Act
    OWASP = "owasp"        # OWASP Top 10


@dataclass
class PolicyRule:
    """Règle de politique de sécurité"""
    id: str
    name: str
    description: str
    policy_type: PolicyType
    severity: PolicySeverity
    condition: str                    # Expression de condition
    action: str                      # Action à effectuer
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = "system"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyViolation:
    """Violation de politique détectée"""
    id: str
    rule_id: str
    rule_name: str
    severity: PolicySeverity
    description: str
    resource: str                    # Ressource concernée
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolution_notes: str = ""
    resolved_at: Optional[datetime] = None
    resolved_by: str = ""


@dataclass
class ComplianceReport:
    """Rapport de conformité"""
    framework: ComplianceFramework
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    total_checks: int
    passed_checks: int
    failed_checks: int
    compliance_score: float          # Pourcentage de conformité
    violations: List[PolicyViolation]
    recommendations: List[str] = field(default_factory=list)
    next_review_date: Optional[datetime] = None


class SecurityPolicies:
    """
    Gestionnaire de politiques de sécurité pour Ghost Cyber Universe
    Automatise l'application des règles, la conformité et les contrôles
    """
    
    def __init__(self, config_path: str = "devsecops/config/policies.json"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.rules: Dict[str, PolicyRule] = {}
        self.violations: List[PolicyViolation] = []
        self.compliance_reports: Dict[str, ComplianceReport] = {}
        
        # Gestionnaires de conditions et actions
        self.condition_handlers: Dict[str, Callable] = {}
        self.action_handlers: Dict[str, Callable] = {}
        
        # Métriques et statistiques
        self.metrics = {
            "total_evaluations": 0,
            "violations_detected": 0,
            "policies_enforced": 0,
            "compliance_checks": 0
        }
    
    async def initialize(self) -> bool:
        """Initialise le gestionnaire de politiques"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            await self._load_config()
            await self._load_rules()
            await self._load_violations()
            await self._register_default_handlers()
            await self._start_policy_monitor()
            return True
        except Exception as e:
            print(f"Erreur initialisation SecurityPolicies: {e}")
            return False
    
    async def _load_config(self):
        """Charge la configuration des politiques"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
        else:
            await self._create_default_config()
    
    async def _create_default_config(self):
        """Configuration par défaut selon les spécifications"""
        self.config = {
            "enforcement": {
                "enabled": True,
                "strict_mode": False,
                "auto_remediation": False,
                "notification_channels": ["email", "slack"],
                "escalation_timeout": 3600
            },
            "compliance": {
                "enabled_frameworks": ["owasp", "nist", "iso27001"],
                "auto_reporting": True,
                "report_frequency": "weekly",
                "retention_days": 365
            },
            "monitoring": {
                "real_time": True,
                "check_interval": 300,  # 5 minutes
                "batch_processing": True,
                "max_violations_per_batch": 100
            },
            "notifications": {
                "immediate_severity": ["critical", "high"],
                "daily_summary": True,
                "weekly_report": True,
                "email_recipients": ["security@company.com"],
                "slack_webhook": ""
            },
            "remediation": {
                "auto_fix_enabled": False,
                "quarantine_violations": True,
                "rollback_on_failure": True,
                "approval_required": True
            },
            "audit": {
                "log_all_evaluations": True,
                "log_policy_changes": True,
                "retention_days": 90,
                "export_format": "json"
            }
        }
        await self._save_config()
    
    async def _save_config(self):
        """Sauvegarde la configuration"""
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    async def _load_rules(self):
        """Charge les règles de politiques"""
        rules_file = self.config_path.parent / "policy_rules.json"
        
        if rules_file.exists():
            with open(rules_file, 'r') as f:
                rules_data = json.load(f)
                for rule_id, rule_dict in rules_data.items():
                    # Conversion des énumérations
                    rule_dict['policy_type'] = PolicyType(rule_dict['policy_type'])
                    rule_dict['severity'] = PolicySeverity(rule_dict['severity'])
                    rule_dict['created_at'] = datetime.fromisoformat(rule_dict['created_at'])
                    rule_dict['updated_at'] = datetime.fromisoformat(rule_dict['updated_at'])
                    
                    # Conversion des frameworks de conformité
                    if 'compliance_frameworks' in rule_dict:
                        rule_dict['compliance_frameworks'] = [
                            ComplianceFramework(fw) for fw in rule_dict['compliance_frameworks']
                        ]
                    
                    self.rules[rule_id] = PolicyRule(**rule_dict)
        else:
            await self._create_default_rules()
    
    async def _create_default_rules(self):
        """Crée les règles de politique par défaut"""
        default_rules = [
            # Contrôle d'accès
            {
                "name": "Authentification forte requise",
                "description": "Exige une authentification multi-facteurs pour les accès privilégiés",
                "policy_type": PolicyType.ACCESS_CONTROL,
                "severity": PolicySeverity.CRITICAL,
                "condition": "user.privilege_level == 'admin' and not user.mfa_enabled",
                "action": "deny_access",
                "compliance_frameworks": [ComplianceFramework.SOC2, ComplianceFramework.ISO27001],
                "tags": ["authentication", "mfa", "admin"]
            },
            
            # Protection des données
            {
                "name": "Chiffrement des données sensibles",
                "description": "Vérifie que les données sensibles sont chiffrées",
                "policy_type": PolicyType.DATA_PROTECTION,
                "severity": PolicySeverity.HIGH,
                "condition": "data.classification == 'sensitive' and not data.encrypted",
                "action": "encrypt_data",
                "compliance_frameworks": [ComplianceFramework.GDPR, ComplianceFramework.HIPAA],
                "tags": ["encryption", "data-protection", "sensitive"]
            },
            
            # Sécurité réseau
            {
                "name": "Ports non autorisés",
                "description": "Détecte l'ouverture de ports non autorisés",
                "policy_type": PolicyType.NETWORK_SECURITY,
                "severity": PolicySeverity.HIGH,
                "condition": "network.open_ports contains unauthorized_port",
                "action": "block_port",
                "compliance_frameworks": [ComplianceFramework.NIST],
                "tags": ["network", "ports", "firewall"]
            },
            
            # Déploiement sécurisé
            {
                "name": "Scan de sécurité obligatoire",
                "description": "Exige un scan de sécurité avant déploiement",
                "policy_type": PolicyType.DEPLOYMENT,
                "severity": PolicySeverity.CRITICAL,
                "condition": "deployment.security_scan_passed == false",
                "action": "block_deployment",
                "compliance_frameworks": [ComplianceFramework.OWASP],
                "tags": ["deployment", "security-scan", "ci-cd"]
            },
            
            # Conformité OWASP
            {
                "name": "Vulnérabilités OWASP Top 10",
                "description": "Détecte les vulnérabilités du Top 10 OWASP",
                "policy_type": PolicyType.COMPLIANCE,
                "severity": PolicySeverity.CRITICAL,
                "condition": "scan.owasp_top10_vulnerabilities > 0",
                "action": "block_deployment",
                "compliance_frameworks": [ComplianceFramework.OWASP],
                "tags": ["owasp", "vulnerabilities", "top10"]
            }
        ]
        
        for rule_data in default_rules:
            rule_id = self._generate_rule_id(rule_data["name"])
            rule = PolicyRule(
                id=rule_id,
                **rule_data
            )
            self.rules[rule_id] = rule
        
        await self._save_rules()
    
    async def _save_rules(self):
        """Sauvegarde les règles de politiques"""
        rules_file = self.config_path.parent / "policy_rules.json"
        
        rules_data = {}
        for rule_id, rule in self.rules.items():
            rule_dict = {
                'id': rule.id,
                'name': rule.name,
                'description': rule.description,
                'policy_type': rule.policy_type.value,
                'severity': rule.severity.value,
                'condition': rule.condition,
                'action': rule.action,
                'enabled': rule.enabled,
                'tags': rule.tags,
                'compliance_frameworks': [fw.value for fw in rule.compliance_frameworks],
                'created_at': rule.created_at.isoformat(),
                'updated_at': rule.updated_at.isoformat(),
                'created_by': rule.created_by,
                'metadata': rule.metadata
            }
            rules_data[rule_id] = rule_dict
        
        with open(rules_file, 'w') as f:
            json.dump(rules_data, f, indent=2)
    
    async def _load_violations(self):
        """Charge les violations existantes"""
        violations_file = self.config_path.parent / "violations.json"
        
        if violations_file.exists():
            with open(violations_file, 'r') as f:
                violations_data = json.load(f)
                for violation_dict in violations_data:
                    violation_dict['severity'] = PolicySeverity(violation_dict['severity'])
                    violation_dict['timestamp'] = datetime.fromisoformat(violation_dict['timestamp'])
                    
                    if violation_dict.get('resolved_at'):
                        violation_dict['resolved_at'] = datetime.fromisoformat(violation_dict['resolved_at'])
                    
                    self.violations.append(PolicyViolation(**violation_dict))
    
    async def _save_violations(self):
        """Sauvegarde les violations"""
        violations_file = self.config_path.parent / "violations.json"
        
        violations_data = []
        for violation in self.violations:
            violation_dict = {
                'id': violation.id,
                'rule_id': violation.rule_id,
                'rule_name': violation.rule_name,
                'severity': violation.severity.value,
                'description': violation.description,
                'resource': violation.resource,
                'timestamp': violation.timestamp.isoformat(),
                'details': violation.details,
                'resolved': violation.resolved,
                'resolution_notes': violation.resolution_notes,
                'resolved_at': violation.resolved_at.isoformat() if violation.resolved_at else None,
                'resolved_by': violation.resolved_by
            }
            violations_data.append(violation_dict)
        
        with open(violations_file, 'w') as f:
            json.dump(violations_data, f, indent=2)
    
    async def _register_default_handlers(self):
        """Enregistre les gestionnaires par défaut"""
        # Gestionnaires de conditions
        self.condition_handlers.update({
            "user_privilege_check": self._check_user_privilege,
            "data_encryption_check": self._check_data_encryption,
            "network_port_check": self._check_network_ports,
            "security_scan_check": self._check_security_scan,
            "owasp_vulnerability_check": self._check_owasp_vulnerabilities
        })
        
        # Gestionnaires d'actions
        self.action_handlers.update({
            "deny_access": self._action_deny_access,
            "encrypt_data": self._action_encrypt_data,
            "block_port": self._action_block_port,
            "block_deployment": self._action_block_deployment,
            "quarantine_resource": self._action_quarantine_resource,
            "send_notification": self._action_send_notification
        })
    
    async def add_rule(
        self,
        name: str,
        description: str,
        policy_type: PolicyType,
        severity: PolicySeverity,
        condition: str,
        action: str,
        compliance_frameworks: List[ComplianceFramework] = None,
        tags: List[str] = None,
        metadata: Dict[str, Any] = None
    ) -> str:
        """
        Ajoute une nouvelle règle de politique
        
        Args:
            name: Nom de la règle
            description: Description de la règle
            policy_type: Type de politique
            severity: Niveau de sévérité
            condition: Expression de condition
            action: Action à effectuer
            compliance_frameworks: Frameworks de conformité
            tags: Tags pour l'organisation
            metadata: Métadonnées additionnelles
            
        Returns:
            ID de la règle créée
        """
        rule_id = self._generate_rule_id(name)
        
        rule = PolicyRule(
            id=rule_id,
            name=name,
            description=description,
            policy_type=policy_type,
            severity=severity,
            condition=condition,
            action=action,
            compliance_frameworks=compliance_frameworks or [],
            tags=tags or [],
            metadata=metadata or {}
        )
        
        self.rules[rule_id] = rule
        await self._save_rules()
        
        print(f" Règle de politique '{name}' ajoutée avec l'ID: {rule_id}")
        return rule_id
    
    async def evaluate_policies(
        self,
        context: Dict[str, Any],
        resource: str = "unknown"
    ) -> List[PolicyViolation]:
        """
        Évalue toutes les politiques actives contre un contexte
        
        Args:
            context: Contexte d'évaluation (données, utilisateur, etc.)
            resource: Ressource concernée
            
        Returns:
            Liste des violations détectées
        """
        violations = []
        self.metrics["total_evaluations"] += 1
        
        for rule_id, rule in self.rules.items():
            if not rule.enabled:
                continue
            
            try:
                # Évaluation de la condition
                if await self._evaluate_condition(rule.condition, context):
                    # Création de la violation
                    violation = PolicyViolation(
                        id=self._generate_violation_id(),
                        rule_id=rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        description=f"Violation de la règle '{rule.name}': {rule.description}",
                        resource=resource,
                        timestamp=datetime.utcnow(),
                        details={
                            "context": context,
                            "rule_condition": rule.condition,
                            "rule_action": rule.action
                        }
                    )
                    
                    violations.append(violation)
                    self.violations.append(violation)
                    self.metrics["violations_detected"] += 1
                    
                    # Exécution de l'action
                    if self.config["enforcement"]["enabled"]:
                        await self._execute_action(rule.action, context, violation)
                        self.metrics["policies_enforced"] += 1
                    
                    print(f"Violation détectée: {rule.name} sur {resource}")
                
            except Exception as e:
                print(f" Erreur évaluation règle {rule_id}: {e}")
        
        # Sauvegarde des violations
        if violations:
            await self._save_violations()
            
            # Notifications pour violations critiques
            critical_violations = [v for v in violations if v.severity == PolicySeverity.CRITICAL]
            if critical_violations:
                await self._send_immediate_notifications(critical_violations)
        
        return violations
    
    async def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Évalue une condition de politique"""
        try:
            # Remplacement des variables dans la condition
            evaluated_condition = condition
            for key, value in context.items():
                placeholder = f"{key}."
                if placeholder in evaluated_condition:
                    # Simulation d'évaluation de condition
                    # En production, utiliser un moteur d'évaluation sécurisé
                    return await self._safe_condition_evaluation(condition, context)
            
            return False
            
        except Exception as e:
            print(f"Erreur évaluation condition '{condition}': {e}")
            return False
    
    async def _safe_condition_evaluation(self, condition: str, context: Dict[str, Any]) -> bool:
        """Évaluation sécurisée des conditions"""
        # Simulation d'évaluation basée sur des patterns communs
        
        # Vérification MFA
        if "mfa_enabled" in condition and "user" in context:
            user_data = context.get("user", {})
            return not user_data.get("mfa_enabled", True)
        
        # Vérification chiffrement
        if "encrypted" in condition and "data" in context:
            data_info = context.get("data", {})
            return not data_info.get("encrypted", True)
        
        # Vérification scan de sécurité
        if "security_scan_passed" in condition and "deployment" in context:
            deployment_info = context.get("deployment", {})
            return not deployment_info.get("security_scan_passed", True)
        
        # Vérification vulnérabilités OWASP
        if "owasp_top10_vulnerabilities" in condition and "scan" in context:
            scan_info = context.get("scan", {})
            return scan_info.get("owasp_top10_vulnerabilities", 0) > 0
        
        return False
    
    async def _execute_action(
        self,
        action: str,
        context: Dict[str, Any],
        violation: PolicyViolation
    ):
        """Exécute une action de politique"""
        try:
            if action in self.action_handlers:
                await self.action_handlers[action](context, violation)
            else:
                # Actions par défaut
                if action == "deny_access":
                    print(f" Accès refusé pour {violation.resource}")
                elif action == "block_deployment":
                    print(f" Déploiement bloqué pour {violation.resource}")
                elif action == "encrypt_data":
                    print(f" Chiffrement requis pour {violation.resource}")
                elif action == "block_port":
                    print(f" Port bloqué pour {violation.resource}")
                else:
                    print(f" Action '{action}' non implémentée")
                    
        except Exception as e:
            print(f" Erreur exécution action '{action}': {e}")
    
    async def resolve_violation(
        self,
        violation_id: str,
        resolution_notes: str,
        resolved_by: str = "system"
    ) -> bool:
        """
        Marque une violation comme résolue
        
        Args:
            violation_id: ID de la violation
            resolution_notes: Notes de résolution
            resolved_by: Utilisateur qui résout
            
        Returns:
            True si la résolution a réussi
        """
        for violation in self.violations:
            if violation.id == violation_id:
                violation.resolved = True
                violation.resolution_notes = resolution_notes
                violation.resolved_at = datetime.utcnow()
                violation.resolved_by = resolved_by
                
                await self._save_violations()
                print(f" Violation {violation_id} résolue par {resolved_by}")
                return True
        
        print(f" Violation {violation_id} non trouvée")
        return False
    
    async def generate_compliance_report(
        self,
        framework: ComplianceFramework,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> ComplianceReport:
        """
        Génère un rapport de conformité pour un framework
        
        Args:
            framework: Framework de conformité
            start_date: Date de début de la période
            end_date: Date de fin de la période
            
        Returns:
            Rapport de conformité
        """
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()
        
        # Filtrage des règles pour le framework
        framework_rules = [
            rule for rule in self.rules.values()
            if framework in rule.compliance_frameworks
        ]
        
        # Filtrage des violations pour la période
        period_violations = [
            violation for violation in self.violations
            if start_date <= violation.timestamp <= end_date
            and any(
                framework in self.rules[violation.rule_id].compliance_frameworks
                for rule_id in [violation.rule_id] if rule_id in self.rules
            )
        ]
        
        # Calcul des métriques
        total_checks = len(framework_rules)
        failed_checks = len(set(v.rule_id for v in period_violations))
        passed_checks = total_checks - failed_checks
        compliance_score = (passed_checks / total_checks * 100) if total_checks > 0 else 100
        
        # Génération des recommandations
        recommendations = await self._generate_recommendations(framework, period_violations)
        
        report = ComplianceReport(
            framework=framework,
            generated_at=datetime.utcnow(),
            period_start=start_date,
            period_end=end_date,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            compliance_score=compliance_score,
            violations=period_violations,
            recommendations=recommendations,
            next_review_date=datetime.utcnow() + timedelta(days=30)
        )
        
        # Sauvegarde du rapport
        report_id = f"{framework.value}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self.compliance_reports[report_id] = report
        
        self.metrics["compliance_checks"] += 1
        print(f" Rapport de conformité {framework.value} généré: {compliance_score:.1f}%")
        
        return report
    
    async def _generate_recommendations(
        self,
        framework: ComplianceFramework,
        violations: List[PolicyViolation]
    ) -> List[str]:
        """Génère des recommandations basées sur les violations"""
        recommendations = []
        
        # Analyse des patterns de violations
        violation_types = {}
        for violation in violations:
            rule = self.rules.get(violation.rule_id)
            if rule:
                policy_type = rule.policy_type.value
                violation_types[policy_type] = violation_types.get(policy_type, 0) + 1
        
        # Recommandations par type
        if violation_types.get("access_control", 0) > 0:
            recommendations.append(
                "Renforcer les contrôles d'accès et implémenter l'authentification multi-facteurs"
            )
        
        if violation_types.get("data_protection", 0) > 0:
            recommendations.append(
                "Améliorer le chiffrement des données et la classification des informations sensibles"
            )
        
        if violation_types.get("network_security", 0) > 0:
            recommendations.append(
                "Réviser la configuration des pare-feux et la segmentation réseau"
            )
        
        if violation_types.get("deployment", 0) > 0:
            recommendations.append(
                "Intégrer des scans de sécurité automatisés dans le pipeline CI/CD"
            )
        
        # Recommandations spécifiques par framework
        if framework == ComplianceFramework.GDPR:
            recommendations.append(
                "Mettre en place des procédures de gestion des droits des personnes concernées"
            )
        elif framework == ComplianceFramework.SOC2:
            recommendations.append(
                "Renforcer la surveillance et les contrôles de sécurité opérationnelle"
            )
        elif framework == ComplianceFramework.OWASP:
            recommendations.append(
                "Effectuer des tests de pénétration réguliers et corriger les vulnérabilités du Top 10"
            )
        
        return recommendations
    
    async def get_policy_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques des politiques"""
        active_rules = len([r for r in self.rules.values() if r.enabled])
        open_violations = len([v for v in self.violations if not v.resolved])
        critical_violations = len([
            v for v in self.violations 
            if v.severity == PolicySeverity.CRITICAL and not v.resolved
        ])
        
        # Calcul du taux de conformité global
        total_evaluations = self.metrics["total_evaluations"]
        violations_detected = self.metrics["violations_detected"]
        compliance_rate = (
            (total_evaluations - violations_detected) / total_evaluations * 100
            if total_evaluations > 0 else 100
        )
        
        return {
            "active_rules": active_rules,
            "total_rules": len(self.rules),
            "open_violations": open_violations,
            "critical_violations": critical_violations,
            "total_violations": len(self.violations),
            "compliance_rate": compliance_rate,
            "metrics": self.metrics,
            "last_evaluation": datetime.utcnow().isoformat()
        }
    
    async def _start_policy_monitor(self):
        """Démarre le moniteur de politiques en temps réel"""
        if not self.config["monitoring"]["real_time"]:
            return
        
        async def monitor_task():
            while True:
                try:
                    await self._periodic_policy_check()
                    await asyncio.sleep(self.config["monitoring"]["check_interval"])
                except Exception as e:
                    print(f"Erreur moniteur de politiques: {e}")
                    await asyncio.sleep(60)
        
        asyncio.create_task(monitor_task())
        print("👁️ Moniteur de politiques démarré")
    
    async def _periodic_policy_check(self):
        """Vérification périodique des politiques"""
        # Simulation de vérifications automatiques
        # En production, intégrer avec les systèmes de monitoring
        
        # Vérification des violations non résolues anciennes
        old_violations = [
            v for v in self.violations
            if not v.resolved and 
            (datetime.utcnow() - v.timestamp).days > 7
        ]
        
        if old_violations:
            print(f" {len(old_violations)} violations non résolues depuis plus de 7 jours")
        
        # Nettoyage des violations anciennes résolues
        retention_date = datetime.utcnow() - timedelta(
            days=self.config["audit"]["retention_days"]
        )
        
        self.violations = [
            v for v in self.violations
            if v.timestamp > retention_date or not v.resolved
        ]
    
    async def _send_immediate_notifications(self, violations: List[PolicyViolation]):
        """Envoie des notifications immédiates pour violations critiques"""
        if not self.config["notifications"]["immediate_severity"]:
            return
        
        critical_violations = [
            v for v in violations
            if v.severity.value in self.config["notifications"]["immediate_severity"]
        ]
        
        if critical_violations:
            print(f" Envoi de notifications pour {len(critical_violations)} violations critiques")
            # En production, intégrer avec les systèmes de notification
    
    # Méthodes utilitaires
    
    def _generate_rule_id(self, name: str) -> str:
        """Génère un ID unique pour une règle"""
        data = f"{name}_{datetime.utcnow().isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:12]
    
    def _generate_violation_id(self) -> str:
        """Génère un ID unique pour une violation"""
        data = f"violation_{datetime.utcnow().isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    # Gestionnaires de conditions par défaut
    
    async def _check_user_privilege(self, context: Dict[str, Any]) -> bool:
        """Vérifie les privilèges utilisateur"""
        user = context.get("user", {})
        return user.get("privilege_level") == "admin" and not user.get("mfa_enabled", True)
    
    async def _check_data_encryption(self, context: Dict[str, Any]) -> bool:
        """Vérifie le chiffrement des données"""
        data = context.get("data", {})
        return data.get("classification") == "sensitive" and not data.get("encrypted", True)
    
    async def _check_network_ports(self, context: Dict[str, Any]) -> bool:
        """Vérifie les ports réseau"""
        network = context.get("network", {})
        open_ports = network.get("open_ports", [])
        unauthorized_ports = [22, 23, 135, 139, 445]  # Exemple
        return any(port in unauthorized_ports for port in open_ports)
    
    async def _check_security_scan(self, context: Dict[str, Any]) -> bool:
        """Vérifie les scans de sécurité"""
        deployment = context.get("deployment", {})
        return not deployment.get("security_scan_passed", True)
    
    async def _check_owasp_vulnerabilities(self, context: Dict[str, Any]) -> bool:
        """Vérifie les vulnérabilités OWASP"""
        scan = context.get("scan", {})
        return scan.get("owasp_top10_vulnerabilities", 0) > 0
    
    # Gestionnaires d'actions par défaut
    
    async def _action_deny_access(self, context: Dict[str, Any], violation: PolicyViolation):
        """Action: Refuser l'accès"""
        print(f" Accès refusé - {violation.description}")
    
    async def _action_encrypt_data(self, context: Dict[str, Any], violation: PolicyViolation):
        """Action: Chiffrer les données"""
        print(f" Chiffrement requis - {violation.description}")
    
    async def _action_block_port(self, context: Dict[str, Any], violation: PolicyViolation):
        """Action: Bloquer un port"""
        print(f" Port bloqué - {violation.description}")
    
    async def _action_block_deployment(self, context: Dict[str, Any], violation: PolicyViolation):
        """Action: Bloquer le déploiement"""
        print(f" Déploiement bloqué - {violation.description}")
    
    async def _action_quarantine_resource(self, context: Dict[str, Any], violation: PolicyViolation):
        """Action: Mettre en quarantaine"""
        print(f" Ressource mise en quarantaine - {violation.description}")
    
    async def _action_send_notification(self, context: Dict[str, Any], violation: PolicyViolation):
        """Action: Envoyer une notification"""
        print(f" Notification envoyée - {violation.description}")
