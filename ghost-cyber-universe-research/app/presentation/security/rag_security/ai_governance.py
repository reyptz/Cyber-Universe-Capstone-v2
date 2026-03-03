"""
Gouvernance IA & Cartographie des risques
Registre de risques, référentiel d'attaques LLM, rapports red team (MTTD/MTTR)
"""

import json
import logging
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import numpy as np
from ..config import config

logger = logging.getLogger(__name__)

class RiskCategory(Enum):
    """Catégories de risque"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    TOXIC_CONTENT = "toxic_content"
    PII_LEAKAGE = "pii_leakage"
    SECRETS_EXPOSURE = "secrets_exposure"
    SUPPLY_CHAIN_COMPROMISE = "supply_chain_compromise"
    MODEL_POISONING = "model_poisoning"
    ADVERSARIAL_ATTACK = "adversarial_attack"
    SYSTEM_MANIPULATION = "system_manipulation"

class SeverityLevel(Enum):
    """Niveaux de sévérité"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class DetectionMethod(Enum):
    """Méthodes de détection"""
    AUTOMATED = "automated"
    MANUAL = "manual"
    HYBRID = "hybrid"
    ML_MODEL = "ml_model"
    HEURISTIC = "heuristic"

@dataclass
class SecurityFinding:
    """Finding de sécurité"""
    id: str
    category: RiskCategory
    severity: SeverityLevel
    description: str
    timestamp: str
    source: str
    affected_components: List[str]
    detection_method: DetectionMethod
    confidence_score: float
    remediation_status: str
    mttd_minutes: Optional[float] = None
    mttr_minutes: Optional[float] = None
    false_positive: bool = False
    validated: bool = False

@dataclass
class AttackPattern:
    """Pattern d'attaque"""
    id: str
    name: str
    category: RiskCategory
    description: str
    attack_vector: str
    detection_indicators: List[str]
    mitigation_strategies: List[str]
    severity: SeverityLevel
    frequency: int
    success_rate: float
    last_seen: datetime

@dataclass
class RedTeamReport:
    """Rapport de red team"""
    id: str
    test_name: str
    test_date: datetime
    attack_scenarios: List[str]
    findings: List[SecurityFinding]
    mttd_metrics: Dict[str, float]
    mttr_metrics: Dict[str, float]
    recommendations: List[str]
    risk_score: float
    status: str

class AIGovernance:
    """Gouvernance IA et cartographie des risques"""
    
    def __init__(self):
        """Initialise la gouvernance IA"""
        try:
            # Registre de risques
            self.risk_registry = {}
            self.security_findings = []
            
            # Référentiel d'attaques LLM
            self.attack_patterns = {}
            self._initialize_attack_patterns()
            
            # Rapports red team
            self.red_team_reports = []
            
            # Métriques MTTD/MTTR
            self.mttd_mttr_metrics = {
                'prompt_injection': {'mttd': 5.0, 'mttr': 30.0},
                'jailbreak': {'mttd': 3.0, 'mttr': 45.0},
                'data_exfiltration': {'mttd': 2.0, 'mttr': 60.0},
                'toxic_content': {'mttd': 1.0, 'mttr': 15.0},
                'pii_leakage': {'mttd': 4.0, 'mttr': 90.0},
                'secrets_exposure': {'mttd': 2.0, 'mttr': 120.0}
            }
            
            # Cadres de conformité
            self._initialize_compliance_frameworks()
            
            logger.info("Gouvernance IA initialisée")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation de la gouvernance IA: {e}")
            raise
    
    def _initialize_attack_patterns(self):
        """Initialise le référentiel d'attaques LLM"""
        self.attack_patterns = {
            'dan_mode': AttackPattern(
                id='dan_mode_001',
                name='DAN Mode Activation',
                category=RiskCategory.PROMPT_INJECTION,
                description='Tentative d\'activation du mode DAN (Do Anything Now)',
                attack_vector='Prompt injection avec instructions de bypass',
                detection_indicators=['ignore previous instructions', 'you are now dan', 'do anything now'],
                mitigation_strategies=['Content filtering', 'Context validation', 'Behavioral analysis'],
                severity=SeverityLevel.HIGH,
                frequency=0,
                success_rate=0.0,
                last_seen=datetime.utcnow()
            ),
            'developer_override': AttackPattern(
                id='dev_override_001',
                name='Developer Override Attempt',
                category=RiskCategory.JAILBREAK,
                description='Tentative d\'override des restrictions en se faisant passer pour un développeur',
                attack_vector='Social engineering avec fausse autorité',
                detection_indicators=['developer mode', 'admin override', 'system override'],
                mitigation_strategies=['Identity verification', 'Authorization checks', 'Audit logging'],
                severity=SeverityLevel.CRITICAL,
                frequency=0,
                success_rate=0.0,
                last_seen=datetime.utcnow()
            ),
            'system_prompt_extraction': AttackPattern(
                id='sys_prompt_001',
                name='System Prompt Extraction',
                category=RiskCategory.DATA_EXFILTRATION,
                description='Tentative d\'extraction des instructions système',
                attack_vector='Interrogation directe sur les instructions',
                detection_indicators=['show your instructions', 'reveal your programming', 'system prompt'],
                mitigation_strategies=['Response filtering', 'Context awareness', 'Information hiding'],
                severity=SeverityLevel.MEDIUM,
                frequency=0,
                success_rate=0.0,
                last_seen=datetime.utcnow()
            ),
            'toxic_content_generation': AttackPattern(
                id='toxic_content_001',
                name='Toxic Content Generation',
                category=RiskCategory.TOXIC_CONTENT,
                description='Tentative de génération de contenu toxique',
                attack_vector='Prompts visant à générer du contenu inapproprié',
                detection_indicators=['hate speech', 'violence', 'discriminatory language'],
                mitigation_strategies=['Content moderation', 'Toxicity detection', 'Response filtering'],
                severity=SeverityLevel.HIGH,
                frequency=0,
                success_rate=0.0,
                last_seen=datetime.utcnow()
            ),
            'pii_extraction': AttackPattern(
                id='pii_extract_001',
                name='PII Extraction Attempt',
                category=RiskCategory.PII_LEAKAGE,
                description='Tentative d\'extraction de données personnelles',
                attack_vector='Interrogation sur les données utilisateur',
                detection_indicators=['personal information', 'user data', 'privacy violation'],
                mitigation_strategies=['PII filtering', 'Data anonymization', 'Access controls'],
                severity=SeverityLevel.CRITICAL,
                frequency=0,
                success_rate=0.0,
                last_seen=datetime.utcnow()
            )
        }
    
    def _initialize_compliance_frameworks(self):
        """Initialise les cadres de conformité"""
        self.compliance_frameworks = {
            'owasp_llm': {
                'name': 'OWASP LLM Top 10',
                'version': '2023',
                'controls': [
                    'LLM01: Prompt Injection',
                    'LLM02: Insecure Output Handling',
                    'LLM03: Training Data Poisoning',
                    'LLM04: Model Denial of Service',
                    'LLM05: Supply Chain Vulnerabilities',
                    'LLM06: Sensitive Information Disclosure',
                    'LLM07: Insecure Plugin Design',
                    'LLM08: Excessive Agency',
                    'LLM09: Overreliance',
                    'LLM10: Model Theft'
                ]
            },
            'nist_ai_rmf': {
                'name': 'NIST AI Risk Management Framework',
                'version': '1.0',
                'controls': [
                    'Govern',
                    'Map',
                    'Measure',
                    'Manage'
                ]
            },
            'iso_27001': {
                'name': 'ISO 27001 Information Security',
                'version': '2022',
                'controls': [
                    'A.5 Information security policies',
                    'A.6 Organization of information security',
                    'A.7 Human resource security',
                    'A.8 Asset management',
                    'A.9 Access control',
                    'A.10 Cryptography',
                    'A.11 Physical and environmental security',
                    'A.12 Operations security',
                    'A.13 Communications security',
                    'A.14 System acquisition, development and maintenance'
                ]
            }
        }
    
    def record_security_finding(self, finding: SecurityFinding):
        """Enregistre un finding de sécurité"""
        try:
            # Calcul des métriques MTTD/MTTR
            if finding.mttd_minutes is None:
                finding.mttd_minutes = self._calculate_mttd(finding)
            
            if finding.mttr_minutes is None:
                finding.mttr_minutes = self._calculate_mttr(finding)
            
            # Ajout à la base de données
            self.security_findings.append(finding)
            
            # Mise à jour du registre de risques
            self._update_risk_registry(finding)
            
            # Mise à jour des patterns d'attaque
            self._update_attack_patterns(finding)
            
            logger.info(f"Finding de sécurité enregistré: {finding.id} - {finding.category.value}")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement du finding: {e}")
    
    def _calculate_mttd(self, finding: SecurityFinding) -> float:
        """Calcule le MTTD (Mean Time To Detection)"""
        try:
            # MTTD basé sur la catégorie de risque
            base_mttd = self.mttd_mttr_metrics.get(finding.category.value, {}).get('mttd', 5.0)
            
            # Ajustement basé sur la sévérité
            severity_multiplier = {
                SeverityLevel.CRITICAL: 0.5,
                SeverityLevel.HIGH: 0.7,
                SeverityLevel.MEDIUM: 1.0,
                SeverityLevel.LOW: 1.5,
                SeverityLevel.INFO: 2.0
            }
            
            multiplier = severity_multiplier.get(finding.severity, 1.0)
            return base_mttd * multiplier
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul du MTTD: {e}")
            return 5.0
    
    def _calculate_mttr(self, finding: SecurityFinding) -> float:
        """Calcule le MTTR (Mean Time To Remediation)"""
        try:
            # MTTR basé sur la catégorie de risque
            base_mttr = self.mttd_mttr_metrics.get(finding.category.value, {}).get('mttr', 30.0)
            
            # Ajustement basé sur la sévérité
            severity_multiplier = {
                SeverityLevel.CRITICAL: 0.5,
                SeverityLevel.HIGH: 0.7,
                SeverityLevel.MEDIUM: 1.0,
                SeverityLevel.LOW: 1.5,
                SeverityLevel.INFO: 2.0
            }
            
            multiplier = severity_multiplier.get(finding.severity, 1.0)
            return base_mttr * multiplier
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul du MTTR: {e}")
            return 30.0
    
    def _update_risk_registry(self, finding: SecurityFinding):
        """Met à jour le registre de risques"""
        try:
            risk_key = f"{finding.category.value}_{finding.severity.value}"
            
            if risk_key not in self.risk_registry:
                self.risk_registry[risk_key] = {
                    'category': finding.category.value,
                    'severity': finding.severity.value,
                    'count': 0,
                    'last_occurrence': finding.timestamp,
                    'total_mttd': 0.0,
                    'total_mttr': 0.0,
                    'avg_mttd': 0.0,
                    'avg_mttr': 0.0
                }
            
            registry_entry = self.risk_registry[risk_key]
            registry_entry['count'] += 1
            registry_entry['last_occurrence'] = finding.timestamp
            registry_entry['total_mttd'] += finding.mttd_minutes or 0.0
            registry_entry['total_mttr'] += finding.mttr_minutes or 0.0
            registry_entry['avg_mttd'] = registry_entry['total_mttd'] / registry_entry['count']
            registry_entry['avg_mttr'] = registry_entry['total_mttr'] / registry_entry['count']
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour du registre de risques: {e}")
    
    def _update_attack_patterns(self, finding: SecurityFinding):
        """Met à jour les patterns d'attaque"""
        try:
            # Recherche du pattern correspondant
            for pattern_id, pattern in self.attack_patterns.items():
                if pattern.category == finding.category:
                    pattern.frequency += 1
                    pattern.last_seen = datetime.utcnow()
                    
                    # Calcul du taux de succès basé sur la confiance
                    if finding.confidence_score > 0.7:
                        pattern.success_rate = (pattern.success_rate + 1.0) / 2.0
                    
                    break
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour des patterns d'attaque: {e}")
    
    def prioritize_findings(self) -> List[SecurityFinding]:
        """Priorise les findings de sécurité"""
        try:
            # Calcul du score de priorité pour chaque finding
            prioritized_findings = []
            
            for finding in self.security_findings:
                priority_score = self._calculate_priority_score(finding)
                prioritized_findings.append((finding, priority_score))
            
            # Tri par score de priorité décroissant
            prioritized_findings.sort(key=lambda x: x[1], reverse=True)
            
            return [finding for finding, score in prioritized_findings]
            
        except Exception as e:
            logger.error(f"Erreur lors de la priorisation des findings: {e}")
            return self.security_findings
    
    def _calculate_priority_score(self, finding: SecurityFinding) -> float:
        """Calcule le score de priorité d'un finding"""
        try:
            # Score de base basé sur la sévérité
            severity_scores = {
                SeverityLevel.CRITICAL: 100,
                SeverityLevel.HIGH: 80,
                SeverityLevel.MEDIUM: 60,
                SeverityLevel.LOW: 40,
                SeverityLevel.INFO: 20
            }
            
            base_score = severity_scores.get(finding.severity, 0)
            
            # Bonus pour la confiance
            confidence_bonus = finding.confidence_score * 20
            
            # Bonus pour les findings non validés
            validation_bonus = 10 if not finding.validated else 0
            
            # Pénalité pour les faux positifs
            false_positive_penalty = -50 if finding.false_positive else 0
            
            # Bonus pour les findings récents
            time_bonus = self._calculate_time_bonus(finding.timestamp)
            
            total_score = base_score + confidence_bonus + validation_bonus + false_positive_penalty + time_bonus
            
            return max(total_score, 0)
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul du score de priorité: {e}")
            return 0.0
    
    def _calculate_time_bonus(self, timestamp: str) -> float:
        """Calcule le bonus temporel pour les findings récents"""
        try:
            finding_time = datetime.fromisoformat(timestamp)
            current_time = datetime.utcnow()
            time_diff = (current_time - finding_time).total_seconds() / 3600  # en heures
            
            # Bonus décroissant avec le temps
            if time_diff < 1:
                return 20
            elif time_diff < 24:
                return 10
            elif time_diff < 168:  # 1 semaine
                return 5
            else:
                return 0
                
        except Exception as e:
            logger.error(f"Erreur lors du calcul du bonus temporel: {e}")
            return 0.0
    
    def calculate_mttd_mttr(self) -> Dict[str, Any]:
        """Calcule les métriques MTTD/MTTR globales"""
        try:
            if not self.security_findings:
                return {
                    'mttd_global': 0.0,
                    'mttr_global': 0.0,
                    'mttd_by_category': {},
                    'mttr_by_category': {},
                    'total_findings': 0
                }
            
            # Calcul global
            total_mttd = sum(finding.mttd_minutes or 0.0 for finding in self.security_findings)
            total_mttr = sum(finding.mttr_minutes or 0.0 for finding in self.security_findings)
            total_findings = len(self.security_findings)
            
            mttd_global = total_mttd / total_findings if total_findings > 0 else 0.0
            mttr_global = total_mttr / total_findings if total_findings > 0 else 0.0
            
            # Calcul par catégorie
            mttd_by_category = {}
            mttr_by_category = {}
            
            for category in RiskCategory:
                category_findings = [f for f in self.security_findings if f.category == category]
                if category_findings:
                    category_mttd = sum(f.mttd_minutes or 0.0 for f in category_findings) / len(category_findings)
                    category_mttr = sum(f.mttr_minutes or 0.0 for f in category_findings) / len(category_findings)
                    
                    mttd_by_category[category.value] = category_mttd
                    mttr_by_category[category.value] = category_mttr
            
            return {
                'mttd_global': mttd_global,
                'mttr_global': mttr_global,
                'mttd_by_category': mttd_by_category,
                'mttr_by_category': mttr_by_category,
                'total_findings': total_findings,
                'calculation_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des métriques MTTD/MTTR: {e}")
            return {'error': str(e)}
    
    def generate_red_team_report(self, test_name: str, attack_scenarios: List[str]) -> RedTeamReport:
        """Génère un rapport de red team"""
        try:
            report_id = hashlib.md5(f"{test_name}_{datetime.utcnow()}".encode()).hexdigest()[:8]
            
            # Exécution des scénarios d'attaque
            findings = []
            for scenario in attack_scenarios:
                finding = self._execute_attack_scenario(scenario)
                if finding:
                    findings.append(finding)
            
            # Calcul des métriques
            mttd_metrics = self._calculate_scenario_mttd(findings)
            mttr_metrics = self._calculate_scenario_mttr(findings)
            
            # Calcul du score de risque
            risk_score = self._calculate_risk_score(findings)
            
            # Génération des recommandations
            recommendations = self._generate_red_team_recommendations(findings)
            
            # Création du rapport
            report = RedTeamReport(
                id=report_id,
                test_name=test_name,
                test_date=datetime.utcnow(),
                attack_scenarios=attack_scenarios,
                findings=findings,
                mttd_metrics=mttd_metrics,
                mttr_metrics=mttr_metrics,
                recommendations=recommendations,
                risk_score=risk_score,
                status='completed'
            )
            
            # Ajout à la base de données
            self.red_team_reports.append(report)
            
            return report
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport red team: {e}")
            raise
    
    def _execute_attack_scenario(self, scenario: str) -> Optional[SecurityFinding]:
        """Exécute un scénario d'attaque"""
        try:
            # Simulation d'exécution de scénario d'attaque
            # En production, ceci appellerait les vrais systèmes de détection
            
            finding = SecurityFinding(
                id=hashlib.md5(f"{scenario}_{datetime.utcnow()}".encode()).hexdigest()[:8],
                category=RiskCategory.PROMPT_INJECTION,  # Par défaut
                severity=SeverityLevel.MEDIUM,
                description=f"Attaque simulée: {scenario}",
                timestamp=datetime.utcnow().isoformat(),
                source="red_team_test",
                affected_components=["rag_chain", "security_filters"],
                detection_method=DetectionMethod.AUTOMATED,
                confidence_score=0.8,
                remediation_status="detected"
            )
            
            return finding
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution du scénario d'attaque: {e}")
            return None
    
    def _calculate_scenario_mttd(self, findings: List[SecurityFinding]) -> Dict[str, float]:
        """Calcule les métriques MTTD pour les scénarios"""
        try:
            if not findings:
                return {}
            
            total_mttd = sum(finding.mttd_minutes or 0.0 for finding in findings)
            avg_mttd = total_mttd / len(findings)
            
            return {
                'total_mttd': total_mttd,
                'average_mttd': avg_mttd,
                'min_mttd': min(finding.mttd_minutes or 0.0 for finding in findings),
                'max_mttd': max(finding.mttd_minutes or 0.0 for finding in findings)
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des métriques MTTD de scénario: {e}")
            return {}
    
    def _calculate_scenario_mttr(self, findings: List[SecurityFinding]) -> Dict[str, float]:
        """Calcule les métriques MTTR pour les scénarios"""
        try:
            if not findings:
                return {}
            
            total_mttr = sum(finding.mttr_minutes or 0.0 for finding in findings)
            avg_mttr = total_mttr / len(findings)
            
            return {
                'total_mttr': total_mttr,
                'average_mttr': avg_mttr,
                'min_mttr': min(finding.mttr_minutes or 0.0 for finding in findings),
                'max_mttr': max(finding.mttr_minutes or 0.0 for finding in findings)
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul des métriques MTTR de scénario: {e}")
            return {}
    
    def _calculate_risk_score(self, findings: List[SecurityFinding]) -> float:
        """Calcule le score de risque global"""
        try:
            if not findings:
                return 0.0
            
            # Calcul du score basé sur la sévérité et la confiance
            total_score = 0.0
            for finding in findings:
                severity_weight = {
                    SeverityLevel.CRITICAL: 1.0,
                    SeverityLevel.HIGH: 0.8,
                    SeverityLevel.MEDIUM: 0.6,
                    SeverityLevel.LOW: 0.4,
                    SeverityLevel.INFO: 0.2
                }
                
                weight = severity_weight.get(finding.severity, 0.5)
                score = weight * finding.confidence_score
                total_score += score
            
            return min(total_score / len(findings), 1.0)
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul du score de risque: {e}")
            return 0.0
    
    def _generate_red_team_recommendations(self, findings: List[SecurityFinding]) -> List[str]:
        """Génère des recommandations basées sur les findings"""
        try:
            recommendations = []
            
            # Recommandations basées sur les catégories de risque
            categories = set(finding.category for finding in findings)
            
            if RiskCategory.PROMPT_INJECTION in categories:
                recommendations.append("Renforcer la détection d'injection de prompts")
            
            if RiskCategory.JAILBREAK in categories:
                recommendations.append("Améliorer la résistance aux tentatives de jailbreak")
            
            if RiskCategory.DATA_EXFILTRATION in categories:
                recommendations.append("Renforcer la protection contre l'exfiltration de données")
            
            if RiskCategory.TOXIC_CONTENT in categories:
                recommendations.append("Améliorer la modération de contenu")
            
            if RiskCategory.PII_LEAKAGE in categories:
                recommendations.append("Renforcer la protection des données personnelles")
            
            # Recommandations générales
            recommendations.extend([
                "Mettre à jour les modèles de détection",
                "Améliorer la formation des équipes de sécurité",
                "Renforcer les contrôles d'accès",
                "Implémenter une surveillance continue"
            ])
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération des recommandations: {e}")
            return ["Erreur lors de la génération des recommandations"]
    
    def generate_security_report(self, report_type: str = "comprehensive") -> Dict[str, Any]:
        """Génère un rapport de sécurité"""
        try:
            if report_type == "comprehensive":
                return self._generate_comprehensive_report()
            elif report_type == "executive":
                return self._generate_executive_report()
            elif report_type == "technical":
                return self._generate_technical_report()
            else:
                return self._generate_comprehensive_report()
                
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport de sécurité: {e}")
            return {'error': str(e)}
    
    def _generate_comprehensive_report(self) -> Dict[str, Any]:
        """Génère un rapport de sécurité complet"""
        try:
            # Métriques globales
            mttd_mttr = self.calculate_mttd_mttr()
            
            # Findings priorisés
            prioritized_findings = self.prioritize_findings()
            
            # Statistiques par catégorie
            category_stats = {}
            for category in RiskCategory:
                category_findings = [f for f in self.security_findings if f.category == category]
                if category_findings:
                    category_stats[category.value] = {
                        'count': len(category_findings),
                        'avg_confidence': sum(f.confidence_score for f in category_findings) / len(category_findings),
                        'severity_distribution': {
                            severity.value: sum(1 for f in category_findings if f.severity == severity)
                            for severity in SeverityLevel
                        }
                    }
            
            # Statistiques des patterns d'attaque
            attack_pattern_stats = {}
            for pattern_id, pattern in self.attack_patterns.items():
                attack_pattern_stats[pattern_id] = {
                    'name': pattern.name,
                    'frequency': pattern.frequency,
                    'success_rate': pattern.success_rate,
                    'last_seen': pattern.last_seen.isoformat()
                }
            
            # Rapports red team récents
            recent_red_team_reports = [
                {
                    'id': report.id,
                    'test_name': report.test_name,
                    'test_date': report.test_date.isoformat(),
                    'risk_score': report.risk_score,
                    'findings_count': len(report.findings)
                }
                for report in self.red_team_reports[-5:]  # 5 derniers rapports
            ]
            
            return {
                'report_type': 'comprehensive',
                'generation_timestamp': datetime.utcnow().isoformat(),
                'executive_summary': {
                    'total_findings': len(self.security_findings),
                    'critical_findings': len([f for f in self.security_findings if f.severity == SeverityLevel.CRITICAL]),
                    'high_findings': len([f for f in self.security_findings if f.severity == SeverityLevel.HIGH]),
                    'mttd_global': mttd_mttr['mttd_global'],
                    'mttr_global': mttd_mttr['mttr_global']
                },
                'mttd_mttr_metrics': mttd_mttr,
                'prioritized_findings': [
                    {
                        'id': f.id,
                        'category': f.category.value,
                        'severity': f.severity.value,
                        'description': f.description,
                        'confidence_score': f.confidence_score,
                        'timestamp': f.timestamp
                    }
                    for f in prioritized_findings[:10]  # Top 10
                ],
                'category_statistics': category_stats,
                'attack_pattern_statistics': attack_pattern_stats,
                'recent_red_team_reports': recent_red_team_reports,
                'compliance_frameworks': self.compliance_frameworks
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport complet: {e}")
            return {'error': str(e)}
    
    def _generate_executive_report(self) -> Dict[str, Any]:
        """Génère un rapport exécutif"""
        try:
            # Métriques clés
            mttd_mttr = self.calculate_mttd_mttr()
            
            # Score de risque global
            risk_score = self._calculate_global_risk_score()
            
            # Tendances
            trends = self._analyze_trends()
            
            return {
                'report_type': 'executive',
                'generation_timestamp': datetime.utcnow().isoformat(),
                'key_metrics': {
                    'total_security_incidents': len(self.security_findings),
                    'critical_incidents': len([f for f in self.security_findings if f.severity == SeverityLevel.CRITICAL]),
                    'average_detection_time': mttd_mttr['mttd_global'],
                    'average_remediation_time': mttd_mttr['mttr_global'],
                    'global_risk_score': risk_score
                },
                'risk_assessment': {
                    'overall_risk_level': self._determine_risk_level(risk_score),
                    'top_risks': self._get_top_risks(),
                    'risk_trends': trends
                },
                'recommendations': [
                    "Surveillance continue des systèmes IA",
                    "Formation des équipes sur les nouvelles menaces",
                    "Mise à jour des contrôles de sécurité",
                    "Tests de pénétration réguliers"
                ]
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport exécutif: {e}")
            return {'error': str(e)}
    
    def _generate_technical_report(self) -> Dict[str, Any]:
        """Génère un rapport technique"""
        try:
            # Détails techniques des findings
            technical_findings = []
            for finding in self.security_findings:
                technical_findings.append({
                    'id': finding.id,
                    'category': finding.category.value,
                    'severity': finding.severity.value,
                    'description': finding.description,
                    'source': finding.source,
                    'affected_components': finding.affected_components,
                    'detection_method': finding.detection_method.value,
                    'confidence_score': finding.confidence_score,
                    'mttd_minutes': finding.mttd_minutes,
                    'mttr_minutes': finding.mttr_minutes,
                    'timestamp': finding.timestamp,
                    'validated': finding.validated,
                    'false_positive': finding.false_positive
                })
            
            # Métriques techniques
            technical_metrics = {
                'detection_methods': {
                    method.value: len([f for f in self.security_findings if f.detection_method == method])
                    for method in DetectionMethod
                },
                'confidence_distribution': self._calculate_confidence_distribution(),
                'component_impact': self._calculate_component_impact()
            }
            
            return {
                'report_type': 'technical',
                'generation_timestamp': datetime.utcnow().isoformat(),
                'technical_findings': technical_findings,
                'technical_metrics': technical_metrics,
                'attack_patterns': {
                    pattern_id: {
                        'name': pattern.name,
                        'category': pattern.category.value,
                        'description': pattern.description,
                        'attack_vector': pattern.attack_vector,
                        'detection_indicators': pattern.detection_indicators,
                        'mitigation_strategies': pattern.mitigation_strategies,
                        'frequency': pattern.frequency,
                        'success_rate': pattern.success_rate,
                        'last_seen': pattern.last_seen.isoformat()
                    }
                    for pattern_id, pattern in self.attack_patterns.items()
                }
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport technique: {e}")
            return {'error': str(e)}
    
    def _calculate_global_risk_score(self) -> float:
        """Calcule le score de risque global"""
        try:
            if not self.security_findings:
                return 0.0
            
            # Calcul basé sur la sévérité et la fréquence
            severity_weights = {
                SeverityLevel.CRITICAL: 1.0,
                SeverityLevel.HIGH: 0.8,
                SeverityLevel.MEDIUM: 0.6,
                SeverityLevel.LOW: 0.4,
                SeverityLevel.INFO: 0.2
            }
            
            total_weighted_score = 0.0
            for finding in self.security_findings:
                weight = severity_weights.get(finding.severity, 0.5)
                score = weight * finding.confidence_score
                total_weighted_score += score
            
            return min(total_weighted_score / len(self.security_findings), 1.0)
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul du score de risque global: {e}")
            return 0.0
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Détermine le niveau de risque"""
        if risk_score >= 0.8:
            return "critical"
        elif risk_score >= 0.6:
            return "high"
        elif risk_score >= 0.4:
            return "medium"
        elif risk_score >= 0.2:
            return "low"
        else:
            return "minimal"
    
    def _get_top_risks(self) -> List[Dict[str, Any]]:
        """Retourne les risques les plus élevés"""
        try:
            # Grouper par catégorie et calculer le score moyen
            category_risks = {}
            for finding in self.security_findings:
                category = finding.category.value
                if category not in category_risks:
                    category_risks[category] = {
                        'count': 0,
                        'total_confidence': 0.0,
                        'max_severity': SeverityLevel.INFO
                    }
                
                category_risks[category]['count'] += 1
                category_risks[category]['total_confidence'] += finding.confidence_score
                if finding.severity.value > category_risks[category]['max_severity'].value:
                    category_risks[category]['max_severity'] = finding.severity
            
            # Calculer le score de risque par catégorie
            top_risks = []
            for category, stats in category_risks.items():
                avg_confidence = stats['total_confidence'] / stats['count']
                severity_weight = {
                    SeverityLevel.CRITICAL: 1.0,
                    SeverityLevel.HIGH: 0.8,
                    SeverityLevel.MEDIUM: 0.6,
                    SeverityLevel.LOW: 0.4,
                    SeverityLevel.INFO: 0.2
                }
                
                risk_score = avg_confidence * severity_weight.get(stats['max_severity'], 0.5)
                
                top_risks.append({
                    'category': category,
                    'risk_score': risk_score,
                    'count': stats['count'],
                    'max_severity': stats['max_severity'].value,
                    'avg_confidence': avg_confidence
                })
            
            # Trier par score de risque décroissant
            top_risks.sort(key=lambda x: x['risk_score'], reverse=True)
            
            return top_risks[:5]  # Top 5
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des risques principaux: {e}")
            return []
    
    def _analyze_trends(self) -> Dict[str, Any]:
        """Analyse les tendances"""
        try:
            # Analyse des tendances sur les 30 derniers jours
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            recent_findings = [
                f for f in self.security_findings
                if datetime.fromisoformat(f.timestamp) >= thirty_days_ago
            ]
            
            # Calcul des tendances
            trends = {
                'total_findings_trend': len(recent_findings),
                'critical_findings_trend': len([f for f in recent_findings if f.severity == SeverityLevel.CRITICAL]),
                'avg_confidence_trend': sum(f.confidence_score for f in recent_findings) / len(recent_findings) if recent_findings else 0,
                'trend_direction': 'increasing' if len(recent_findings) > len(self.security_findings) / 2 else 'decreasing'
            }
            
            return trends
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse des tendances: {e}")
            return {'error': str(e)}
    
    def _calculate_confidence_distribution(self) -> Dict[str, int]:
        """Calcule la distribution de confiance"""
        try:
            distribution = {
                'high_confidence': 0,    # > 0.8
                'medium_confidence': 0,  # 0.5 - 0.8
                'low_confidence': 0      # < 0.5
            }
            
            for finding in self.security_findings:
                if finding.confidence_score > 0.8:
                    distribution['high_confidence'] += 1
                elif finding.confidence_score >= 0.5:
                    distribution['medium_confidence'] += 1
                else:
                    distribution['low_confidence'] += 1
            
            return distribution
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul de la distribution de confiance: {e}")
            return {'error': str(e)}
    
    def _calculate_component_impact(self) -> Dict[str, int]:
        """Calcule l'impact par composant"""
        try:
            component_impact = {}
            
            for finding in self.security_findings:
                for component in finding.affected_components:
                    if component not in component_impact:
                        component_impact[component] = 0
                    component_impact[component] += 1
            
            return component_impact
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul de l'impact des composants: {e}")
            return {'error': str(e)}
