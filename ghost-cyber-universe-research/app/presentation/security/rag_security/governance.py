"""
Module de gouvernance et cartographie des risques
"""
import logging
import json
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from ..config import config

logger = logging.getLogger(__name__)

class RiskCategory(Enum):
    """Catégories de risques IA"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_LEAKAGE = "pii_leakage"
    SECRETS_EXPOSURE = "secrets_exposure"
    TOXIC_CONTENT = "toxic_content"
    ADVERSARIAL_ATTACK = "adversarial_attack"
    SUPPLY_CHAIN_COMPROMISE = "supply_chain_compromise"
    MODEL_POISONING = "model_poisoning"

class SeverityLevel(Enum):
    """Niveaux de sévérité"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityFinding:
    """Représentation d'un finding de sécurité"""
    id: str
    category: RiskCategory
    severity: SeverityLevel
    description: str
    timestamp: str
    source: str
    affected_components: List[str]
    detection_method: str
    confidence_score: float
    remediation_status: str = "open"
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None

@dataclass
class RiskAssessment:
    """Évaluation des risques"""
    risk_id: str
    category: RiskCategory
    severity: SeverityLevel
    likelihood: float  # 0.0 à 1.0
    impact: float      # 0.0 à 1.0
    risk_score: float  # likelihood * impact
    description: str
    mitigation_measures: List[str]
    residual_risk: float
    assessment_date: str

class SecurityGovernance:
    """Gestionnaire de gouvernance de sécurité"""
    
    def __init__(self):
        """Initialise le gestionnaire de gouvernance"""
        try:
            # Registre des findings
            self.findings_registry = {}
            
            # Registre des évaluations de risques
            self.risk_assessments = {}
            
            # Métriques de sécurité
            self.security_metrics = {
                'total_findings': 0,
                'findings_by_category': {category.value: 0 for category in RiskCategory},
                'findings_by_severity': {severity.value: 0 for severity in SeverityLevel},
                'mttd_avg': 0.0,  # Mean Time To Detection
                'mttr_avg': 0.0,  # Mean Time To Resolution
                'last_updated': datetime.utcnow().isoformat()
            }
            
            # Configuration de gouvernance
            self.governance_config = config.GOVERNANCE
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation de la gouvernance: {e}")
            raise
    
    def record_security_finding(self, finding: SecurityFinding) -> Dict[str, Any]:
        """
        Enregistre un finding de sécurité
        
        Args:
            finding: Finding de sécurité à enregistrer
            
        Returns:
            Résultat de l'enregistrement
        """
        try:
            # Ajout au registre
            self.findings_registry[finding.id] = finding
            
            # Mise à jour des métriques
            self._update_security_metrics(finding)
            
            # Log du finding
            logger.warning(f"Finding de sécurité enregistré: {finding.id} - {finding.category.value} - {finding.severity.value}")
            
            return {
                'finding_recorded': True,
                'finding_id': finding.id,
                'category': finding.category.value,
                'severity': finding.severity.value,
                'timestamp': finding.timestamp
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement du finding: {e}")
            return {'finding_recorded': False, 'error': str(e)}
    
    def create_risk_assessment(self, risk_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Crée une évaluation de risques
        
        Args:
            risk_data: Données de l'évaluation de risques
            
        Returns:
            Résultat de la création de l'évaluation
        """
        try:
            # Calcul du score de risque
            likelihood = risk_data.get('likelihood', 0.5)
            impact = risk_data.get('impact', 0.5)
            risk_score = likelihood * impact
            
            # Création de l'évaluation
            assessment = RiskAssessment(
                risk_id=risk_data['risk_id'],
                category=RiskCategory(risk_data['category']),
                severity=self._calculate_severity_from_score(risk_score),
                likelihood=likelihood,
                impact=impact,
                risk_score=risk_score,
                description=risk_data['description'],
                mitigation_measures=risk_data.get('mitigation_measures', []),
                residual_risk=risk_data.get('residual_risk', risk_score * 0.3),
                assessment_date=datetime.utcnow().isoformat()
            )
            
            # Ajout au registre
            self.risk_assessments[assessment.risk_id] = assessment
            
            logger.info(f"Évaluation de risques créée: {assessment.risk_id} - Score: {risk_score:.2f}")
            
            return {
                'assessment_created': True,
                'risk_id': assessment.risk_id,
                'risk_score': risk_score,
                'severity': assessment.severity.value,
                'assessment_date': assessment.assessment_date
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la création de l'évaluation de risques: {e}")
            return {'assessment_created': False, 'error': str(e)}
    
    def generate_security_report(self, report_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Génère un rapport de sécurité
        
        Args:
            report_type: Type de rapport (comprehensive, executive, technical)
            
        Returns:
            Rapport de sécurité généré
        """
        try:
            report = {
                'report_id': self._generate_report_id(),
                'report_type': report_type,
                'generation_timestamp': datetime.utcnow().isoformat(),
                'period': self._get_reporting_period(),
                'executive_summary': self._generate_executive_summary(),
                'findings_summary': self._generate_findings_summary(),
                'risk_assessments': self._generate_risk_summary(),
                'metrics': self._generate_metrics_summary(),
                'recommendations': self._generate_recommendations(),
                'compliance_status': self._generate_compliance_status()
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport: {e}")
            return {'report_generated': False, 'error': str(e)}
    
    def calculate_mttd_mttr(self) -> Dict[str, Any]:
        """
        Calcule les métriques MTTD et MTTR
        
        Returns:
            Métriques MTTD/MTTR
        """
        try:
            # Calcul MTTD (Mean Time To Detection)
            detection_times = []
            for finding in self.findings_registry.values():
                if hasattr(finding, 'detection_time') and hasattr(finding, 'incident_time'):
                    detection_time = (datetime.fromisoformat(finding.detection_time) - 
                                    datetime.fromisoformat(finding.incident_time)).total_seconds()
                    detection_times.append(detection_time)
            
            mttd_avg = sum(detection_times) / len(detection_times) if detection_times else 0
            
            # Calcul MTTR (Mean Time To Resolution)
            resolution_times = []
            for finding in self.findings_registry.values():
                if finding.remediation_status == "resolved" and hasattr(finding, 'resolution_time'):
                    resolution_time = (datetime.fromisoformat(finding.resolution_time) - 
                                     datetime.fromisoformat(finding.timestamp)).total_seconds()
                    resolution_times.append(resolution_time)
            
            mttr_avg = sum(resolution_times) / len(resolution_times) if resolution_times else 0
            
            # Mise à jour des métriques
            self.security_metrics['mttd_avg'] = mttd_avg
            self.security_metrics['mttr_avg'] = mttr_avg
            self.security_metrics['last_updated'] = datetime.utcnow().isoformat()
            
            return {
                'mttd_avg_seconds': mttd_avg,
                'mttd_avg_minutes': mttd_avg / 60,
                'mttr_avg_seconds': mttr_avg,
                'mttr_avg_minutes': mttr_avg / 60,
                'mttd_target_seconds': self.governance_config['mttd_target'],
                'mttr_target_seconds': self.governance_config['mttr_target'],
                'mttd_compliance': mttd_avg <= self.governance_config['mttd_target'],
                'mttr_compliance': mttr_avg <= self.governance_config['mttr_target']
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du calcul MTTD/MTTR: {e}")
            return {'mttd_avg_seconds': 0, 'mttr_avg_seconds': 0, 'error': str(e)}
    
    def prioritize_findings(self) -> List[Dict[str, Any]]:
        """
        Priorise les findings selon leur criticité
        
        Returns:
            Liste des findings priorisés
        """
        try:
            # Calcul du score de priorité pour chaque finding
            prioritized_findings = []
            
            for finding in self.findings_registry.values():
                if finding.remediation_status == "open":
                    # Score de priorité basé sur la sévérité et la catégorie
                    priority_score = self._calculate_priority_score(finding)
                    
                    prioritized_findings.append({
                        'finding_id': finding.id,
                        'category': finding.category.value,
                        'severity': finding.severity.value,
                        'priority_score': priority_score,
                        'description': finding.description,
                        'timestamp': finding.timestamp,
                        'assigned_to': finding.assigned_to
                    })
            
            # Tri par score de priorité décroissant
            prioritized_findings.sort(key=lambda x: x['priority_score'], reverse=True)
            
            return prioritized_findings
            
        except Exception as e:
            logger.error(f"Erreur lors de la priorisation des findings: {e}")
            return []
    
    def map_findings_to_framework(self, framework: str = "OWASP_LLM") -> Dict[str, Any]:
        """
        Mappe les findings vers un framework de sécurité
        
        Args:
            framework: Framework de référence (OWASP_LLM, NIST, ISO27001)
            
        Returns:
            Mapping des findings vers le framework
        """
        try:
            if framework == "OWASP_LLM":
                mapping = self._map_to_owasp_llm()
            elif framework == "NIST":
                mapping = self._map_to_nist()
            elif framework == "ISO27001":
                mapping = self._map_to_iso27001()
            else:
                return {'mapping_completed': False, 'error': 'Framework non supporté'}
            
            return {
                'mapping_completed': True,
                'framework': framework,
                'mapping': mapping,
                'total_mapped': len(mapping),
                'mapping_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du mapping vers le framework: {e}")
            return {'mapping_completed': False, 'error': str(e)}
    
    def _update_security_metrics(self, finding: SecurityFinding):
        """Met à jour les métriques de sécurité"""
        self.security_metrics['total_findings'] += 1
        self.security_metrics['findings_by_category'][finding.category.value] += 1
        self.security_metrics['findings_by_severity'][finding.severity.value] += 1
    
    def _calculate_severity_from_score(self, risk_score: float) -> SeverityLevel:
        """Calcule la sévérité basée sur le score de risque"""
        if risk_score >= 0.8:
            return SeverityLevel.CRITICAL
        elif risk_score >= 0.6:
            return SeverityLevel.HIGH
        elif risk_score >= 0.4:
            return SeverityLevel.MEDIUM
        else:
            return SeverityLevel.LOW
    
    def _calculate_priority_score(self, finding: SecurityFinding) -> float:
        """Calcule le score de priorité d'un finding"""
        # Score de base basé sur la sévérité
        severity_scores = {
            SeverityLevel.CRITICAL: 4.0,
            SeverityLevel.HIGH: 3.0,
            SeverityLevel.MEDIUM: 2.0,
            SeverityLevel.LOW: 1.0
        }
        
        base_score = severity_scores[finding.severity]
        
        # Bonus pour certaines catégories critiques
        critical_categories = [RiskCategory.PROMPT_INJECTION, RiskCategory.SECRETS_EXPOSURE]
        if finding.category in critical_categories:
            base_score += 1.0
        
        # Bonus pour la confiance élevée
        if finding.confidence_score > 0.8:
            base_score += 0.5
        
        return base_score
    
    def _generate_report_id(self) -> str:
        """Génère un ID unique pour le rapport"""
        return f"SEC_REPORT_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    
    def _get_reporting_period(self) -> Dict[str, str]:
        """Détermine la période de reporting"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)  # 30 derniers jours
        
        return {
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat()
        }
    
    def _generate_executive_summary(self) -> Dict[str, Any]:
        """Génère le résumé exécutif"""
        total_findings = self.security_metrics['total_findings']
        critical_findings = self.security_metrics['findings_by_severity']['critical']
        high_findings = self.security_metrics['findings_by_severity']['high']
        
        return {
            'total_findings': total_findings,
            'critical_findings': critical_findings,
            'high_findings': high_findings,
            'risk_level': 'high' if critical_findings > 0 else 'medium' if high_findings > 2 else 'low',
            'key_concerns': self._identify_key_concerns()
        }
    
    def _generate_findings_summary(self) -> Dict[str, Any]:
        """Génère le résumé des findings"""
        return {
            'findings_by_category': self.security_metrics['findings_by_category'],
            'findings_by_severity': self.security_metrics['findings_by_severity'],
            'open_findings': len([f for f in self.findings_registry.values() if f.remediation_status == "open"]),
            'resolved_findings': len([f for f in self.findings_registry.values() if f.remediation_status == "resolved"])
        }
    
    def _generate_risk_summary(self) -> Dict[str, Any]:
        """Génère le résumé des évaluations de risques"""
        if not self.risk_assessments:
            return {'total_assessments': 0}
        
        risk_scores = [assessment.risk_score for assessment in self.risk_assessments.values()]
        
        return {
            'total_assessments': len(self.risk_assessments),
            'average_risk_score': sum(risk_scores) / len(risk_scores),
            'max_risk_score': max(risk_scores),
            'high_risk_assessments': len([r for r in risk_scores if r > 0.7])
        }
    
    def _generate_metrics_summary(self) -> Dict[str, Any]:
        """Génère le résumé des métriques"""
        mttd_mttr = self.calculate_mttd_mttr()
        
        return {
            'mttd_avg_minutes': mttd_mttr.get('mttd_avg_minutes', 0),
            'mttr_avg_minutes': mttd_mttr.get('mttr_avg_minutes', 0),
            'mttd_compliance': mttd_mttr.get('mttd_compliance', False),
            'mttr_compliance': mttd_mttr.get('mttr_compliance', False)
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Génère les recommandations de sécurité"""
        recommendations = []
        
        # Recommandations basées sur les findings
        if self.security_metrics['findings_by_severity']['critical'] > 0:
            recommendations.append("Traiter immédiatement les findings critiques")
        
        if self.security_metrics['findings_by_category']['prompt_injection'] > 0:
            recommendations.append("Renforcer la détection d'injection de prompts")
        
        if self.security_metrics['findings_by_category']['secrets_exposure'] > 0:
            recommendations.append("Améliorer la détection et rédaction de secrets")
        
        # Recommandations basées sur les métriques
        mttd_mttr = self.calculate_mttd_mttr()
        if not mttd_mttr.get('mttd_compliance', False):
            recommendations.append("Améliorer les temps de détection (MTTD)")
        
        if not mttd_mttr.get('mttr_compliance', False):
            recommendations.append("Améliorer les temps de résolution (MTTR)")
        
        return recommendations
    
    def _generate_compliance_status(self) -> Dict[str, Any]:
        """Génère le statut de conformité"""
        return {
            'mttd_compliant': self.calculate_mttd_mttr().get('mttd_compliance', False),
            'mttr_compliant': self.calculate_mttd_mttr().get('mttr_compliance', False),
            'overall_compliance': 'compliant' if self.calculate_mttd_mttr().get('mttd_compliance', False) and self.calculate_mttd_mttr().get('mttr_compliance', False) else 'non_compliant'
        }
    
    def _identify_key_concerns(self) -> List[str]:
        """Identifie les préoccupations clés"""
        concerns = []
        
        # Préoccupations basées sur les catégories les plus fréquentes
        category_counts = self.security_metrics['findings_by_category']
        top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        
        for category, count in top_categories:
            if count > 0:
                concerns.append(f"Nombre élevé de findings {category}: {count}")
        
        return concerns
    
    def _map_to_owasp_llm(self) -> Dict[str, List[str]]:
        """Mappe les findings vers OWASP LLM Top 10"""
        owasp_mapping = {
            "LLM01_Prompt_Injection": [],
            "LLM02_Insecure_Output_Handling": [],
            "LLM03_Training_Data_Poisoning": [],
            "LLM04_Model_DoS": [],
            "LLM05_Supply_Chain_Vulnerabilities": [],
            "LLM06_Sensitive_Information_Disclosure": [],
            "LLM07_Insecure_Plugin_Design": [],
            "LLM08_Excessive_Agency": [],
            "LLM09_Overreliance": [],
            "LLM10_Model_Theft": []
        }
        
        # Mapping des catégories vers OWASP LLM
        category_mapping = {
            RiskCategory.PROMPT_INJECTION: "LLM01_Prompt_Injection",
            RiskCategory.JAILBREAK: "LLM01_Prompt_Injection",
            RiskCategory.PII_LEAKAGE: "LLM06_Sensitive_Information_Disclosure",
            RiskCategory.SECRETS_EXPOSURE: "LLM06_Sensitive_Information_Disclosure",
            RiskCategory.TOXIC_CONTENT: "LLM02_Insecure_Output_Handling",
            RiskCategory.ADVERSARIAL_ATTACK: "LLM01_Prompt_Injection",
            RiskCategory.SUPPLY_CHAIN_COMPROMISE: "LLM05_Supply_Chain_Vulnerabilities",
            RiskCategory.MODEL_POISONING: "LLM03_Training_Data_Poisoning"
        }
        
        for finding in self.findings_registry.values():
            if finding.category in category_mapping:
                owasp_category = category_mapping[finding.category]
                owasp_mapping[owasp_category].append(finding.id)
        
        return owasp_mapping
    
    def _map_to_nist(self) -> Dict[str, List[str]]:
        """Mappe les findings vers le framework NIST"""
        # Simplification pour l'exemple
        return {"NIST_Cybersecurity_Framework": [f.id for f in self.findings_registry.values()]}
    
    def _map_to_iso27001(self) -> Dict[str, List[str]]:
        """Mappe les findings vers ISO 27001"""
        # Simplification pour l'exemple
        return {"ISO27001_Controls": [f.id for f in self.findings_registry.values()]}
