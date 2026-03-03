"""
DevSecOps - Point d'entrée principal
Orchestrateur des composants de sécurité pour Ghost Cyber Universe
"""

import asyncio
import json
from typing import Dict, Any

from .pipeline import SecurePipeline, PipelineStage
from .secrets import SecretsManager, SecretType
from .scanner import VulnerabilityScanner
from .policies import SecurityPolicies, PolicyStatus


class DevSecOpsOrchestrator:
    """Orchestrateur principal des composants DevSecOps"""
    
    def __init__(self):
        # Composants principaux selon l'architecture Ghost Cyber Universe
        self.pipeline = SecurePipeline()
        self.secrets_manager = SecretsManager()
        self.scanner = VulnerabilityScanner()
        self.policies = SecurityPolicies()
        
    async def initialize(self) -> bool:
        """Initialise tous les composants DevSecOps"""
        print("Initialisation DevSecOps...")
        
        components = [
            ("Pipeline", self.pipeline),
            ("Secrets", self.secrets_manager),
            ("Scanner", self.scanner),
            ("Policies", self.policies)
        ]
        
        for name, component in components:
            if not await component.initialize():
                print(f"Échec initialisation {name}")
                return False
            print(f" {name} initialisé")
        
        return True
    
    async def demo_secrets(self):
        """Démontre la gestion sécurisée des secrets"""
        print("\n Gestion des secrets...")
        
        # Secrets critiques selon les spécifications
        secrets = [
            ("github_token", "ghp_secure_token", SecretType.API_KEY, "Token GitHub CI/CD"),
            ("db_prod_pwd", "SecurePass123!", SecretType.DATABASE_PASSWORD, "DB Production"),
            ("jwt_key", "jwt-signing-key", SecretType.JWT_SECRET, "Signature JWT")
        ]
        
        # Stockage sécurisé
        for secret_id, value, type_, desc in secrets:
            await self.secrets_manager.store_secret(secret_id, value, type_, desc)
        
        # Génération mot de passe sécurisé
        secure_pwd = await self.secrets_manager.generate_secure_password(16)
        print(f"Mot de passe généré: {secure_pwd}")
        
        # Rapport de sécurité
        report = await self.secrets_manager.get_security_report()
        print(f"Score sécurité: {report['security_score']}/100")
    
    async def demo_scanning(self):
        """Démontre les scans de vulnérabilités (SAST, DAST, SCA, IaC)"""
        print("\n Scans de sécurité...")
        
        # SAST - Analyse statique du code
        sast_result = await self.scanner.run_sast_scan("src/")
        print(f"SAST: {len(sast_result.vulnerabilities)} vulnérabilités")
        
        # SCA - Analyse des dépendances
        sca_result = await self.scanner.run_sca_scan(".")
        print(f"SCA: {len(sca_result.vulnerabilities)} vulnérabilités")
        
        # IaC - Infrastructure as Code
        iac_result = await self.scanner.run_iac_scan("infra/")
        print(f"IaC: {len(iac_result.vulnerabilities)} vulnérabilités")
        
        # Rapport global de sécurité
        security_report = await self.scanner.generate_security_report()
        summary = security_report['summary']
        print(f"Total: {summary['total_vulnerabilities']} vulnérabilités")
        print(f"   Critiques: {summary['severity_breakdown']['critical']}")
        print(f"   Élevées: {summary['severity_breakdown']['high']}")
    
    async def demo_policies(self):
        """Démontre les politiques de sécurité automatisées (OPA/Gatekeeper, RBAC, ABAC)"""
        print("\n Politiques de sécurité...")
        
        # Politiques actives
        active_policies = await self.policies.list_policies(status=PolicyStatus.ACTIVE)
        print(f"Politiques actives: {len(active_policies)}")
        
        # Test politique mot de passe faible
        weak_data = {
            "password_length": 6,
            "password_complexity": ["lowercase"],
            "password_age": 180
        }
        
        compliant, violations = await self.policies.evaluate_policy("password_policy", weak_data)
        if not compliant:
            print("Politique mot de passe violée:")
            for violation in violations[:2]:  # Limite affichage
                print(f"   - {violation}")
        
        # Statistiques conformité
        stats = await self.policies.get_policy_statistics()
        print(f"Violations non résolues: {stats['unresolved_violations']}")
    
    async def demo_pipeline(self):
        """Démontre le pipeline CI/CD sécurisé (GitHub Actions, monitoring)"""
        print("\n Pipeline CI/CD sécurisé...")
        
        # Callback pour événements pipeline
        async def on_pipeline_event(event_type: str, data: Any = None):
            print(f" {event_type}")
        
        await self.pipeline.add_callback(on_pipeline_event)
        
        # Exécution pipeline jusqu'aux tests
        success = await self.pipeline.run_pipeline(PipelineStage.TEST)
        status_icon = "✅" if success else "❌"
        print(f"{status_icon} Pipeline terminé")
        
        # Statut détaillé
        status = await self.pipeline.get_pipeline_status()
        print(f"Étapes: {status['completed_steps']}/{status['total_steps']}")
        
        # Rapport sécurité pipeline
        security_report = await self.pipeline.get_security_report()
        print(f" Problèmes critiques: {security_report['critical_issues']}")
    
    async def demo_compliance(self):
        """Démontre la conformité réglementaire (ISO 27001, NIST, SOC 2, GDPR)"""
        print("\n Conformité réglementaire...")
        
        # Standards de conformité selon les spécifications
        frameworks = ["NIST", "ISO27001"]
        
        for framework in frameworks:
            report = await self.policies.generate_compliance_report(framework)
            print(f"  {framework}: {report.compliance_percentage:.1f}% conforme")
            print(f" Politiques: {report.compliant_policies}/{report.total_policies}")
    
    async def run_complete_demo(self):
        """Exécute la démonstration complète du module DevSecOps"""
        print("=" * 60)
        print(" GHOST CYBER UNIVERSE - DevSecOps Demo")
        print("=" * 60)
        
        # Séquence de démonstration
        demos = [
            self.demo_secrets,
            self.demo_scanning,
            self.demo_policies,
            self.demo_pipeline,
            self.demo_compliance
        ]
        
        for demo in demos:
            try:
                await demo()
            except Exception as e:
                print(f" Erreur dans {demo.__name__}: {e}")
        
        print("\n Démonstration DevSecOps terminée")


async def main():
    """Point d'entrée principal"""
    orchestrator = DevSecOpsOrchestrator()
    
    if await orchestrator.initialize():
        await orchestrator.run_complete_demo()
    else:
        print(" Échec de l'initialisation")


if __name__ == "__main__":
    asyncio.run(main())
