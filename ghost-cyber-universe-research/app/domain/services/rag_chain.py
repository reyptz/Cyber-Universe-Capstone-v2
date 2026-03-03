"""
Chaîne RAG sécurisée avec toutes les fonctionnalités de sécurité
"""
import logging
from typing import List, Dict, Any, Optional, Tuple
from langchain.embeddings import HuggingFaceEmbeddings
from langchain.vectorstores import Chroma
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.chains import RetrievalQA
from langchain.llms import OpenAI
from langchain.document_loaders import TextLoader
import os
from pathlib import Path

# Import des modules de sécurité
from ..security.pii_filter import PIIFilter
from ..security.content_moderation import ContentModerator
from ..security.embedding_security import EmbeddingSecurity
from ..security.injection_detection import InjectionDetector
from ..security.secrets_detection import SecretsDetector
from ..security.supply_chain_security import SupplyChainSecurity
from ..security.adversarial_detection import AdversarialDetector
from ..security.governance import SecurityGovernance, SecurityFinding, RiskCategory, SeverityLevel
from ..config import config

logger = logging.getLogger(__name__)

class SecureRAGChain:
    """Chaîne RAG sécurisée avec toutes les protections"""
    
    def __init__(self, docs_directory: str = "docs", openai_api_key: Optional[str] = None):
        """
        Initialise la chaîne RAG sécurisée
        
        Args:
            docs_directory: Répertoire contenant les documents
            openai_api_key: Clé API OpenAI (optionnelle)
        """
        try:
            # Initialisation des modules de sécurité
            self.pii_filter = PIIFilter()
            self.content_moderator = ContentModerator()
            self.embedding_security = EmbeddingSecurity()
            self.injection_detector = InjectionDetector()
            self.secrets_detector = SecretsDetector()
            self.supply_chain_security = SupplyChainSecurity()
            self.adversarial_detector = AdversarialDetector()
            self.governance = SecurityGovernance()
            
            # Configuration des composants RAG
            self.docs_directory = docs_directory
            self.openai_api_key = openai_api_key or os.getenv("OPENAI_API_KEY")
            
            # Initialisation des composants LangChain
            self._initialize_rag_components()
            
            # Vérification de la chaîne d'approvisionnement
            self._verify_supply_chain()
            
            logger.info("Chaîne RAG sécurisée initialisée avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation de la chaîne RAG: {e}")
            raise
    
    def _initialize_rag_components(self):
        """Initialise les composants RAG de base"""
        try:
            # Configuration des embeddings sécurisés
            self.embeddings = HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-MiniLM-L6-v2"
            )
            
            # Configuration du splitter de texte
            self.text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=1000,
                chunk_overlap=200
            )
            
            # Initialisation du vector store
            self.vectorstore = None
            
            # Configuration du LLM
            if self.openai_api_key:
                self.llm = OpenAI(
                    openai_api_key=self.openai_api_key,
                    temperature=0.1,
                    max_tokens=500
                )
            else:
                logger.warning("Clé API OpenAI non fournie, utilisation d'un modèle local")
                # Utilisation d'un modèle local en fallback
                self.llm = None
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation des composants RAG: {e}")
            raise
    
    def _verify_supply_chain(self):
        """Vérifie la sécurité de la chaîne d'approvisionnement"""
        try:
            # Vérification de l'intégrité des modèles
            model_verification = self.supply_chain_security.verify_model_integrity(
                "sentence-transformers/all-MiniLM-L6-v2"
            )
            
            if not model_verification.get('verified', False):
                logger.warning("Vérification d'intégrité du modèle échouée")
                self._record_security_finding(
                    "MODEL_INTEGRITY_FAILURE",
                    RiskCategory.SUPPLY_CHAIN_COMPROMISE,
                    SeverityLevel.HIGH,
                    "Échec de la vérification d'intégrité du modèle d'embedding"
                )
            
            # Génération du SBOM
            sbom_result = self.supply_chain_security.generate_sbom(".")
            if sbom_result.get('sbom_generated', False):
                logger.info(f"SBOM généré avec {sbom_result['components_count']} composants")
            
            # Configuration du sandbox
            sandbox_result = self.supply_chain_security.setup_sandbox_environment()
            if sandbox_result.get('sandbox_configured', False):
                logger.info("Environnement sandbox configuré")
            
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de la chaîne d'approvisionnement: {e}")
    
    def load_and_process_documents(self) -> Dict[str, Any]:
        """
        Charge et traite les documents de manière sécurisée
        
        Returns:
            Résultat du traitement des documents
        """
        try:
            docs_path = Path(self.docs_directory)
            if not docs_path.exists():
                return {'success': False, 'error': 'Répertoire de documents non trouvé'}
            
            all_documents = []
            processing_results = {
                'total_documents': 0,
                'processed_documents': 0,
                'security_issues': 0,
                'secrets_detected': 0,
                'pii_detected': 0
            }
            
            # Traitement de chaque document
            for doc_file in docs_path.glob("*.txt"):
                processing_results['total_documents'] += 1
                
                try:
                    # Chargement du document
                    loader = TextLoader(str(doc_file))
                    documents = loader.load()
                    
                    for doc in documents:
                        # Traitement sécurisé du contenu
                        secure_result = self._process_document_content(doc.page_content, str(doc_file))
                        
                        if secure_result['is_safe']:
                            # Ajout du document traité
                            doc.page_content = secure_result['processed_content']
                            all_documents.append(doc)
                            processing_results['processed_documents'] += 1
                        else:
                            processing_results['security_issues'] += 1
                            
                            # Enregistrement des problèmes de sécurité
                            if secure_result.get('secrets_detected', False):
                                processing_results['secrets_detected'] += 1
                                self._record_security_finding(
                                    f"SECRETS_IN_DOC_{doc_file.name}",
                                    RiskCategory.SECRETS_EXPOSURE,
                                    SeverityLevel.HIGH,
                                    f"Secrets détectés dans le document {doc_file.name}"
                                )
                            
                            if secure_result.get('pii_detected', False):
                                processing_results['pii_detected'] += 1
                                self._record_security_finding(
                                    f"PII_IN_DOC_{doc_file.name}",
                                    RiskCategory.PII_LEAKAGE,
                                    SeverityLevel.MEDIUM,
                                    f"PII détecté dans le document {doc_file.name}"
                                )
                
                except Exception as e:
                    logger.error(f"Erreur lors du traitement du document {doc_file}: {e}")
                    processing_results['security_issues'] += 1
            
            # Création du vector store si des documents sont disponibles
            if all_documents:
                # Découpage des documents
                split_docs = self.text_splitter.split_documents(all_documents)
                
                # Création du vector store avec embeddings sécurisés
                self.vectorstore = Chroma.from_documents(
                    documents=split_docs,
                    embedding=self.embeddings,
                    persist_directory="./chroma_db"
                )
                
                # Configuration de la chaîne de récupération
                self.retrieval_chain = RetrievalQA.from_chain_type(
                    llm=self.llm,
                    chain_type="stuff",
                    retriever=self.vectorstore.as_retriever(search_kwargs={"k": 3}),
                    return_source_documents=True
                )
                
                processing_results['success'] = True
                processing_results['vectorstore_created'] = True
                processing_results['total_chunks'] = len(split_docs)
            else:
                processing_results['success'] = False
                processing_results['error'] = 'Aucun document sécurisé disponible'
            
            return processing_results
            
        except Exception as e:
            logger.error(f"Erreur lors du chargement des documents: {e}")
            return {'success': False, 'error': str(e)}
    
    def _process_document_content(self, content: str, source: str) -> Dict[str, Any]:
        """
        Traite le contenu d'un document de manière sécurisée
        
        Args:
            content: Contenu du document
            source: Source du document
            
        Returns:
            Résultat du traitement sécurisé
        """
        try:
            # Détection et rédaction de secrets
            secrets_result = self.secrets_detector.process_text_with_secrets(content)
            if secrets_result['secrets_detected']:
                content = secrets_result['processed_text']
            
            # Filtrage PII
            pii_result = self.pii_filter.sanitize_for_rag(content)
            if not pii_result['compliance']['is_compliant']:
                content = pii_result['cleaned_text']
            
            # Modération de contenu
            moderation_result = self.content_moderator.moderate_content(content)
            if moderation_result['should_block']:
                return {
                    'is_safe': False,
                    'reason': 'Contenu modéré bloqué',
                    'moderation_result': moderation_result
                }
            
            return {
                'is_safe': True,
                'processed_content': content,
                'secrets_detected': secrets_result['secrets_detected'],
                'pii_detected': not pii_result['compliance']['is_compliant'],
                'moderation_result': moderation_result
            }
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement sécurisé du contenu: {e}")
            return {'is_safe': False, 'reason': f'Erreur de traitement: {str(e)}'}
    
    def secure_query(self, query: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Exécute une requête de manière sécurisée
        
        Args:
            query: Requête de l'utilisateur
            user_id: Identifiant de l'utilisateur (optionnel)
            
        Returns:
            Résultat sécurisé de la requête
        """
        try:
            # Vérification de l'initialisation
            if not self.vectorstore or not self.retrieval_chain:
                return {
                    'success': False,
                    'error': 'Chaîne RAG non initialisée. Veuillez charger les documents d\'abord.'
                }
            
            # Analyse de sécurité de la requête
            security_analysis = self._analyze_query_security(query)
            
            if not security_analysis['is_safe']:
                # Enregistrement de la tentative d'attaque
                self._record_security_finding(
                    f"ATTACK_ATTEMPT_{user_id or 'anonymous'}",
                    security_analysis['risk_category'],
                    security_analysis['severity'],
                    f"Tentative d'attaque détectée: {security_analysis['reason']}"
                )
                
                return {
                    'success': False,
                    'error': 'Requête bloquée pour des raisons de sécurité',
                    'security_analysis': security_analysis
                }
            
            # Exécution de la requête
            try:
                result = self.retrieval_chain({"query": query})
                
                # Analyse de sécurité de la réponse
                response_analysis = self._analyze_response_security(result['result'])
                
                if response_analysis['should_quarantine']:
                    # Mise en quarantaine de la réponse
                    quarantine_result = self.adversarial_detector.quarantine_content(
                        f"response_{user_id or 'anonymous'}_{self._get_timestamp()}",
                        result['result'],
                        response_analysis
                    )
                    
                    return {
                        'success': False,
                        'error': 'Réponse mise en quarantaine pour des raisons de sécurité',
                        'quarantine_result': quarantine_result,
                        'response_analysis': response_analysis
                    }
                
                # Traitement sécurisé de la réponse finale
                final_response = self._secure_final_response(result['result'])
                
                return {
                    'success': True,
                    'answer': final_response,
                    'source_documents': result.get('source_documents', []),
                    'security_analysis': security_analysis,
                    'response_analysis': response_analysis
                }
                
            except Exception as e:
                logger.error(f"Erreur lors de l'exécution de la requête: {e}")
                return {
                    'success': False,
                    'error': f'Erreur lors de l\'exécution de la requête: {str(e)}'
                }
            
        except Exception as e:
            logger.error(f"Erreur lors de la requête sécurisée: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_query_security(self, query: str) -> Dict[str, Any]:
        """
        Analyse la sécurité d'une requête
        
        Args:
            query: Requête à analyser
            
        Returns:
            Résultat de l'analyse de sécurité
        """
        try:
            # Détection d'injection de prompts
            injection_analysis = self.injection_detector.comprehensive_injection_analysis(query)
            
            # Détection de secrets dans la requête
            secrets_analysis = self.secrets_detector.detect_secrets(query)
            
            # Modération de contenu
            moderation_analysis = self.content_moderator.moderate_content(query)
            
            # Détermination de la sécurité globale
            is_safe = (
                not injection_analysis['should_block'] and
                not secrets_analysis['has_secrets'] and
                not moderation_analysis['should_block']
            )
            
            # Détermination du niveau de risque et de la catégorie
            risk_scores = [
                injection_analysis['global_risk_score'],
                1.0 if secrets_analysis['has_secrets'] else 0.0,
                1.0 if moderation_analysis['should_block'] else 0.0
            ]
            
            max_risk_score = max(risk_scores)
            
            if max_risk_score > 0.8:
                severity = SeverityLevel.CRITICAL
            elif max_risk_score > 0.6:
                severity = SeverityLevel.HIGH
            elif max_risk_score > 0.4:
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW
            
            # Détermination de la catégorie de risque
            if injection_analysis['should_block']:
                risk_category = RiskCategory.PROMPT_INJECTION
                reason = "Injection de prompts détectée"
            elif secrets_analysis['has_secrets']:
                risk_category = RiskCategory.SECRETS_EXPOSURE
                reason = "Secrets détectés dans la requête"
            elif moderation_analysis['should_block']:
                risk_category = RiskCategory.TOXIC_CONTENT
                reason = "Contenu toxique détecté"
            else:
                risk_category = RiskCategory.PROMPT_INJECTION  # Par défaut
                reason = "Aucun problème détecté"
            
            return {
                'is_safe': is_safe,
                'risk_score': max_risk_score,
                'risk_category': risk_category,
                'severity': severity,
                'reason': reason,
                'injection_analysis': injection_analysis,
                'secrets_analysis': secrets_analysis,
                'moderation_analysis': moderation_analysis
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de sécurité de la requête: {e}")
            return {
                'is_safe': False,
                'risk_score': 1.0,
                'risk_category': RiskCategory.PROMPT_INJECTION,
                'severity': SeverityLevel.CRITICAL,
                'reason': f'Erreur d\'analyse: {str(e)}'
            }
    
    def _analyze_response_security(self, response: str) -> Dict[str, Any]:
        """
        Analyse la sécurité d'une réponse
        
        Args:
            response: Réponse à analyser
            
        Returns:
            Résultat de l'analyse de sécurité de la réponse
        """
        try:
            # Analyse adversarial complète
            adversarial_analysis = self.adversarial_detector.comprehensive_adversarial_analysis(response)
            
            # Détection de fuite d'informations
            leakage_analysis = self.adversarial_detector.detect_information_leakage(response)
            
            # Détection de secrets dans la réponse
            secrets_analysis = self.secrets_detector.detect_secrets(response)
            
            # Détermination de la mise en quarantaine
            should_quarantine = (
                adversarial_analysis['should_quarantine'] or
                leakage_analysis['has_leakage'] or
                secrets_analysis['has_secrets']
            )
            
            return {
                'should_quarantine': should_quarantine,
                'adversarial_analysis': adversarial_analysis,
                'leakage_analysis': leakage_analysis,
                'secrets_analysis': secrets_analysis,
                'analysis_timestamp': self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de sécurité de la réponse: {e}")
            return {
                'should_quarantine': True,  # En cas d'erreur, mettre en quarantaine par sécurité
                'error': str(e)
            }
    
    def _secure_final_response(self, response: str) -> str:
        """
        Sécurise la réponse finale
        
        Args:
            response: Réponse à sécuriser
            
        Returns:
            Réponse sécurisée
        """
        try:
            # Rédaction des secrets
            secrets_result = self.secrets_detector.process_text_with_secrets(response)
            if secrets_result['secrets_detected']:
                response = secrets_result['processed_text']
            
            # Anonymisation PII
            pii_result = self.pii_filter.sanitize_for_rag(response)
            if not pii_result['compliance']['is_compliant']:
                response = pii_result['cleaned_text']
            
            return response
            
        except Exception as e:
            logger.error(f"Erreur lors de la sécurisation de la réponse finale: {e}")
            return "Erreur lors de la sécurisation de la réponse."
    
    def _record_security_finding(self, finding_id: str, category: RiskCategory, severity: SeverityLevel, description: str):
        """Enregistre un finding de sécurité"""
        try:
            finding = SecurityFinding(
                id=finding_id,
                category=category,
                severity=severity,
                description=description,
                timestamp=self._get_timestamp(),
                source="rag_chain",
                affected_components=["rag_chain"],
                detection_method="automated",
                confidence_score=0.9
            )
            
            self.governance.record_security_finding(finding)
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement du finding: {e}")
    
    def get_security_status(self) -> Dict[str, Any]:
        """
        Retourne le statut de sécurité du système
        
        Returns:
            Statut de sécurité complet
        """
        try:
            # Statut de la quarantaine
            quarantine_status = self.adversarial_detector.get_quarantine_status()
            
            # Métriques de gouvernance
            mttd_mttr = self.governance.calculate_mttd_mttr()
            
            # Surveillance de la chaîne d'approvisionnement
            supply_chain_risks = self.supply_chain_security.monitor_supply_chain_risks()
            
            # Findings priorisés
            prioritized_findings = self.governance.prioritize_findings()
            
            return {
                'system_status': 'operational',
                'quarantine_status': quarantine_status,
                'mttd_mttr_metrics': mttd_mttr,
                'supply_chain_risks': supply_chain_risks,
                'prioritized_findings': prioritized_findings[:5],  # Top 5
                'security_timestamp': self._get_timestamp()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du statut de sécurité: {e}")
            return {'system_status': 'error', 'error': str(e)}
    
    def generate_security_report(self) -> Dict[str, Any]:
        """
        Génère un rapport de sécurité complet
        
        Returns:
            Rapport de sécurité
        """
        try:
            return self.governance.generate_security_report("comprehensive")
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport de sécurité: {e}")
            return {'report_generated': False, 'error': str(e)}
    
    def _get_timestamp(self) -> str:
        """Retourne le timestamp actuel"""
        from datetime import datetime
        return datetime.utcnow().isoformat()
