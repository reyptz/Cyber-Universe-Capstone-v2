"""
Module de métriques Prometheus pour l'assistant RAG sécurisé
"""
import time
import logging
from typing import Dict, Any
from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest, CONTENT_TYPE_LATEST
from fastapi import Request, Response
from fastapi.responses import PlainTextResponse

logger = logging.getLogger(__name__)

# Métriques de base
rag_requests_total = Counter(
    'rag_requests_total',
    'Nombre total de requêtes RAG',
    ['method', 'endpoint', 'status']
)

rag_response_time_seconds = Histogram(
    'rag_response_time_seconds',
    'Temps de réponse des requêtes RAG',
    ['method', 'endpoint']
)

rag_active_connections = Gauge(
    'rag_active_connections',
    'Nombre de connexions actives'
)

# Métriques de sécurité
security_attacks_detected_total = Counter(
    'security_attacks_detected_total',
    'Nombre total d\'attaques détectées',
    ['attack_type', 'severity']
)

security_quarantine_items_total = Gauge(
    'security_quarantine_items_total',
    'Nombre d\'éléments en quarantaine'
)

security_findings_total = Counter(
    'security_findings_total',
    'Nombre total de findings de sécurité',
    ['category', 'severity']
)

# Métriques de performance
rag_embedding_generation_time = Histogram(
    'rag_embedding_generation_time_seconds',
    'Temps de génération des embeddings'
)

rag_vector_search_time = Histogram(
    'rag_vector_search_time_seconds',
    'Temps de recherche vectorielle'
)

rag_llm_inference_time = Histogram(
    'rag_llm_inference_time_seconds',
    'Temps d\'inférence du LLM'
)

# Métriques de qualité
rag_response_quality_score = Histogram(
    'rag_response_quality_score',
    'Score de qualité des réponses',
    buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
)

rag_source_documents_count = Histogram(
    'rag_source_documents_count',
    'Nombre de documents sources utilisés'
)

# Métriques système
system_memory_usage = Gauge(
    'system_memory_usage_bytes',
    'Utilisation de la mémoire système'
)

system_cpu_usage = Gauge(
    'system_cpu_usage_percent',
    'Utilisation du CPU système'
)

# Informations système
system_info = Info(
    'system_info',
    'Informations sur le système'
)

class MetricsCollector:
    """Collecteur de métriques pour l'assistant RAG"""
    
    def __init__(self):
        """Initialise le collecteur de métriques"""
        self.start_time = time.time()
        
        # Enregistrement des informations système
        system_info.info({
            'version': '1.0.0',
            'service': 'rag-assistant-secure',
            'environment': 'production'
        })
    
    def record_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Enregistre une requête"""
        rag_requests_total.labels(
            method=method,
            endpoint=endpoint,
            status=status_code
        ).inc()
        
        rag_response_time_seconds.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
    
    def record_security_attack(self, attack_type: str, severity: str):
        """Enregistre une attaque détectée"""
        security_attacks_detected_total.labels(
            attack_type=attack_type,
            severity=severity
        ).inc()
    
    def record_security_finding(self, category: str, severity: str):
        """Enregistre un finding de sécurité"""
        security_findings_total.labels(
            category=category,
            severity=severity
        ).inc()
    
    def update_quarantine_count(self, count: int):
        """Met à jour le nombre d'éléments en quarantaine"""
        security_quarantine_items_total.set(count)
    
    def record_embedding_time(self, duration: float):
        """Enregistre le temps de génération d'embedding"""
        rag_embedding_generation_time.observe(duration)
    
    def record_vector_search_time(self, duration: float):
        """Enregistre le temps de recherche vectorielle"""
        rag_vector_search_time.observe(duration)
    
    def record_llm_inference_time(self, duration: float):
        """Enregistre le temps d'inférence du LLM"""
        rag_llm_inference_time.observe(duration)
    
    def record_response_quality(self, score: float):
        """Enregistre le score de qualité de la réponse"""
        rag_response_quality_score.observe(score)
    
    def record_source_documents_count(self, count: int):
        """Enregistre le nombre de documents sources"""
        rag_source_documents_count.observe(count)
    
    def update_system_metrics(self, memory_usage: float, cpu_usage: float):
        """Met à jour les métriques système"""
        system_memory_usage.set(memory_usage)
        system_cpu_usage.set(cpu_usage)
    
    def get_metrics(self) -> str:
        """Retourne les métriques au format Prometheus"""
        return generate_latest()

# Instance globale du collecteur
metrics_collector = MetricsCollector()

def get_metrics_response() -> Response:
    """Retourne une réponse HTTP avec les métriques"""
    metrics_data = metrics_collector.get_metrics()
    return PlainTextResponse(
        content=metrics_data,
        media_type=CONTENT_TYPE_LATEST
    )

def record_request_metrics(request: Request, response: Response, duration: float):
    """Enregistre les métriques d'une requête"""
    try:
        method = request.method
        endpoint = request.url.path
        
        # Détermination du statut
        if hasattr(response, 'status_code'):
            status_code = response.status_code
        else:
            status_code = 200
        
        metrics_collector.record_request(method, endpoint, status_code, duration)
        
    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement des métriques: {e}")

def record_security_metrics(security_analysis: Dict[str, Any]):
    """Enregistre les métriques de sécurité"""
    try:
        if not security_analysis.get('is_safe', True):
            attack_type = security_analysis.get('risk_category', 'unknown')
            severity = security_analysis.get('severity', 'unknown')
            
            metrics_collector.record_security_attack(attack_type, severity)
        
        # Enregistrement des findings
        if 'injection_analysis' in security_analysis:
            injection = security_analysis['injection_analysis']
            if injection.get('is_injection', False):
                metrics_collector.record_security_finding('prompt_injection', 'high')
        
        if 'secrets_analysis' in security_analysis:
            secrets = security_analysis['secrets_analysis']
            if secrets.get('has_secrets', False):
                metrics_collector.record_security_finding('secrets_exposure', 'critical')
        
        if 'moderation_analysis' in security_analysis:
            moderation = security_analysis['moderation_analysis']
            if moderation.get('should_block', False):
                metrics_collector.record_security_finding('toxic_content', 'medium')
        
    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement des métriques de sécurité: {e}")

def record_rag_metrics(rag_result: Dict[str, Any]):
    """Enregistre les métriques RAG"""
    try:
        # Score de qualité basé sur la présence de documents sources
        source_docs = rag_result.get('source_documents', [])
        quality_score = min(len(source_docs) / 3.0, 1.0)  # Normalisation sur 3 documents
        
        metrics_collector.record_response_quality(quality_score)
        metrics_collector.record_source_documents_count(len(source_docs))
        
    except Exception as e:
        logger.error(f"Erreur lors de l'enregistrement des métriques RAG: {e}")

def update_system_metrics():
    """Met à jour les métriques système"""
    try:
        import psutil
        
        # Utilisation de la mémoire
        memory = psutil.virtual_memory()
        memory_usage = memory.used
        
        # Utilisation du CPU
        cpu_usage = psutil.cpu_percent(interval=1)
        
        metrics_collector.update_system_metrics(memory_usage, cpu_usage)
        
    except ImportError:
        logger.warning("psutil non disponible, métriques système ignorées")
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour des métriques système: {e}")
