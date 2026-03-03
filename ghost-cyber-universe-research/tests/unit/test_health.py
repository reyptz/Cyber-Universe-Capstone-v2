# Tests pour l'application FastAPI

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)


# === PHASE 1: TESTS DE BASE ===

def test_health_endpoint():
    """Test de l'endpoint de santé"""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["status"] == "ok"
    assert "timestamp" in data
    assert "uptime" in data


def test_root_endpoint():
    """Test de l'endpoint racine"""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "version" in data
    assert "endpoints" in data


def test_get_items():
    """Test de récupération des items"""
    response = client.get("/api/v1/items")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["id"] == 1
    assert data[0]["name"] == "alpha"


def test_create_item():
    """Test de création d'un item"""
    item_data = {
        "id": 3,
        "name": "Test Item"
    }
    response = client.post("/api/v1/items", json=item_data)
    assert response.status_code == 200
    data = response.json()
    assert "created" in data
    assert data["created"]["id"] == item_data["id"]
    assert data["created"]["name"] == item_data["name"]


def test_create_item_validation():
    """Test de validation des données d'entrée"""
    # Test avec données invalides
    invalid_data = {
        "name": "",  # Nom vide
        "description": "x" * 1001  # Description trop longue
    }
    response = client.post("/api/v1/items", json=invalid_data)
    assert response.status_code == 422


# === PHASE 2: TESTS DE SÉCURITÉ ===

def test_security_headers():
    """Test de la présence des headers de sécurité"""
    response = client.get("/health")
    headers = response.headers

    # Vérification des headers de sécurité
    assert "x-content-type-options" in headers
    assert headers["x-content-type-options"] == "nosniff"

    assert "x-frame-options" in headers
    assert headers["x-frame-options"] == "DENY"

    assert "referrer-policy" in headers
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"

    # HSTS seulement en production
    # assert "strict-transport-security" in headers


def test_cors_configuration():
    """Test de la configuration CORS"""
    # Test avec origine autorisée
    headers = {"Origin": "http://localhost:3000"}
    response = client.get("/health", headers=headers)
    assert response.status_code == 200


def test_input_sanitization():
    """Test de la sanitisation des entrées"""
    # Test avec tentative d'injection
    malicious_data = {
        "name": "<script>alert('xss')</script>",
        "description": "'; DROP TABLE items; --"
    }
    response = client.post("/api/v1/items", json=malicious_data)
    # L'application doit soit rejeter soit sanitiser
    if response.status_code == 201:
        data = response.json()
        # Vérifier que les scripts sont échappés/supprimés
        assert "<script>" not in data["name"]
        assert "DROP TABLE" not in data["description"]


def test_large_payload():
    """Test de protection contre les gros payloads"""
    large_data = {
        "name": "x" * 10000,
        "description": "y" * 50000
    }
    response = client.post("/api/v1/items", json=large_data)
    # Doit être rejeté (422 pour validation ou 413 pour taille)
    assert response.status_code in [413, 422]


def test_sql_injection_protection():
    """Test de protection contre l'injection SQL"""
    sql_injection_attempts = [
        "'; DROP TABLE items; --",
        "1' OR '1'='1",
        "admin'--",
        "' UNION SELECT * FROM users --"
    ]

    for injection in sql_injection_attempts:
        item_data = {
            "name": injection,
            "description": "Test description"
        }
        response = client.post("/api/v1/items", json=item_data)
        # L'application ne doit pas planter
        assert response.status_code != 500


def test_404_handling():
    """Test de gestion des erreurs 404"""
    response = client.get("/nonexistent")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"] == "not found"


def test_method_not_allowed():
    """Test de gestion des méthodes non autorisées"""
    response = client.delete("/health")
    assert response.status_code == 405


# === TESTS DE PERFORMANCE ===

def test_response_time():
    """Test du temps de réponse"""
    import time
    start_time = time.time()
    response = client.get("/health")
    end_time = time.time()

    assert response.status_code == 200
    response_time = end_time - start_time
    # Le temps de réponse doit être inférieur à 1 seconde
    assert response_time < 1.0


# === TESTS D'INTÉGRATION ===

def test_full_workflow():
    """Test du workflow complet"""
    # 1. Vérifier la santé
    health_response = client.get("/health")
    assert health_response.status_code == 200

    # 2. Créer un item
    item_data = {
        "id": 4,
        "name": "Integration Test Item"
    }
    create_response = client.post("/api/v1/items", json=item_data)
    assert create_response.status_code == 200
    assert "created" in create_response.json()

    # 3. Récupérer la liste des items
    list_response = client.get("/api/v1/items")
    assert list_response.status_code == 200
    items = list_response.json()
    assert len(items) == 2  # alpha et beta


if __name__ == "__main__":
    pytest.main(["-v", __file__])