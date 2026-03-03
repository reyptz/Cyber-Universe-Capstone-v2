# Ghost Cyber Universe — Capstone v2

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://rust-lang.org)
[![C](https://img.shields.io/badge/C-GNU-blue.svg)](https://gcc.gnu.org)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org)
[![License](https://img.shields.io/badge/License-AGPL%20v3-yellow.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-ISO%2027001-red.svg)](https://www.iso.org/isoiec-27001-information-security.html)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Enabled-purple.svg)](https://www.devsecops.org)

---

## English Version

## Description

Ghost Cyber Universe is an integrated cybersecurity platform designed for security professionals, combining offensive and defensive capabilities with cutting-edge technologies in cryptography, artificial intelligence, and DevSecOps.

## Main Platforms

### Offensive Operations Suite
- **Genjutsu Engine**: Polymorphic payload generation with LLVM (< 3 minutes)
- **Ghost Compiler**: Reflective in-memory injection without traces (Rust no_std)
- **Hiraishin Framework**: Ultra-fast Infrastructure as Code (deploy/destroy < 180s, rollback < 60s)

### Defensive Intelligence Platform
- **Shinra OSINT Agent**: Automated collection (1000 pages/min) with RAG
- **KumoShield S-IA**: Real-time detection (< 200ms) with eBPF, Sigma, YARA
- **Modern Web Interface**: React + TypeScript + TailwindCSS

### Aetherium Module (Cryptography)
- **GKEP Protocol**: Proprietary Ghost Key Exchange Protocol
- **PKI Infrastructure**: X.509, certificate management, CRLs
- **Automatic Rotation**: Intelligent key management with blockchain support
- **Multi-Algorithm Encryption**: AES-GCM, RSA, ECC, RC4 (backward compatibility)
- **Digital Signatures**: ECDSA, Ed25519, HMAC
- **Network Protocols**: SSL/TLS/DTLS, IPsec, QUIC

## Technologies Used

### Backend
- **Python 3.11+**: Main language with FastAPI
- **Rust 1.75+**: Secure services and eBPF
- **C/C++**: Critical performance kernel
- **Go 1.21+**: CLI tools and infrastructure

### Frontend
- **React 18+**: Modern user interface
- **TypeScript**: Strict typing and security
- **TailwindCSS**: Responsive design system
- **Vite**: Optimized build tool

### Artificial Intelligence
- **ML/DL**: PyTorch, TensorFlow/Keras, scikit-learn
- **NLP**: Transformers, LangChain, RAG
- **Vector Databases**: Pinecone, Milvus, Weaviate, FAISS
- **MLOps**: MLflow, TFX, BentoML

### Infrastructure
- **Containerization**: Docker, Kubernetes
- **IaC**: Terraform, Ansible, Pulumi
- **Monitoring**: Prometheus, Grafana, ELK Stack, Jaeger
- **CI/CD**: GitHub Actions with security scans

## Installation

### Technical Prerequisites

#### Mandatory
- **Docker 24+** & **Docker Compose 2.0+**
- **Git**
- **Python 3.11+**
- **Node.js 18+**

#### Optional (for Offensive Ops)
- **Rust 1.75+** (Ghost Compiler)
- **Go 1.21+** (Hiraishin CLI)
- **LLVM 17+** (Genjutsu Engine)

### Quick Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/reyptz/Cyber-Universe-Capstone-v1.git
cd Cyber-Universe-Capstone-v1
```

### Docker Installation (Production)

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# Access services
# - Grafana:    http://localhost:3000 (admin/admin)
# - API Docs:   http://localhost:8000/api/docs
# - Frontend:   http://localhost:5173
# - Prometheus: http://localhost:9090

# View logs
docker-compose logs -f shinra-api
```

## Use Cases

### Red Team / Offensive Security
- **Payload Generation**: Generate undetectable polymorphic shellcodes
- **Stealth Injection**: Inject code in-memory without traces
- **Rapid Infrastructure**: Deploy/destroy attack environments in < 3 minutes
- **Training Labs**: Create ephemeral Red Team exercise labs

### Blue Team / Defensive Security
- **OSINT Collection**: Automatically collect threat intelligence data
- **Real-time Detection**: Detect threats with < 200ms latency
- **Threat Hunting**: Search IOCs with RAG and AI enrichment
- **SOC Automation**: Automate incident response playbooks

### Purple Team / DevSecOps
- **CI/CD Security**: Secure pipelines with SBOM and attestations
- **Supply Chain Security**: Complete traceability with Sigstore/Rekor
- **Performance Monitoring**: Grafana dashboards for operational metrics
- **Compliance**: ISO 27001/27007 and GDPR compliance

## Performance Targets

| Component | Language | Target | Status |
|-----------|---------|--------|---------|
| Payload execution | C | < 500ms | Implemented |
| eBPF detection | Rust | < 150ms | Implemented |
| API response | Python | < 80ms | Implemented |
| UI update | React | < 30ms | Implemented |
| OSINT collection | Python | 1000 pages/min | Implemented |
| Infrastructure deploy | Terraform | < 180s | Implemented |

## Security & Compliance

### Standards
- **ISO 27001**: Information security management
- **NIST Cybersecurity Framework**: Cybersecurity framework
- **SOC 2**: Organizational security controls
- **GDPR**: Personal data protection
- **SLSA v1.2**: Supply-chain security

### Security Measures
- **Encryption**: AES-GCM, RSA, ECC, TLS 1.3
- **Authentication**: JWT, OAuth 2.0, MFA/2FA
- **Authorization**: RBAC, ABAC, OPA/Gatekeeper
- **Audit**: Encrypted logs, real-time monitoring

## Contributing

We warmly welcome contributions! Here's how to participate:

### Contribution Guidelines

1. **Fork** the project
2. **Create** a feature branch (`git checkout -b feature/AmazingFeature`)
3. **Commit** your changes (`git commit -m 'Add AmazingFeature'`)
4. **Push** to the branch (`git push origin feature/AmazingFeature`)
5. **Open** a Pull Request

### Code Standards
- Follow **PEP 8** for Python
- Add **unit tests** for new features
- Document code with **docstrings**
- Respect **security principles**

## License

This project is licensed under **AGPL v3**. See the [LICENSE](LICENSE) file for more details.

## Author & Contact

### Development Team
**Ghost Cyber Universe Team**
- Cybersecurity Capstone Project
- Year: 2025

### Contact Methods

- **Email**: [reypotozy@gmail.com](mailto:reypotozy@gmail.com)
- **GitHub**: [reyptz](https://github.com/reyptz)

### Support

- **Issues**: [GitHub Issues](https://github.com/reyptz/Cyber-Universe-Capstone-v1/issues)
- **Discussions**: [GitHub Discussions](https://github.com/reyptz/Cyber-Universe-Capstone-v1/discussions)

## Project Statistics

![GitHub stars](https://img.shields.io/github/stars/reyptz/Cyber-Universe-Capstone-v1?style=social)
![GitHub forks](https://img.shields.io/github/forks/reyptz/Cyber-Universe-Capstone-v1?style=social)
![GitHub issues](https://img.shields.io/github/issues/reyptz/Cyber-Universe-Capstone-v1)
![GitHub pull requests](https://img.shields.io/github/issues-pr/reyptz/Cyber-Universe-Capstone-v1)

---

**If this project helps you, don't hesitate to give it a star!**

Made with ❤️ by Ghost Cyber Universe Team

---

## Version Française

## Description

Ghost Cyber Universe est une plateforme intégrée de cybersécurité conçue pour les professionnels de la sécurité, combinant des capacités offensives et défensives avec des technologies de pointe en cryptographie, intelligence artificielle et DevSecOps.

## Plateformes Principales

### Offensive Operations Suite
- **Genjutsu Engine** : Génération polymorphe de payloads avec LLVM (< 3 minutes)
- **Ghost Compiler** : Injection reflective in-memory sans traces (Rust no_std)
- **Hiraishin Framework** : Infrastructure as Code ultra-rapide (deploy/destroy < 180s, rollback < 60s)

### Defensive Intelligence Platform
- **Shinra OSINT Agent** : Collecte automatisée (1000 pages/min) avec RAG
- **KumoShield S-IA** : Détection temps réel (< 200ms) avec eBPF, Sigma, YARA
- **Interface Web Moderne** : React + TypeScript + TailwindCSS

### Module Aetherium (Cryptographie)
- **Protocole GKEP** : Ghost Key Exchange Protocol propriétaire
- **Infrastructure PKI** : X.509, gestion des certificats, CRLs
- **Rotation Automatique** : Gestion intelligente des clés avec support blockchain
- **Chiffrement Multi-Algorithmes** : AES-GCM, RSA, ECC, RC4 (rétrocompatibilité)
- **Signatures Numériques** : ECDSA, Ed25519, HMAC
- **Protocoles Réseau** : SSL/TLS/DTLS, IPsec, QUIC

## Technologies Utilisées

### Backend
- **Python 3.11+** : FastAPI pour les services principaux
- **Rust 1.75+** : Services sécurisés et eBPF
- **C/C++** : Noyau performance critique

### Frontend
- **React 18+** : Interface utilisateur moderne
- **TypeScript** : Typage strict et sécurité
- **TailwindCSS** : Design system responsive
- **Vite** : Build tool optimisé

### Intelligence Artificielle
- **ML/DL** : PyTorch, TensorFlow/Keras, scikit-learn
- **NLP** : Transformers, LangChain, RAG
- **Vector Databases** : Pinecone, Milvus, Weaviate, FAISS
- **MLOps** : MLflow, TFX, BentoML

### Infrastructure
- **Conteneurisation** : Docker, Kubernetes
- **IaC** : Terraform, Ansible, Pulumi
- **Monitoring** : Prometheus, Grafana, ELK Stack, Jaeger
- **CI/CD** : GitHub Actions avec scans de sécurité

## Installation

### Prérequis Techniques

#### Obligatoires
- **Docker 24+** & **Docker Compose 2.0+**
- **Git**
- **Python 3.11+**
- **Node.js 18+**

#### Optionnels (pour Offensive Ops)
- **Rust 1.75+** (Ghost Compiler)
- **LLVM 17+** (Genjutsu Engine)

### Installation Rapide (Recommandée)

```bash
# Cloner le repository
git clone https://github.com/reyptz/Cyber-Universe-Capstone-v1.git
cd Cyber-Universe-Capstone-v1
```

### Installation avec Docker (Production)

```bash
# Démarrer tous les services
docker-compose up -d

# Vérifier le statut
docker-compose ps

# Accéder aux services
# - Grafana:    http://localhost:3000 (admin/admin)
# - API Docs:   http://localhost:8000/api/docs
# - Frontend:   http://localhost:5173
# - Prometheus: http://localhost:9090

# Voir les logs
docker-compose logs -f shinra-api
```

## Cas d'Usage

### Red Team / Offensive Security
- **Payload Generation** : Générer des shellcodes polymorphes indétectables
- **Stealth Injection** : Injecter du code en mémoire sans traces
- **Rapid Infrastructure** : Déployer/détruire des environnements d'attaque en < 3 minutes
- **Training Labs** : Créer des labs éphémères pour exercices Red Team

### Blue Team / Defensive Security
- **OSINT Collection** : Collecter automatiquement des données de threat intelligence
- **Real-time Detection** : Détecter des menaces avec < 200ms de latence
- **Threat Hunting** : Rechercher des IOCs avec RAG et enrichissement IA
- **SOC Automation** : Automatiser les playbooks de réponse aux incidents

### Purple Team / DevSecOps
- **CI/CD Security** : Pipelines sécurisés avec SBOM et attestations
- **Supply Chain Security** : Traçabilité complète avec Sigstore/Rekor
- **Performance Monitoring** : Dashboards Grafana pour métriques opérationnelles
- **Compliance** : Conformité ISO 27001/27007 et RGPD

## Performance Cibles

| Composant | Langage | Target | Status |
|-----------|---------|--------|---------|
| Payload execution | C | < 500ms | Implémenté |
| eBPF detection | Rust | < 150ms | Implémenté |
| API response | Python | < 80ms | Implémenté |
| UI update | React | < 30ms | Implémenté |
| OSINT collection | Python | 1000 pages/min | Implémenté |
| Infrastructure deploy | Terraform | < 180s | Implémenté |

## Sécurité et Conformité

### Standards
- **ISO 27001** : Management de la sécurité de l'information
- **NIST Cybersecurity Framework** : Cadre de cybersécurité
- **SOC 2** : Contrôles de sécurité organisationnels
- **GDPR** : Protection des données personnelles
- **SLSA v1.2** : Supply-chain security

### Mesures de Sécurité
- **Chiffrement** : AES-GCM, RSA, ECC, TLS 1.3
- **Authentification** : JWT, OAuth 2.0, MFA/2FA
- **Autorisation** : RBAC, ABAC, OPA/Gatekeeper
- **Audit** : Logs chiffrés, monitoring temps réel

## Contribuer

Nous accueillons chaleureusement les contributions ! Voici comment participer :

### Guidelines de Contribution

1. **Fork** le projet
2. **Créer** une branche feature (`git checkout -b feature/AmazingFeature`)
3. **Commit** vos changements (`git commit -m 'Add AmazingFeature'`)
4. **Push** vers la branche (`git push origin feature/AmazingFeature`)
5. **Ouvrir** une Pull Request

### Standards de Code
- Suivre **PEP 8** pour Python
- Ajouter des **tests unitaires** pour les nouvelles fonctionnalités
- Documenter le code avec **docstrings**
- Respecter les **principes de sécurité**

## Licence

Ce projet est sous licence **AGPL v3**. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## Auteur & Contact

### Équipe de Développement
**Ghost Cyber Universe Team**
- Projet Capstone en Cybersécurité
- Année : 2025

### Moyens de Contact
- **Email** : [reypotozy@gmail.com](mailto:reypotozy@gmail.com)
- **GitHub** : [reyptz](https://github.com/reyptz)

### Support
- **Issues** : [GitHub Issues](https://github.com/reyptz/Cyber-Universe-Capstone-v1/issues)
- **Discussions** : [GitHub Discussions](https://github.com/reyptz/Cyber-Universe-Capstone-v1/discussions)

## Statistiques du Projet

![GitHub stars](https://img.shields.io/github/stars/reyptz/Cyber-Universe-Capstone-v1?style=social)
![GitHub forks](https://img.shields.io/github/forks/reyptz/Cyber-Universe-Capstone-v1?style=social)
![GitHub issues](https://img.shields.io/github/issues/reyptz/Cyber-Universe-Capstone-v1)
![GitHub pull requests](https://img.shields.io/github/issues-pr/reyptz/Cyber-Universe-Capstone-v1)

---

**Si ce projet vous aide, n'hésitez pas à lui donner une étoile !**

Made with ❤️ by Ghost Cyber Universe Team
