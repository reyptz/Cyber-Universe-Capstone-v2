from fastapi import APIRouter, Query
from typing import List, Optional
from datetime import datetime, timedelta

from app.models import Threat, ThreatCategory, SeverityLevel
from app.schemas import ThreatResponse

router = APIRouter(prefix="/info", tags=["Information & Documentation"])


@router.get("/latest-cves")
async def get_latest_cves(
    days: int = Query(default=30, ge=1, le=90),
    severity: Optional[SeverityLevel] = None,
    limit: int = Query(default=50, ge=1, le=200)
):
    """
    Liste des dernières vulnérabilités CVE
    
    Retourne les CVE les plus récentes avec leurs détails.
    """
    since = datetime.now() - timedelta(days=days)
    
    criteria = [
        Threat.category == ThreatCategory.VULNERABILITY,
        Threat.is_active == True,
        Threat.detected_date >= since
    ]
    
    if severity:
        criteria.append(Threat.severity == severity)
    
    from beanie.operators import And, RegEx
    # Filtre pour ne garder que les CVE (external_id commence par CVE-)
    criteria.append(RegEx(Threat.external_id, "^CVE-", "i"))
    
    cves = await Threat.find(
        And(*criteria)
    ).sort(-Threat.detected_date).limit(limit).to_list()
    
    return {
        "period_days": days,
        "total": len(cves),
        "cves": [
            {
                "cve_id": cve.external_id,
                "title": cve.title,
                "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description,
                "severity": cve.severity.value,
                "cvss_score": cve.cvss_score,
                "published_date": cve.published_date,
                "affected_systems": cve.affected_systems,
                "source_url": cve.source_url
            }
            for cve in cves
        ]
    }


@router.get("/practical-guides")
async def get_practical_guides():
    """
    Guides pratiques et fiches synthétiques
    
    Comment se protéger de différentes menaces.
    """
    guides = [
        {
            "id": "ransomware-protection",
            "title": "Comment se protéger du ransomware ?",
            "category": "ransomware",
            "difficulty": "beginner",
            "content": {
                "introduction": "Le ransomware est l'une des menaces les plus courantes et dévastatrices.",
                "prevention": [
                    "Effectuer des sauvegardes régulières (offline)",
                    "Maintenir les systèmes à jour",
                    "Utiliser un antivirus professionnel",
                    "Former les employés au phishing",
                    "Segmenter le réseau",
                    "Implémenter le principe du moindre privilège"
                ],
                "detection": [
                    "Surveiller les activités de chiffrement inhabituelles",
                    "Monitorer les accès aux fichiers",
                    "Alertes sur modifications massives de fichiers"
                ],
                "response": [
                    "Isoler immédiatement les systèmes infectés",
                    "Ne PAS payer la rançon",
                    "Contacter les autorités (ANSSI, police)",
                    "Restaurer depuis les sauvegardes",
                    "Analyser le vecteur d'infection"
                ]
            }
        },
        {
            "id": "phishing-protection",
            "title": "Comment éviter le phishing ?",
            "category": "phishing",
            "difficulty": "beginner",
            "content": {
                "introduction": "Le phishing est la technique la plus utilisée pour voler des identifiants.",
                "recognition": [
                    "Vérifier l'adresse de l'expéditeur",
                    "Survoler les liens sans cliquer",
                    "Attention aux fautes d'orthographe",
                    "Méfiance face à l'urgence",
                    "Vérifier le domaine des sites"
                ],
                "prevention": [
                    "Activer l'authentification à deux facteurs",
                    "Utiliser un gestionnaire de mots de passe",
                    "Formation régulière des utilisateurs",
                    "Filtres anti-phishing"
                ],
                "response": [
                    "Ne pas cliquer sur les liens",
                    "Signaler l'email",
                    "Si cliqué: changer les mots de passe immédiatement",
                    "Contacter le service IT",
                    "Surveiller les comptes"
                ]
            }
        },
        {
            "id": "password-security",
            "title": "Sécuriser ses mots de passe",
            "category": "authentication",
            "difficulty": "beginner",
            "content": {
                "rules": [
                    "Minimum 12 caractères",
                    "Mélange majuscules, minuscules, chiffres, symboles",
                    "Unique pour chaque compte",
                    "Pas d'informations personnelles"
                ],
                "tools": [
                    "Gestionnaires: 1Password, Bitwarden, Dashlane",
                    "Générateurs de mots de passe",
                    "Authentification à deux facteurs (2FA)"
                ],
                "mistakes": [
                    "Ne jamais réutiliser un mot de passe",
                    "Ne pas noter sur papier/fichier non chiffré",
                    "Ne pas partager ses mots de passe",
                    "Changer après une fuite de données"
                ]
            }
        },
        {
            "id": "compromised-account",
            "title": "Mon compte est compromis, que faire ?",
            "category": "incident-response",
            "difficulty": "beginner",
            "content": {
                "immediate": [
                    "1. Changer immédiatement le mot de passe",
                    "2. Activer 2FA si pas déjà fait",
                    "3. Déconnecter toutes les sessions actives",
                    "4. Vérifier les paramètres du compte"
                ],
                "investigation": [
                    "Vérifier l'historique de connexion",
                    "Examiner les activités récentes",
                    "Chercher des modifications non autorisées",
                    "Vérifier les emails de notification"
                ],
                "recovery": [
                    "Contacter le support du service",
                    "Signaler l'incident",
                    "Changer les mots de passe de tous les comptes liés",
                    "Surveiller les activités suspectes",
                    "Vérifier le crédit/comptes bancaires si données financières"
                ]
            }
        }
    ]
    
    return {
        "total": len(guides),
        "guides": guides
    }


@router.get("/os-recommendations")
async def get_os_recommendations(os_type: Optional[str] = Query(None, description="windows, macos, linux, android, ios")):
    """
    Recommandations de sécurité par système d'exploitation
    """
    all_recommendations = {
        "windows": {
            "os": "Windows",
            "version": "Windows 10/11",
            "critical": [
                "Activer Windows Defender et le maintenir à jour",
                "Installer toutes les mises à jour Windows Update",
                "Activer le pare-feu Windows",
                "Activer BitLocker pour chiffrer le disque",
                "Désactiver les comptes administrateur inutilisés"
            ],
            "recommended": [
                "Utiliser un compte utilisateur standard (non-admin)",
                "Activer la protection en temps réel",
                "Configurer des sauvegardes automatiques",
                "Désactiver les services inutiles",
                "Utiliser un VPN sur les réseaux publics",
                "Activer Windows Hello (biométrie)"
            ],
            "tools": [
                "Windows Defender (intégré)",
                "Windows Firewall",
                "BitLocker",
                "Windows Security Center",
                "Microsoft Defender for Endpoint (entreprise)"
            ]
        },
        "macos": {
            "os": "macOS",
            "version": "macOS 13+ (Ventura, Sonoma)",
            "critical": [
                "Activer FileVault (chiffrement disque)",
                "Installer les mises à jour système régulièrement",
                "Activer le pare-feu",
                "Utiliser Touch ID / Face ID",
                "Activer 'Find My Mac'"
            ],
            "recommended": [
                "Activer Gatekeeper (vérification apps)",
                "Utiliser un compte standard (non-admin)",
                "Activer Time Machine (sauvegardes)",
                "Désactiver le partage inutile",
                "Utiliser un VPN",
                "Activer la double authentification iCloud"
            ],
            "tools": [
                "XProtect (anti-malware intégré)",
                "Gatekeeper",
                "FileVault",
                "Firewall macOS",
                "Malwarebytes for Mac"
            ]
        },
        "linux": {
            "os": "Linux",
            "version": "Ubuntu, Debian, Fedora, etc.",
            "critical": [
                "Maintenir le système à jour (apt update/upgrade)",
                "Utiliser un compte utilisateur non-root",
                "Configurer un pare-feu (ufw/iptables)",
                "Chiffrer le disque (LUKS)",
                "Désactiver SSH root login"
            ],
            "recommended": [
                "Installer fail2ban (protection brute-force)",
                "Utiliser des clés SSH au lieu de mots de passe",
                "Activer SELinux/AppArmor",
                "Auditer les services en écoute (netstat)",
                "Configurer des sauvegardes automatiques",
                "Utiliser sudo avec timeout court"
            ],
            "tools": [
                "UFW (Uncomplicated Firewall)",
                "fail2ban",
                "ClamAV (antivirus)",
                "rkhunter (rootkit hunter)",
                "Lynis (audit sécurité)"
            ]
        },
        "android": {
            "os": "Android",
            "version": "Android 11+",
            "critical": [
                "Activer le chiffrement du téléphone",
                "Utiliser un code PIN fort ou biométrie",
                "Installer uniquement depuis Google Play Store",
                "Activer Google Play Protect",
                "Maintenir Android à jour"
            ],
            "recommended": [
                "Vérifier les permissions des apps",
                "Activer 'Find My Device'",
                "Utiliser un VPN sur WiFi public",
                "Désactiver le Bluetooth quand inutilisé",
                "Effacer régulièrement le cache",
                "Activer la double authentification Google"
            ],
            "tools": [
                "Google Play Protect (intégré)",
                "Lookout Mobile Security",
                "Malwarebytes Mobile",
                "Norton Mobile Security",
                "Avast Mobile Security"
            ]
        },
        "ios": {
            "os": "iOS / iPadOS",
            "version": "iOS 16+",
            "critical": [
                "Installer les mises à jour iOS rapidement",
                "Activer Face ID / Touch ID",
                "Activer 'Find My iPhone'",
                "Utiliser un code à 6 chiffres minimum",
                "Activer le chiffrement des sauvegardes iCloud"
            ],
            "recommended": [
                "Activer la double authentification Apple ID",
                "Vérifier les permissions des apps",
                "Désactiver le Bluetooth quand inutilisé",
                "Utiliser un VPN sur WiFi public",
                "Activer 'Effacer données' après 10 tentatives",
                "Limiter le tracking publicitaire"
            ],
            "tools": [
                "iOS Security Features (intégré)",
                "iCloud Keychain",
                "Lookout Mobile Security",
                "Norton Mobile Security",
                "VPN apps (NordVPN, ExpressVPN)"
            ]
        }
    }
    
    if os_type:
        os_type = os_type.lower()
        if os_type in all_recommendations:
            return {
                "os_type": os_type,
                "recommendation": all_recommendations[os_type]
            }
        else:
            return {
                "error": "OS not found",
                "available": list(all_recommendations.keys())
            }
    
    return {
        "total_os": len(all_recommendations),
        "recommendations": all_recommendations
    }


@router.get("/quick-tips")
async def get_quick_security_tips():
    """
    Conseils rapides de sécurité (particuliers et entreprises)
    """
    return {
        "individuals": {
            "category": "Particuliers",
            "tips": [
                {
                    "title": "Mots de passe forts",
                    "description": "Utilisez un gestionnaire de mots de passe et activez la 2FA partout"
                },
                {
                    "title": "Mises à jour régulières",
                    "description": "Maintenez vos appareils et applications à jour"
                },
                {
                    "title": "Méfiance des emails",
                    "description": "Vérifiez toujours l'expéditeur avant de cliquer sur un lien"
                },
                {
                    "title": "Sauvegardes régulières",
                    "description": "Sauvegardez vos données importantes régulièrement"
                },
                {
                    "title": "VPN sur WiFi public",
                    "description": "Utilisez un VPN quand vous vous connectez à un WiFi public"
                },
                {
                    "title": "Vérifiez vos comptes",
                    "description": "Surveillez régulièrement l'activité de vos comptes en ligne"
                }
            ]
        },
        "businesses": {
            "category": "Entreprises",
            "tips": [
                {
                    "title": "Formation continue",
                    "description": "Formez régulièrement vos employés à la cybersécurité"
                },
                {
                    "title": "Politique de sécurité",
                    "description": "Établissez et appliquez une politique de sécurité claire"
                },
                {
                    "title": "Sauvegarde 3-2-1",
                    "description": "3 copies, 2 supports différents, 1 copie hors site"
                },
                {
                    "title": "Plan de réponse aux incidents",
                    "description": "Préparez et testez régulièrement votre plan de réponse"
                },
                {
                    "title": "Principe du moindre privilège",
                    "description": "Limitez les accès au strict nécessaire"
                },
                {
                    "title": "Audit de sécurité régulier",
                    "description": "Effectuez des pentests et audits de sécurité périodiques"
                },
                {
                    "title": "Chiffrement des données",
                    "description": "Chiffrez les données sensibles en transit et au repos"
                },
                {
                    "title": "Segmentation réseau",
                    "description": "Séparez les réseaux critiques des réseaux utilisateur"
                }
            ]
        }
    }


@router.get("/documentation/standards")
async def get_security_standards():
    """
    Liste des normes et standards de cybersécurité
    
    Redirige vers le module éducatif pour les détails complets.
    """
    return {
        "message": "Pour les standards complets, consultez /educational/resources",
        "quick_reference": [
            {
                "name": "ISO 27001",
                "type": "Standard",
                "description": "Management de la sécurité de l'information",
                "url": "/educational/resources/iso-27001"
            },
            {
                "name": "NIST Cybersecurity Framework",
                "type": "Framework",
                "description": "Framework de cybersécurité américain",
                "url": "/educational/resources/nist-csf"
            },
            {
                "name": "OWASP Top 10",
                "type": "Guide",
                "description": "Top 10 des risques applicatifs web",
                "url": "/educational/resources/owasp-top-10"
            },
            {
                "name": "MITRE ATT&CK",
                "type": "Framework",
                "description": "Base de connaissances des tactiques adverses",
                "url": "/educational/resources/mitre-attack"
            }
        ]
    }


@router.get("/glossary")
async def get_glossary_reference():
    """
    Référence rapide au glossaire
    
    Redirige vers le module éducatif pour le glossaire complet.
    """
    return {
        "message": "Pour le glossaire complet, consultez /educational/glossary",
        "quick_terms": [
            {"term": "Phishing", "url": "/educational/glossary/phishing"},
            {"term": "Ransomware", "url": "/educational/glossary/ransomware"},
            {"term": "Zero-Day", "url": "/educational/glossary/zero-day"},
            {"term": "APT", "url": "/educational/glossary/apt"},
            {"term": "DDoS", "url": "/educational/glossary/ddos"}
        ],
        "search_url": "/educational/glossary?query=TERM"
    }

