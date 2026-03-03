"""
Script pour peupler le contenu éducatif initial de CyberRadar
"""

import asyncio
import sys
import os

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.database import connect_to_mongo
from app.models import (
    GlossaryTerm, EducationalResource, DailyLesson,
    ThreatCategory, TeamColor, DifficultyLevel
)
from slugify import slugify


async def seed_glossary():
    """Peuple le glossaire avec des termes de base"""
    
    terms_data = [
        {
            "term": "Phishing",
            "slug": "phishing",
            "short_definition": "Technique de fraude visant à obtenir des informations sensibles en se faisant passer pour une entité de confiance.",
            "long_definition": "Le phishing (ou hameçonnage) est une technique d'ingénierie sociale utilisée par des cybercriminels pour obtenir des informations confidentielles telles que des mots de passe, numéros de carte bancaire, etc. Les attaquants se font passer pour une organisation légitime via email, SMS ou site web contrefait.",
            "category": ThreatCategory.PHISHING,
            "team_colors": [TeamColor.BLUE, TeamColor.PURPLE],
            "difficulty": DifficultyLevel.BEGINNER,
            "examples": [
                "Email frauduleux imitant votre banque",
                "SMS demandant de cliquer sur un lien suspect",
                "Site web copié de votre service en ligne préféré"
            ],
            "related_terms": ["spear-phishing", "whaling", "smishing"],
            "tags": ["email", "fraude", "ingenierie-sociale"]
        },
        {
            "term": "Ransomware",
            "slug": "ransomware",
            "short_definition": "Logiciel malveillant qui chiffre les données et demande une rançon pour les déchiffrer.",
            "long_definition": "Un ransomware est un type de malware qui chiffre les fichiers de la victime, rendant le système inutilisable jusqu'au paiement d'une rançon (souvent en cryptomonnaie). Les variantes modernes peuvent aussi exfiltrer les données avant chiffrement pour faire du double chantage.",
            "category": ThreatCategory.RANSOMWARE,
            "team_colors": [TeamColor.BLUE, TeamColor.RED],
            "difficulty": DifficultyLevel.INTERMEDIATE,
            "examples": [
                "WannaCry (2017) - affecté 200 000+ ordinateurs",
                "LockBit - ransomware-as-a-service actuel",
                "Ryuk - ciblant les grandes organisations"
            ],
            "related_terms": ["malware", "encryption", "cyber-extortion"],
            "tags": ["malware", "encryption", "rançon"]
        },
        {
            "term": "Zero-Day",
            "slug": "zero-day",
            "short_definition": "Vulnérabilité inconnue de l'éditeur et exploitée avant qu'un patch soit disponible.",
            "long_definition": "Une vulnérabilité zero-day est une faille de sécurité dans un logiciel qui est exploitée avant que le développeur n'en ait connaissance ou qu'un correctif soit disponible. Le terme 'zero-day' signifie que les développeurs ont eu zéro jour pour corriger la faille avant l'exploitation.",
            "category": ThreatCategory.ZERO_DAY,
            "team_colors": [TeamColor.BLUE, TeamColor.RED, TeamColor.PURPLE],
            "difficulty": DifficultyLevel.ADVANCED,
            "examples": [
                "Log4Shell (CVE-2021-44228) - Apache Log4j",
                "EternalBlue - utilisé par WannaCry",
                "Pegasus - exploits iOS/Android"
            ],
            "related_terms": ["vulnerability", "exploit", "patch"],
            "tags": ["vulnerability", "exploit", "advanced-threat"]
        },
        {
            "term": "APT",
            "slug": "apt",
            "short_definition": "Advanced Persistent Threat - Attaque ciblée et prolongée menée par des acteurs sophistiqués.",
            "long_definition": "Les APT (Advanced Persistent Threats) sont des cyberattaques orchestrées par des groupes bien organisés et financés (souvent étatiques) qui ciblent des organisations spécifiques sur une longue période. Ils utilisent des techniques avancées pour infiltrer, persister et exfiltrer des données sensibles.",
            "category": ThreatCategory.APT,
            "team_colors": [TeamColor.BLUE, TeamColor.PURPLE],
            "difficulty": DifficultyLevel.EXPERT,
            "examples": [
                "APT29 (Cozy Bear) - groupe lié à la Russie",
                "APT28 (Fancy Bear) - ciblant gouvernements",
                "Lazarus Group - attaques nord-coréennes"
            ],
            "related_terms": ["nation-state", "espionage", "lateral-movement"],
            "tags": ["apt", "nation-state", "espionage"]
        },
        {
            "term": "DDoS",
            "slug": "ddos",
            "short_definition": "Distributed Denial of Service - Attaque visant à rendre un service indisponible par surcharge.",
            "long_definition": "Une attaque DDoS (Distributed Denial of Service) consiste à saturer un serveur, service ou réseau avec un trafic massif provenant de multiples sources, le rendant indisponible pour les utilisateurs légitimes. Les attaquants utilisent souvent des botnets de milliers d'appareils compromis.",
            "category": ThreatCategory.DDOS,
            "team_colors": [TeamColor.BLUE, TeamColor.RED],
            "difficulty": DifficultyLevel.INTERMEDIATE,
            "examples": [
                "Attaque par amplification DNS",
                "SYN flood - saturation de connexions TCP",
                "Attaque applicative (Layer 7)"
            ],
            "related_terms": ["botnet", "dos", "mitigation"],
            "tags": ["ddos", "availability", "botnet"]
        },
    ]
    
    count = 0
    for term_data in terms_data:
        existing = await GlossaryTerm.find_one(GlossaryTerm.term == term_data["term"])
        if not existing:
            term = GlossaryTerm(**term_data)
            await term.insert()
            count += 1
            print(f"✅ Créé: {term.term}")
    
    print(f"\n{count} termes ajoutés au glossaire")


async def seed_resources():
    """Peuple les ressources éducatives"""
    
    resources_data = [
        {
            "title": "ISO 27001 - Sécurité de l'information",
            "slug": "iso-27001",
            "type": "standard",
            "description": "Norme internationale pour les systèmes de management de la sécurité de l'information (SMSI).",
            "summary": "ISO/IEC 27001 spécifie les exigences pour établir, mettre en œuvre, maintenir et améliorer continuellement un système de management de la sécurité de l'information.",
            "organization": "ISO",
            "official_url": "https://www.iso.org/standard/27001",
            "team_colors": [TeamColor.BLUE, TeamColor.GREEN],
            "topics": ["governance", "compliance", "management"],
            "difficulty": DifficultyLevel.INTERMEDIATE,
            "is_featured": True
        },
        {
            "title": "NIST Cybersecurity Framework",
            "slug": "nist-csf",
            "type": "framework",
            "description": "Framework de cybersécurité développé par le NIST pour améliorer la gestion des risques cyber.",
            "summary": "Le NIST CSF fournit une approche structurée basée sur 5 fonctions: Identifier, Protéger, Détecter, Répondre, Récupérer.",
            "organization": "NIST",
            "official_url": "https://www.nist.gov/cyberframework",
            "documentation_url": "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf",
            "team_colors": [TeamColor.BLUE, TeamColor.GREEN, TeamColor.PURPLE],
            "topics": ["risk-management", "governance", "best-practices"],
            "difficulty": DifficultyLevel.INTERMEDIATE,
            "is_featured": True
        },
        {
            "title": "OWASP Top 10",
            "slug": "owasp-top-10",
            "type": "guide",
            "description": "Liste des 10 risques de sécurité les plus critiques pour les applications web.",
            "summary": "L'OWASP Top 10 est un document de référence pour les développeurs et professionnels de la sécurité, mis à jour régulièrement avec les menaces les plus prévalentes.",
            "organization": "OWASP",
            "official_url": "https://owasp.org/www-project-top-ten/",
            "team_colors": [TeamColor.BLUE, TeamColor.RED, TeamColor.PURPLE],
            "topics": ["application-security", "web-security", "development"],
            "difficulty": DifficultyLevel.BEGINNER,
            "is_featured": True
        },
        {
            "title": "MITRE ATT&CK Framework",
            "slug": "mitre-attack",
            "type": "framework",
            "description": "Base de connaissances des tactiques et techniques utilisées par les adversaires.",
            "summary": "MITRE ATT&CK catalogue les comportements adverses basés sur des observations réelles, utile pour la détection et la réponse aux incidents.",
            "organization": "MITRE",
            "official_url": "https://attack.mitre.org/",
            "team_colors": [TeamColor.BLUE, TeamColor.RED, TeamColor.PURPLE],
            "topics": ["threat-intelligence", "detection", "response"],
            "difficulty": DifficultyLevel.ADVANCED,
            "is_featured": True
        },
        {
            "title": "CISSP - Certified Information Systems Security Professional",
            "slug": "cissp",
            "type": "certification",
            "description": "Certification professionnelle reconnue mondialement en sécurité de l'information.",
            "summary": "CISSP couvre 8 domaines de la sécurité: Sécurité & gestion des risques, Sécurité des actifs, Sécurité de l'ingénierie, Communications & sécurité réseau, IAM, Évaluation & tests de sécurité, Opérations de sécurité, Sécurité du développement logiciel.",
            "organization": "ISC2",
            "official_url": "https://www.isc2.org/Certifications/CISSP",
            "team_colors": [TeamColor.BLUE, TeamColor.GREEN],
            "topics": ["certification", "professional-development"],
            "difficulty": DifficultyLevel.ADVANCED,
            "is_featured": False
        },
    ]
    
    count = 0
    for resource_data in resources_data:
        existing = await EducationalResource.find_one(
            EducationalResource.slug == resource_data["slug"]
        )
        if not existing:
            resource = EducationalResource(**resource_data)
            await resource.insert()
            count += 1
            print(f"✅ Créé: {resource.title}")
    
    print(f"\n{count} ressources ajoutées")


async def seed_lessons():
    """Peuple les leçons quotidiennes"""
    
    lessons_data = [
        {
            "title": "Introduction à la Cybersécurité",
            "slug": "intro-cybersecurite",
            "lesson_number": 1,
            "introduction": "Bienvenue dans votre première leçon ! Découvrez les bases de la cybersécurité.",
            "main_content": """
# Qu'est-ce que la Cybersécurité ?

La cybersécurité est l'ensemble des pratiques, technologies et processus conçus pour protéger les systèmes, réseaux et données contre les cyberattaques.

## Les 3 Piliers (Triade CIA)

1. **Confidentialité** : Seules les personnes autorisées peuvent accéder aux informations
2. **Intégrité** : Les données ne sont pas altérées de manière non autorisée
3. **Disponibilité** : Les systèmes et données sont accessibles quand nécessaire

## Pourquoi c'est important ?

- Protection des données personnelles et professionnelles
- Continuité des activités
- Conformité réglementaire (RGPD, etc.)
- Réputation de l'entreprise

## Premiers Pas

Commencez par des actions simples :
- Utilisez des mots de passe forts et uniques
- Activez l'authentification à deux facteurs (2FA)
- Maintenez vos systèmes à jour
- Soyez vigilant face aux emails suspects
            """,
            "key_takeaways": [
                "La cybersécurité protège les systèmes contre les cyberattaques",
                "La triade CIA (Confidentialité, Intégrité, Disponibilité) est fondamentale",
                "Chacun a un rôle à jouer dans la sécurité",
                "Des actions simples peuvent avoir un grand impact"
            ],
            "practical_tips": [
                "Activez 2FA sur vos comptes importants dès aujourd'hui",
                "Utilisez un gestionnaire de mots de passe",
                "Vérifiez toujours l'expéditeur avant de cliquer sur un lien"
            ],
            "category": ThreatCategory.OTHER,
            "team_color": TeamColor.WHITE,
            "difficulty": DifficultyLevel.BEGINNER,
            "duration_minutes": 10,
            "tags": ["introduction", "basics", "beginner"]
        },
        {
            "title": "Le Phishing : Reconnaître et se Protéger",
            "slug": "phishing-reconnaissance-protection",
            "lesson_number": 2,
            "introduction": "Le phishing est l'une des menaces les plus communes. Apprenez à le reconnaître !",
            "main_content": """
# Le Phishing en Détail

Le phishing (hameçonnage) est une technique de fraude visant à voler vos informations confidentielles.

## Comment Reconnaître un Phishing ?

### 🚩 Signaux d'Alerte

1. **L'expéditeur** : Adresse email suspecte ou mal orthographiée
2. **L'urgence** : "Agissez immédiatement !" est un red flag classique
3. **Les liens** : Survolezhuman les liens sans cliquer pour voir la vraie URL
4. **Les pièces jointes** : Méfiez-vous des fichiers non sollicités
5. **Les fautes** : Erreurs de grammaire/orthographe inhabituelles

### Types de Phishing

- **Email phishing** : Le plus courant
- **Spear phishing** : Ciblé sur une personne spécifique
- **Whaling** : Ciblant les dirigeants
- **Smishing** : Via SMS
- **Vishing** : Par téléphone

## Protection

✅ Vérifiez toujours l'expéditeur
✅ Ne cliquez pas sur les liens suspects
✅ Utilisez l'authentification à deux facteurs
✅ Signalez les tentatives à votre équipe IT
✅ Formez-vous régulièrement

## Que Faire Si Vous Cliquez ?

1. **Ne paniquez pas** mais agissez vite
2. **Changez vos mots de passe** immédiatement
3. **Contactez votre IT** ou banque
4. **Signalez** l'incident
5. **Surveillez** vos comptes
            """,
            "key_takeaways": [
                "Le phishing exploite la confiance et l'urgence",
                "Toujours vérifier l'expéditeur avant de cliquer",
                "Le 2FA est une protection essentielle",
                "En cas de doute, contactez directement l'organisation"
            ],
            "practical_tips": [
                "Survolez les liens pour voir la vraie destination",
                "Vérifiez le domaine de l'expéditeur (ex: @banque.com vs @banque-secure.com)",
                "Créez un filtre anti-spam efficace"
            ],
            "category": ThreatCategory.PHISHING,
            "team_color": TeamColor.BLUE,
            "difficulty": DifficultyLevel.BEGINNER,
            "duration_minutes": 15,
            "tags": ["phishing", "email-security", "awareness"]
        },
        {
            "title": "Mots de Passe Forts et Gestion Sécurisée",
            "slug": "mots-de-passe-securises",
            "lesson_number": 3,
            "introduction": "Les mots de passe sont votre première ligne de défense. Apprenez à les créer et les gérer efficacement.",
            "main_content": """
# Les Mots de Passe Sécurisés

Un mot de passe fort est essentiel pour protéger vos comptes et données.

## Qu'est-ce qu'un Bon Mot de Passe ?

### ✅ Caractéristiques

- **Longueur** : Minimum 12-16 caractères
- **Complexité** : Mélange de majuscules, minuscules, chiffres, symboles
- **Unicité** : Différent pour chaque compte
- **Imprévisible** : Pas de mots du dictionnaire, dates, noms

### ❌ À Éviter

- Mots de passe évidents : password123, qwerty
- Informations personnelles : date de naissance, nom d'animal
- Séquences simples : 123456, abcdef
- Réutilisation sur plusieurs sites

## Méthodes de Création

### 1. Passphrase (Recommandé)

Phrase longue et mémorable :
`J'aime-Manger-7-Croissants-Le-Dimanche!`

### 2. Générateur Aléatoire

Utilisez un gestionnaire de mots de passe :
`Kp9$mL2#vN8@qR5!`

### 3. Méthode Acronyme

Première lettre de chaque mot d'une phrase :
"Mon chat Félix a 3 ans et adore jouer"
→ `McFa3aej!`

## Gestionnaires de Mots de Passe

### Avantages

✅ Stockage sécurisé et chiffré
✅ Génération automatique
✅ Remplissage automatique
✅ Synchronisation multi-appareils
✅ Alerte de mots de passe compromis

### Recommandations

- **1Password** : Complet et user-friendly
- **Bitwarden** : Open-source et gratuit
- **Dashlane** : Interface intuitive
- **KeePass** : Solution locale

## Authentification à Deux Facteurs (2FA)

### Types

1. **SMS** : Mieux que rien mais vulnérable
2. **Authenticator Apps** : Google Authenticator, Authy (recommandé)
3. **Clés physiques** : YubiKey (plus sécurisé)

### Activer 2FA Partout

✅ Email
✅ Réseaux sociaux
✅ Banque en ligne
✅ Cloud storage
✅ Comptes professionnels

## Que Faire en Cas de Fuite ?

1. **Changez immédiatement** le mot de passe compromis
2. **Changez aussi** tous les comptes utilisant le même mot de passe
3. **Activez 2FA** si ce n'est pas déjà fait
4. **Vérifiez** sur https://haveibeenpwned.com
5. **Surveillez** vos comptes pour activité suspecte
            """,
            "key_takeaways": [
                "Un mot de passe fort fait au moins 12 caractères",
                "Utilisez un mot de passe unique par compte",
                "Les gestionnaires de mots de passe facilitent la sécurité",
                "L'authentification à deux facteurs est indispensable"
            ],
            "practical_tips": [
                "Installez un gestionnaire de mots de passe dès aujourd'hui",
                "Activez 2FA sur vos 3 comptes les plus importants",
                "Changez vos mots de passe faibles dès maintenant",
                "Vérifiez si vos emails ont été compromis sur haveibeenpwned.com"
            ],
            "category": ThreatCategory.OTHER,
            "team_color": TeamColor.BLUE,
            "difficulty": DifficultyLevel.BEGINNER,
            "duration_minutes": 20,
            "tags": ["passwords", "authentication", "2fa", "security-basics"]
        },
    ]
    
    count = 0
    for lesson_data in lessons_data:
        existing = await DailyLesson.find_one(
            DailyLesson.slug == lesson_data["slug"]
        )
        if not existing:
            lesson = DailyLesson(**lesson_data)
            await lesson.insert()
            count += 1
            print(f"✅ Créé: Leçon {lesson.lesson_number} - {lesson.title}")
    
    print(f"\n{count} leçons ajoutées")


async def main():
    """Fonction principale"""
    print("🌱 Peuplement du contenu éducatif CyberRadar\n")
    print("=" * 50)
    
    # Connexion à MongoDB
    await connect_to_mongo()
    
    # Peupler les données
    print("\n📚 Glossaire...")
    await seed_glossary()
    
    print("\n📖 Ressources...")
    await seed_resources()
    
    print("\n🎓 Leçons quotidiennes...")
    await seed_lessons()
    
    print("\n" + "=" * 50)
    print("✅ Contenu éducatif initialisé avec succès !")


if __name__ == "__main__":
    asyncio.run(main())

