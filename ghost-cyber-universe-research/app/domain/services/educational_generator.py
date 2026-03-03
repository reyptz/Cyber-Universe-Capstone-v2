"""
Générateur de contenu éducatif avec IA
"""

import logging
from typing import List, Dict
from datetime import datetime

logger = logging.getLogger(__name__)


async def generate_red_blue_scenarios() -> List[Dict]:
    """
    Génère des scénarios Red Team vs Blue Team
    """
    scenarios = [
        {
            "id": "phishing-attack",
            "title": "Attaque par Phishing",
            "severity": "high",
            "red_team": {
                "action": "Campagne de phishing ciblée",
                "technique": "Social Engineering",
                "tools": ["GoPhish", "SET", "Evilginx2"],
                "steps": [
                    "Reconnaissance des cibles via OSINT (LinkedIn, Twitter)",
                    "Création de domaine similaire (typosquatting)",
                    "Template email professionnel (clone site légitime)",
                    "Envoi emails avec lien malveillant",
                    "Harvesting credentials via page login fake",
                    "Accès comptes compromis"
                ],
                "mitre_techniques": ["T1566.002 - Phishing: Spearphishing Link"]
            },
            "blue_team": {
                "defense": "Protection anti-phishing multi-couches",
                "technique": "Security Awareness + Technical Controls",
                "tools": ["Proofpoint", "Mimecast", "KnowBe4"],
                "steps": [
                    "Formation utilisateurs (phishing simulations mensuelles)",
                    "Filtres email SPF/DKIM/DMARC",
                    "Sandbox pour liens suspects",
                    "MFA obligatoire sur tous les comptes",
                    "Banner warning emails externes",
                    "Reporting phishing facile (bouton Outlook)"
                ],
                "controls": ["Technical", "Administrative", "Physical"]
            },
            "real_world_example": "Campagne Emotet 2022 - 100K+ emails/jour",
            "impact": "Compromission comptes, vol données, ransomware",
            "difficulty": "Medium"
        },
        {
            "id": "sql-injection",
            "title": "Injection SQL",
            "severity": "critical",
            "red_team": {
                "action": "Exploitation SQLi pour dump DB",
                "technique": "Web Application Attack",
                "tools": ["SQLMap", "Burp Suite", "OWASP ZAP"],
                "steps": [
                    "Identifier inputs web (recherche, login, etc.)",
                    "Test manuel: ' OR '1'='1' -- ",
                    "SQLMap automatique: sqlmap -u URL --dbs",
                    "Extraction schéma: --tables --columns",
                    "Dump données sensibles: --dump",
                    "Post-exploitation: shell via INTO OUTFILE"
                ],
                "mitre_techniques": ["T1190 - Exploit Public-Facing Application"]
            },
            "blue_team": {
                "defense": "Input validation + Prepared Statements",
                "technique": "Secure Coding Practices",
                "tools": ["WAF (ModSecurity)", "SAST", "Code Review"],
                "steps": [
                    "Prepared statements/Parameterized queries OBLIGATOIRES",
                    "ORM (SQLAlchemy, Hibernate) avec escaping auto",
                    "Input validation stricte (whitelist)",
                    "WAF rules anti-SQLi (OWASP CRS)",
                    "Principe moindre privilège DB (pas de root)",
                    "Monitoring queries anormales"
                ],
                "controls": ["Technical", "Preventive"]
            },
            "real_world_example": "Breach Equifax 2017 - 147M personnes",
            "impact": "Vol données massif, credential theft, defacement",
            "difficulty": "Medium"
        },
        {
            "id": "ransomware-attack",
            "title": "Attaque Ransomware",
            "severity": "critical",
            "red_team": {
                "action": "Déploiement ransomware sur réseau",
                "technique": "Malware Deployment + Lateral Movement",
                "tools": ["Cobalt Strike", "Metasploit", "Custom Ransomware"],
                "steps": [
                    "Accès initial: phishing macro Office malveillante",
                    "Établir persistence: scheduled task, registry",
                    "Élévation privilèges: exploit CVE ou mimikatz",
                    "Reconnaissance réseau: nmap, bloodhound AD",
                    "Lateral movement: psexec, SMB, RDP",
                    "Exfiltration données sensibles (double extortion)",
                    "Chiffrement AES-256 de tous les fichiers",
                    "Note de rançon + wallet Bitcoin"
                ],
                "mitre_techniques": ["T1486 - Data Encrypted for Impact", "T1021 - Remote Services"]
            },
            "blue_team": {
                "defense": "Defense in Depth + Incident Response",
                "technique": "Multi-Layer Security Strategy",
                "tools": ["EDR (CrowdStrike)", "SIEM", "Backup Veeam"],
                "steps": [
                    "Backups 3-2-1 avec copie OFFLINE déconnectée",
                    "EDR/XDR sur tous les endpoints",
                    "Segmentation réseau (VLANs, firewalls internes)",
                    "Désactiver macros Office par GPO",
                    "Application whitelisting (AppLocker)",
                    "Monitoring SIEM (alertes encryption mass)",
                    "Plan réponse incident testé (tabletop exercise)",
                    "Snapshots VM réguliers"
                ],
                "controls": ["Preventive", "Detective", "Corrective"]
            },
            "real_world_example": "LockBit 3.0, BlackCat (ALPHV), REvil",
            "impact": "Perte données, downtime business, rançon $millions",
            "difficulty": "High"
        },
        {
            "id": "privilege-escalation",
            "title": "Élévation de Privilèges",
            "severity": "high",
            "red_team": {
                "action": "User → SYSTEM/root",
                "technique": "Post-Exploitation",
                "tools": ["WinPEAS", "LinPEAS", "Metasploit"],
                "steps": [
                    "Accès initial: user standard compromis",
                    "Enumération: whoami /all, sudo -l, SUID binaries",
                    "Recherche vulns locales: exploit-db, GitHub",
                    "Exploit CVE Windows (PrintNightmare, etc.)",
                    "Ou exploit config: sudo misconfiguration",
                    "Ou credential harvesting: mimikatz, lsass dump",
                    "Obtenir SYSTEM/root access",
                    "Persistence: backdoor, implant"
                ],
                "mitre_techniques": ["T1068 - Exploitation for Privilege Escalation"]
            },
            "blue_team": {
                "defense": "Least Privilege + Hardening",
                "technique": "Access Control + Patch Management",
                "tools": ["Microsoft Defender", "Monitoring", "Patch Management"],
                "steps": [
                    "Principe moindre privilège STRICT",
                    "Pas de droits admin pour utilisateurs standard",
                    "Patching OS régulier (monthly Windows Updates)",
                    "Désactiver services inutiles",
                    "AppLocker / WDAC pour bloquer exécutables",
                    "Monitoring privilèges escalation (Event ID 4672)",
                    "LAPS pour mots de passe admin locaux",
                    "UAC activé"
                ],
                "controls": ["Preventive", "Detective"]
            },
            "real_world_example": "PrintNightmare CVE-2021-34527, Dirty Pipe Linux",
            "impact": "Contrôle total système, persistence, data theft",
            "difficulty": "High"
        },
        {
            "id": "lateral-movement",
            "title": "Mouvement Latéral (AD)",
            "severity": "critical",
            "red_team": {
                "action": "Compromission Active Directory",
                "technique": "Network Traversal + Credential Theft",
                "tools": ["BloodHound", "Mimikatz", "Impacket"],
                "steps": [
                    "Machine initiale compromise (workstation)",
                    "Dump credentials local: mimikatz sekurlsa::logonpasswords",
                    "Reconnaissance AD: BloodHound (chemins admin)",
                    "Pass-the-Hash: psexec avec NTLM hash",
                    "Compromission serveur file share (vol credentials)",
                    "Kerberoasting: tickets TGS pour crack offline",
                    "Compromission Domain Controller",
                    "Golden Ticket: contrôle total AD"
                ],
                "mitre_techniques": ["T1021 - Remote Services", "T1550 - Use Alternate Authentication Material"]
            },
            "blue_team": {
                "defense": "AD Hardening + Credential Protection",
                "technique": "Identity Security",
                "tools": ["Defender for Identity", "CyberArk", "Tiering Model"],
                "steps": [
                    "Credential Guard activé (protection LSASS)",
                    "LAPS pour admin locaux (rotation auto)",
                    "Tiering Model AD (séparer admin/user)",
                    "Désactiver NTLM (Kerberos only)",
                    "Monitoring Mimikatz (détection LSASS access)",
                    "Protected Users group pour VIPs",
                    "Honeypot accounts (alertes instant)",
                    "MFA pour admin AD"
                ],
                "controls": ["Preventive", "Detective"]
            },
            "real_world_example": "APT29 (Cozy Bear), APT28 (Fancy Bear)",
            "impact": "Compromission totale domaine, exfiltration massive",
            "difficulty": "Advanced"
        },
        {
            "id": "zero-day-exploit",
            "title": "Exploitation Zero-Day",
            "severity": "critical",
            "red_team": {
                "action": "Exploit vulnérabilité inconnue",
                "technique": "Zero-Day Exploitation",
                "tools": ["Fuzzing (AFL)", "IDA Pro", "Exploit Dev"],
                "steps": [
                    "Recherche vulnérabilité: fuzzing application",
                    "Reverse engineering binaire (IDA, Ghidra)",
                    "Développement exploit custom",
                    "Bypass protections (ASLR, DEP, CFG)",
                    "ROP chain pour code execution",
                    "Shellcode injection",
                    "Remote Code Execution achieved"
                ],
                "mitre_techniques": ["T1203 - Exploitation for Client Execution"]
            },
            "blue_team": {
                "defense": "Defense in Depth + Exploit Mitigations",
                "technique": "Exploit Protection",
                "tools": ["Windows Defender Exploit Guard", "EMET"],
                "steps": [
                    "Activer toutes protections système (ASLR, DEP, CFG)",
                    "Application sandboxing (containers, VMs)",
                    "Principe moindre privilège (pas admin)",
                    "Patch management agressif (0-day → patch J+1)",
                    "EDR détection comportementale (exploit activity)",
                    "Network segmentation (limiter blast radius)",
                    "Threat intelligence pour IOCs",
                    "Bug bounty program"
                ],
                "controls": ["Preventive", "Detective", "Limiting"]
            },
            "real_world_example": "Log4Shell CVE-2021-44228, Zerologon CVE-2020-1472",
            "impact": "RCE, compromission avant patch disponible",
            "difficulty": "Expert"
        }
    ]
    
    return scenarios


async def save_scenarios_to_database():
    """
    Sauvegarde les scénarios générés dans MongoDB
    """
    from app.models import DailyLesson, ThreatCategory, TeamColor, DifficultyLevel
    
    scenarios = await generate_red_blue_scenarios()
    saved_count = 0
    
    for scenario in scenarios:
        try:
            # Vérifier si existe
            existing = await DailyLesson.find_one(DailyLesson.slug == scenario['id'])
            if existing:
                continue
            
            # Mapper difficulty
            difficulty_map = {
                'Medium': DifficultyLevel.INTERMEDIATE,
                'High': DifficultyLevel.ADVANCED,
                'Advanced': DifficultyLevel.ADVANCED,
                'Expert': DifficultyLevel.EXPERT
            }
            
            # Créer leçon
            lesson = DailyLesson(
                title=scenario['title'],
                slug=scenario['id'],
                lesson_number=saved_count + 1,
                introduction=f"Scénario: {scenario['title']}",
                main_content=f"""
# Red Team: {scenario['red_team']['action']}

**Technique:** {scenario['red_team']['technique']}
**Outils:** {', '.join(scenario['red_team']['tools'])}

**Étapes:**
{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(scenario['red_team']['steps']))}

---

# Blue Team: {scenario['blue_team']['defense']}

**Technique:** {scenario['blue_team']['technique']}
**Outils:** {', '.join(scenario['blue_team']['tools'])}

**Étapes:**
{chr(10).join(f"{i+1}. {step}" for i, step in enumerate(scenario['blue_team']['steps']))}

---

**Exemple réel:** {scenario['real_world_example']}
**Impact:** {scenario['impact']}
""",
                key_takeaways=[
                    scenario['red_team']['technique'],
                    scenario['blue_team']['technique'],
                    scenario['real_world_example']
                ],
                practical_tips=scenario['blue_team']['steps'][:3],
                category=ThreatCategory.OTHER,
                team_color=TeamColor.PURPLE,
                difficulty=difficulty_map.get(scenario['difficulty'], DifficultyLevel.INTERMEDIATE),
                duration_minutes=15,
                tags=[scenario['id'], 'red-team', 'blue-team', scenario['severity']],
                related_terms=[],
                related_resources=[],
                is_published=True,
                # Données custom pour le front
                metadata={
                    'red_team': scenario['red_team'],
                    'blue_team': scenario['blue_team'],
                    'severity': scenario['severity'],
                    'real_example': scenario['real_world_example'],
                    'impact': scenario['impact']
                }
            )
            
            await lesson.insert()
            saved_count += 1
            logger.info(f"Scénario créé: {scenario['title']}")
            
        except Exception as e:
            logger.error(f"Erreur création scénario: {e}")
            continue
    
    return saved_count


async def generate_glossary_terms() -> List[Dict]:
    """
    Génère des termes de glossaire cyber
    """
    from app.models import GlossaryTerm, ThreatCategory, TeamColor, DifficultyLevel
    
    terms_data = [
        {
            "term": "Phishing",
            "slug": "phishing",
            "short_definition": "Attaque par hameçonnage visant à voler des identifiants",
            "long_definition": "Le phishing est une technique d'ingénierie sociale où l'attaquant se fait passer pour une entité de confiance (banque, admin IT, etc.) pour voler des informations sensibles comme mots de passe, numéros de carte bancaire ou données personnelles. L'attaque se fait généralement par email, SMS (smishing) ou appel téléphonique (vishing).",
            "category": ThreatCategory.PHISHING,
            "team_colors": [TeamColor.RED, TeamColor.BLUE],
            "difficulty": DifficultyLevel.BEGINNER,
            "examples": [
                "Email fake 'Votre compte Netflix a expiré'",
                "SMS 'Colis en attente, cliquez ici'",
                "Site clone de votre banque"
            ],
            "related_terms": ["Social Engineering", "Spear Phishing", "Whaling"],
            "tags": ["social-engineering", "email", "web", "credentials"]
        },
        {
            "term": "Ransomware",
            "slug": "ransomware",
            "short_definition": "Malware qui chiffre vos fichiers et demande une rançon",
            "long_definition": "Un ransomware est un logiciel malveillant qui chiffre les fichiers de la victime avec un algorithme fort (AES-256, RSA-2048) et demande le paiement d'une rançon (généralement en Bitcoin) pour obtenir la clé de déchiffrement. Certains ransomwares modernes pratiquent la 'double extortion' en exfiltrant les données avant chiffrement.",
            "category": ThreatCategory.RANSOMWARE,
            "team_colors": [TeamColor.RED, TeamColor.PURPLE],
            "difficulty": DifficultyLevel.INTERMEDIATE,
            "examples": [
                "LockBit 3.0 - $10M rançon moyenne",
                "BlackCat/ALPHV - Rust-based",
                "WannaCry 2017 - 300K+ machines"
            ],
            "related_terms": ["Malware", "Encryption", "Bitcoin", "Double Extortion"],
            "tags": ["malware", "encryption", "extortion", "bitcoin"]
        },
        {
            "term": "Zero-Day",
            "slug": "zero-day",
            "short_definition": "Vulnérabilité inconnue exploitée avant qu'un patch existe",
            "long_definition": "Une vulnérabilité zero-day (0-day) est une faille de sécurité découverte et exploitée par des attaquants AVANT que le développeur/éditeur en soit informé. Le nom vient du fait qu'il y a 'zéro jour' pour corriger la faille avant son exploitation. Ces vulnérabilités valent très cher sur le marché noir ($100K-$1M+).",
            "category": ThreatCategory.VULNERABILITY,
            "team_colors": [TeamColor.RED],
            "difficulty": DifficultyLevel.ADVANCED,
            "examples": [
                "Log4Shell (Log4j) - RCE critique",
                "Zerologon - Compromission AD",
                "ProxyLogon (Exchange) - APT exploit"
            ],
            "related_terms": ["CVE", "Exploit", "APT", "Bug Bounty"],
            "tags": ["vulnerability", "exploit", "apt", "unpatched"]
        },
        {
            "term": "APT (Advanced Persistent Threat)",
            "slug": "apt",
            "short_definition": "Groupe d'attaquants sophistiqués (souvent nation-state)",
            "long_definition": "Une APT est un groupe de hackers hautement qualifiés, généralement sponsorisés par un État-nation, qui mène des campagnes d'espionnage ou de sabotage sur le long terme. Ils utilisent des zero-days, du social engineering avancé et des techniques de persistence furtives pour rester non-détectés pendant des mois/années.",
            "category": ThreatCategory.APT,
            "team_colors": [TeamColor.RED, TeamColor.PURPLE],
            "difficulty": DifficultyLevel.EXPERT,
            "examples": [
                "APT29 (Cozy Bear) - Russie",
                "APT28 (Fancy Bear) - Russie",
                "Lazarus Group - Corée du Nord",
                "APT41 - Chine"
            ],
            "related_terms": ["Nation-State", "Espionage", "Zero-Day", "C2"],
            "tags": ["apt", "nation-state", "espionage", "advanced"]
        },
        {
            "term": "MITRE ATT&CK",
            "slug": "mitre-attack",
            "short_definition": "Framework de tactiques et techniques des attaquants",
            "long_definition": "MITRE ATT&CK est une base de connaissance globale des tactiques, techniques et procédures (TTPs) utilisées par les cyber-adversaires. Elle décrit 14 tactiques (Initial Access, Execution, Persistence, etc.) et 200+ techniques documentées. C'est LA référence pour la threat intelligence et la détection.",
            "category": ThreatCategory.OTHER,
            "team_colors": [TeamColor.BLUE, TeamColor.PURPLE],
            "difficulty": DifficultyLevel.INTERMEDIATE,
            "examples": [
                "T1566 - Phishing",
                "T1059 - Command and Scripting Interpreter",
                "T1003 - OS Credential Dumping"
            ],
            "related_terms": ["TTPs", "Threat Intelligence", "Detection"],
            "tags": ["framework", "mitre", "tactics", "detection"]
        },
        {
            "term": "C2 (Command & Control)",
            "slug": "c2",
            "short_definition": "Serveur pour contrôler les machines compromises",
            "long_definition": "Un serveur C2 (Command & Control) est l'infrastructure utilisée par un attaquant pour communiquer avec les machines qu'il a compromises (zombies, bots). Le malware installé 'call back' vers le C2 pour recevoir des commandes (télécharger fichiers, exfiltrer données, propager, etc.). Les C2 modernes utilisent du domain fronting, DNS tunneling ou Tor pour éviter la détection.",
            "category": ThreatCategory.MALWARE,
            "team_colors": [TeamColor.RED, TeamColor.BLUE],
            "difficulty": DifficultyLevel.ADVANCED,
            "examples": [
                "Cobalt Strike (beacon)",
                "Metasploit Meterpreter",
                "Empire/Covenant frameworks"
            ],
            "related_terms": ["Botnet", "Backdoor", "Malware", "Exfiltration"],
            "tags": ["c2", "malware", "botnet", "infrastructure"]
        }
    ]
    
    saved = 0
    for term_data in terms_data:
        try:
            existing = await GlossaryTerm.find_one(GlossaryTerm.term == term_data['term'])
            if existing:
                continue
            
            term = GlossaryTerm(**term_data)
            await term.insert()
            saved += 1
            logger.info(f"Terme créé: {term.term}")
        except Exception as e:
            logger.error(f"Erreur création terme: {e}")
    
    return saved

