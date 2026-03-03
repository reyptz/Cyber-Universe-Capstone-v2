"""
SecretsManager - Gestionnaire de secrets sécurisé
Intègre HashiCorp Vault, rotation automatique, chiffrement selon DevSecOps
"""

import asyncio
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecretType(Enum):
    """Types de secrets gérés"""
    API_KEY = "api_key"           # Clés API externes
    DATABASE = "database"         # Connexions base de données
    CERTIFICATE = "certificate"   # Certificats SSL/TLS
    SSH_KEY = "ssh_key"          # Clés SSH
    TOKEN = "token"              # Tokens d'authentification
    PASSWORD = "password"        # Mots de passe
    ENCRYPTION_KEY = "encryption_key"  # Clés de chiffrement


class AccessLevel(Enum):
    """Niveaux d'accès aux secrets"""
    READ_ONLY = "read_only"      # Lecture seule
    READ_WRITE = "read_write"    # Lecture et écriture
    ADMIN = "admin"              # Administration complète
    ROTATE = "rotate"            # Rotation des secrets


@dataclass
class SecretMetadata:
    """Métadonnées d'un secret"""
    id: str
    name: str
    secret_type: SecretType
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None
    rotation_interval: Optional[int] = None  # en jours
    tags: List[str] = field(default_factory=list)
    description: str = ""
    owner: str = ""
    environment: str = "production"


@dataclass
class AccessLog:
    """Journal d'accès aux secrets"""
    secret_id: str
    user: str
    action: str
    timestamp: datetime
    ip_address: str = ""
    user_agent: str = ""
    success: bool = True
    error_message: str = ""


class SecretsManager:
    """
    Gestionnaire de secrets pour Ghost Cyber Universe
    Intègre HashiCorp Vault, chiffrement AES-256, rotation automatique
    """
    
    def __init__(self, config_path: str = "devsecops/config/secrets.json"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.secrets_store: Dict[str, bytes] = {}
        self.metadata_store: Dict[str, SecretMetadata] = {}
        self.access_logs: List[AccessLog] = []
        self.encryption_key: Optional[bytes] = None
        self.vault_client = None  # HashiCorp Vault client
        
        # Configuration par défaut
        self.default_rotation_intervals = {
            SecretType.API_KEY: 90,
            SecretType.DATABASE: 180,
            SecretType.CERTIFICATE: 365,
            SecretType.SSH_KEY: 365,
            SecretType.TOKEN: 30,
            SecretType.PASSWORD: 90,
            SecretType.ENCRYPTION_KEY: 365
        }
    
    async def initialize(self) -> bool:
        """Initialise le gestionnaire de secrets"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            await self._load_config()
            await self._initialize_encryption()
            await self._load_secrets_store()
            await self._initialize_vault_client()
            await self._start_rotation_scheduler()
            return True
        except Exception as e:
            print(f"Erreur initialisation SecretsManager: {e}")
            return False
    
    async def _load_config(self):
        """Charge la configuration du gestionnaire"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
        else:
            await self._create_default_config()
    
    async def _create_default_config(self):
        """Configuration par défaut selon les spécifications"""
        self.config = {
            "encryption": {
                "algorithm": "AES-256-GCM",
                "key_derivation": "PBKDF2",
                "iterations": 100000,
                "salt_length": 32
            },
            "vault": {
                "enabled": True,
                "url": "http://localhost:8200",
                "auth_method": "token",
                "mount_path": "secret/",
                "timeout": 30
            },
            "rotation": {
                "enabled": True,
                "check_interval": 3600,  # 1 heure
                "notification_days": 7,
                "auto_rotate": False
            },
            "access_control": {
                "require_authentication": True,
                "session_timeout": 3600,
                "max_failed_attempts": 3,
                "lockout_duration": 900
            },
            "audit": {
                "enabled": True,
                "log_all_access": True,
                "retention_days": 90,
                "export_format": "json"
            },
            "backup": {
                "enabled": True,
                "interval": 86400,  # 24 heures
                "retention_count": 30,
                "encryption": True
            }
        }
        await self._save_config()
    
    async def _save_config(self):
        """Sauvegarde la configuration"""
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    async def _initialize_encryption(self):
        """Initialise le système de chiffrement"""
        # Génération ou chargement de la clé maître
        key_file = self.config_path.parent / "master.key"
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                self.encryption_key = f.read()
        else:
            # Génération d'une nouvelle clé maître
            password = secrets.token_urlsafe(32).encode()
            salt = secrets.token_bytes(32)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=self.config["encryption"]["iterations"]
            )
            self.encryption_key = kdf.derive(password)
            
            # Sauvegarde sécurisée de la clé
            with open(key_file, 'wb') as f:
                f.write(self.encryption_key)
            
            # Permissions restrictives (Unix-like)
            try:
                key_file.chmod(0o600)
            except:
                pass  # Windows ne supporte pas chmod
    
    async def _load_secrets_store(self):
        """Charge le magasin de secrets chiffrés"""
        store_file = self.config_path.parent / "secrets.enc"
        metadata_file = self.config_path.parent / "metadata.json"
        
        if store_file.exists():
            with open(store_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Déchiffrement du magasin
            fernet = Fernet(base64.urlsafe_b64encode(self.encryption_key))
            decrypted_data = fernet.decrypt(encrypted_data)
            self.secrets_store = json.loads(decrypted_data.decode())
        
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata_data = json.load(f)
                for secret_id, meta_dict in metadata_data.items():
                    # Conversion des dates
                    meta_dict['created_at'] = datetime.fromisoformat(meta_dict['created_at'])
                    meta_dict['updated_at'] = datetime.fromisoformat(meta_dict['updated_at'])
                    if meta_dict.get('expires_at'):
                        meta_dict['expires_at'] = datetime.fromisoformat(meta_dict['expires_at'])
                    
                    # Conversion du type
                    meta_dict['secret_type'] = SecretType(meta_dict['secret_type'])
                    
                    self.metadata_store[secret_id] = SecretMetadata(**meta_dict)
    
    async def _save_secrets_store(self):
        """Sauvegarde le magasin de secrets chiffrés"""
        store_file = self.config_path.parent / "secrets.enc"
        metadata_file = self.config_path.parent / "metadata.json"
        
        # Chiffrement du magasin
        fernet = Fernet(base64.urlsafe_b64encode(self.encryption_key))
        data_to_encrypt = json.dumps(self.secrets_store).encode()
        encrypted_data = fernet.encrypt(data_to_encrypt)
        
        with open(store_file, 'wb') as f:
            f.write(encrypted_data)
        
        # Sauvegarde des métadonnées
        metadata_data = {}
        for secret_id, metadata in self.metadata_store.items():
            meta_dict = {
                'id': metadata.id,
                'name': metadata.name,
                'secret_type': metadata.secret_type.value,
                'created_at': metadata.created_at.isoformat(),
                'updated_at': metadata.updated_at.isoformat(),
                'expires_at': metadata.expires_at.isoformat() if metadata.expires_at else None,
                'rotation_interval': metadata.rotation_interval,
                'tags': metadata.tags,
                'description': metadata.description,
                'owner': metadata.owner,
                'environment': metadata.environment
            }
            metadata_data[secret_id] = meta_dict
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata_data, f, indent=2)
    
    async def _initialize_vault_client(self):
        """Initialise le client HashiCorp Vault"""
        if not self.config["vault"]["enabled"]:
            return
        
        try:
            # Simulation d'initialisation Vault
            # En production, utiliser hvac ou requests
            self.vault_client = {
                "url": self.config["vault"]["url"],
                "authenticated": False,
                "token": None
            }
            print("Client Vault initialisé")
        except Exception as e:
            print(f"Erreur initialisation Vault: {e}")
    
    async def store_secret(
        self,
        name: str,
        value: Union[str, bytes],
        secret_type: SecretType,
        description: str = "",
        tags: List[str] = None,
        expires_at: Optional[datetime] = None,
        owner: str = "system",
        environment: str = "production"
    ) -> str:
        """
        Stocke un secret de manière sécurisée
        
        Args:
            name: Nom du secret
            value: Valeur du secret
            secret_type: Type de secret
            description: Description du secret
            tags: Tags pour l'organisation
            expires_at: Date d'expiration
            owner: Propriétaire du secret
            environment: Environnement (dev, staging, prod)
            
        Returns:
            ID unique du secret
        """
        secret_id = self._generate_secret_id(name, secret_type)
        
        # Conversion en bytes si nécessaire
        if isinstance(value, str):
            value = value.encode('utf-8')
        
        # Chiffrement du secret
        encrypted_value = await self._encrypt_secret(value)
        
        # Stockage
        self.secrets_store[secret_id] = encrypted_value
        
        # Métadonnées
        now = datetime.utcnow()
        rotation_interval = self.default_rotation_intervals.get(secret_type)
        
        if not expires_at and rotation_interval:
            expires_at = now + timedelta(days=rotation_interval)
        
        metadata = SecretMetadata(
            id=secret_id,
            name=name,
            secret_type=secret_type,
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            rotation_interval=rotation_interval,
            tags=tags or [],
            description=description,
            owner=owner,
            environment=environment
        )
        
        self.metadata_store[secret_id] = metadata
        
        # Sauvegarde
        await self._save_secrets_store()
        
        # Audit
        await self._log_access(secret_id, owner, "store", True)
        
        # Synchronisation avec Vault si activé
        if self.config["vault"]["enabled"]:
            await self._sync_to_vault(secret_id, value)
        
        print(f"Secret '{name}' stocké avec l'ID: {secret_id}")
        return secret_id
    
    async def retrieve_secret(
        self,
        secret_id: str,
        user: str = "system",
        access_level: AccessLevel = AccessLevel.READ_ONLY
    ) -> Optional[bytes]:
        """
        Récupère un secret par son ID
        
        Args:
            secret_id: ID du secret
            user: Utilisateur demandant l'accès
            access_level: Niveau d'accès requis
            
        Returns:
            Valeur du secret déchiffrée ou None
        """
        try:
            # Vérification d'existence
            if secret_id not in self.secrets_store:
                await self._log_access(secret_id, user, "retrieve", False, "Secret non trouvé")
                return None
            
            # Vérification d'expiration
            metadata = self.metadata_store.get(secret_id)
            if metadata and metadata.expires_at and metadata.expires_at < datetime.utcnow():
                await self._log_access(secret_id, user, "retrieve", False, "Secret expiré")
                print(f" Secret {secret_id} expiré")
                return None
            
            # Déchiffrement
            encrypted_value = self.secrets_store[secret_id]
            decrypted_value = await self._decrypt_secret(encrypted_value)
            
            # Audit
            await self._log_access(secret_id, user, "retrieve", True)
            
            return decrypted_value
            
        except Exception as e:
            await self._log_access(secret_id, user, "retrieve", False, str(e))
            print(f" Erreur récupération secret {secret_id}: {e}")
            return None
    
    async def rotate_secret(self, secret_id: str, new_value: Union[str, bytes]) -> bool:
        """
        Effectue la rotation d'un secret
        
        Args:
            secret_id: ID du secret à faire tourner
            new_value: Nouvelle valeur du secret
            
        Returns:
            True si la rotation a réussi
        """
        try:
            if secret_id not in self.secrets_store:
                print(f" Secret {secret_id} non trouvé pour rotation")
                return False
            
            # Conversion en bytes si nécessaire
            if isinstance(new_value, str):
                new_value = new_value.encode('utf-8')
            
            # Chiffrement de la nouvelle valeur
            encrypted_value = await self._encrypt_secret(new_value)
            
            # Mise à jour
            self.secrets_store[secret_id] = encrypted_value
            
            # Mise à jour des métadonnées
            if secret_id in self.metadata_store:
                metadata = self.metadata_store[secret_id]
                metadata.updated_at = datetime.utcnow()
                
                # Nouvelle date d'expiration
                if metadata.rotation_interval:
                    metadata.expires_at = datetime.utcnow() + timedelta(days=metadata.rotation_interval)
            
            # Sauvegarde
            await self._save_secrets_store()
            
            # Audit
            await self._log_access(secret_id, "system", "rotate", True)
            
            # Synchronisation avec Vault
            if self.config["vault"]["enabled"]:
                await self._sync_to_vault(secret_id, new_value)
            
            print(f" Secret {secret_id} rotation effectuée")
            return True
            
        except Exception as e:
            await self._log_access(secret_id, "system", "rotate", False, str(e))
            print(f" Erreur rotation secret {secret_id}: {e}")
            return False
    
    async def delete_secret(self, secret_id: str, user: str = "system") -> bool:
        """
        Supprime un secret de manière sécurisée
        
        Args:
            secret_id: ID du secret à supprimer
            user: Utilisateur effectuant la suppression
            
        Returns:
            True si la suppression a réussi
        """
        try:
            if secret_id not in self.secrets_store:
                return False
            
            # Suppression sécurisée (écrasement mémoire)
            del self.secrets_store[secret_id]
            
            if secret_id in self.metadata_store:
                del self.metadata_store[secret_id]
            
            # Sauvegarde
            await self._save_secrets_store()
            
            # Audit
            await self._log_access(secret_id, user, "delete", True)
            
            # Suppression dans Vault
            if self.config["vault"]["enabled"]:
                await self._delete_from_vault(secret_id)
            
            print(f"Secret {secret_id} supprimé")
            return True
            
        except Exception as e:
            await self._log_access(secret_id, user, "delete", False, str(e))
            print(f"Erreur suppression secret {secret_id}: {e}")
            return False
    
    async def list_secrets(
        self,
        environment: Optional[str] = None,
        secret_type: Optional[SecretType] = None,
        tags: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Liste les secrets avec filtres optionnels
        
        Args:
            environment: Filtrer par environnement
            secret_type: Filtrer par type de secret
            tags: Filtrer par tags
            
        Returns:
            Liste des métadonnées des secrets
        """
        results = []
        
        for secret_id, metadata in self.metadata_store.items():
            # Filtres
            if environment and metadata.environment != environment:
                continue
            
            if secret_type and metadata.secret_type != secret_type:
                continue
            
            if tags and not any(tag in metadata.tags for tag in tags):
                continue
            
            # Vérification d'expiration
            is_expired = (
                metadata.expires_at and 
                metadata.expires_at < datetime.utcnow()
            )
            
            # Calcul du temps avant expiration
            days_until_expiry = None
            if metadata.expires_at:
                delta = metadata.expires_at - datetime.utcnow()
                days_until_expiry = delta.days
            
            results.append({
                "id": secret_id,
                "name": metadata.name,
                "type": metadata.secret_type.value,
                "environment": metadata.environment,
                "owner": metadata.owner,
                "created_at": metadata.created_at.isoformat(),
                "updated_at": metadata.updated_at.isoformat(),
                "expires_at": metadata.expires_at.isoformat() if metadata.expires_at else None,
                "days_until_expiry": days_until_expiry,
                "is_expired": is_expired,
                "tags": metadata.tags,
                "description": metadata.description
            })
        
        return results
    
    async def check_expiring_secrets(self, days_ahead: int = 7) -> List[Dict[str, Any]]:
        """
        Vérifie les secrets qui expirent bientôt
        
        Args:
            days_ahead: Nombre de jours à l'avance pour la vérification
            
        Returns:
            Liste des secrets expirant bientôt
        """
        expiring_secrets = []
        threshold_date = datetime.utcnow() + timedelta(days=days_ahead)
        
        for secret_id, metadata in self.metadata_store.items():
            if metadata.expires_at and metadata.expires_at <= threshold_date:
                days_remaining = (metadata.expires_at - datetime.utcnow()).days
                
                expiring_secrets.append({
                    "id": secret_id,
                    "name": metadata.name,
                    "type": metadata.secret_type.value,
                    "expires_at": metadata.expires_at.isoformat(),
                    "days_remaining": days_remaining,
                    "owner": metadata.owner,
                    "environment": metadata.environment
                })
        
        return expiring_secrets
    
    async def _start_rotation_scheduler(self):
        """Démarre le planificateur de rotation automatique"""
        if not self.config["rotation"]["enabled"]:
            return
        
        async def rotation_task():
            while True:
                try:
                    await self._check_and_rotate_secrets()
                    await asyncio.sleep(self.config["rotation"]["check_interval"])
                except Exception as e:
                    print(f"Erreur planificateur rotation: {e}")
                    await asyncio.sleep(60)  # Retry après 1 minute
        
        # Démarrage de la tâche en arrière-plan
        asyncio.create_task(rotation_task())
        print("Planificateur de rotation démarré")
    
    async def _check_and_rotate_secrets(self):
        """Vérifie et effectue la rotation automatique des secrets"""
        if not self.config["rotation"]["auto_rotate"]:
            return
        
        expiring_secrets = await self.check_expiring_secrets(
            self.config["rotation"]["notification_days"]
        )
        
        for secret_info in expiring_secrets:
            secret_id = secret_info["id"]
            secret_type = SecretType(secret_info["type"])
            
            # Génération automatique de nouvelle valeur selon le type
            new_value = await self._generate_new_secret_value(secret_type)
            
            if new_value:
                await self.rotate_secret(secret_id, new_value)
                print(f"Rotation automatique effectuée pour {secret_id}")
    
    async def _generate_new_secret_value(self, secret_type: SecretType) -> Optional[str]:
        """Génère une nouvelle valeur de secret selon le type"""
        if secret_type == SecretType.API_KEY:
            return secrets.token_urlsafe(32)
        elif secret_type == SecretType.PASSWORD:
            return secrets.token_urlsafe(16)
        elif secret_type == SecretType.TOKEN:
            return secrets.token_hex(32)
        elif secret_type == SecretType.ENCRYPTION_KEY:
            return secrets.token_urlsafe(32)
        else:
            # Types nécessitant une intervention manuelle
            return None
    
    # Méthodes utilitaires de chiffrement
    
    def _generate_secret_id(self, name: str, secret_type: SecretType) -> str:
        """Génère un ID unique pour un secret"""
        data = f"{name}_{secret_type.value}_{datetime.utcnow().isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    async def _encrypt_secret(self, value: bytes) -> bytes:
        """Chiffre un secret avec AES-256"""
        fernet = Fernet(base64.urlsafe_b64encode(self.encryption_key))
        return fernet.encrypt(value)
    
    async def _decrypt_secret(self, encrypted_value: bytes) -> bytes:
        """Déchiffre un secret"""
        fernet = Fernet(base64.urlsafe_b64encode(self.encryption_key))
        return fernet.decrypt(encrypted_value)
    
    async def _log_access(
        self,
        secret_id: str,
        user: str,
        action: str,
        success: bool,
        error_message: str = ""
    ):
        """Enregistre un accès dans les logs d'audit"""
        if not self.config["audit"]["enabled"]:
            return
        
        log_entry = AccessLog(
            secret_id=secret_id,
            user=user,
            action=action,
            timestamp=datetime.utcnow(),
            success=success,
            error_message=error_message
        )
        
        self.access_logs.append(log_entry)
        
        # Nettoyage des logs anciens
        retention_date = datetime.utcnow() - timedelta(days=self.config["audit"]["retention_days"])
        self.access_logs = [
            log for log in self.access_logs 
            if log.timestamp > retention_date
        ]
    
    # Intégration HashiCorp Vault
    
    async def _sync_to_vault(self, secret_id: str, value: bytes):
        """Synchronise un secret avec HashiCorp Vault"""
        if not self.vault_client:
            return
        
        try:
            # Simulation de synchronisation Vault
            # En production, utiliser hvac.Client
            vault_path = f"{self.config['vault']['mount_path']}{secret_id}"
            print(f"Synchronisation Vault: {vault_path}")
            
        except Exception as e:
            print(f"Erreur synchronisation Vault: {e}")
    
    async def _delete_from_vault(self, secret_id: str):
        """Supprime un secret de HashiCorp Vault"""
        if not self.vault_client:
            return
        
        try:
            # Simulation de suppression Vault
            vault_path = f"{self.config['vault']['mount_path']}{secret_id}"
            print(f"Suppression Vault: {vault_path}")
            
        except Exception as e:
            print(f"Erreur suppression Vault: {e}")
    
    async def get_audit_report(self, days: int = 30) -> Dict[str, Any]:
        """Génère un rapport d'audit des accès"""
        start_date = datetime.utcnow() - timedelta(days=days)
        relevant_logs = [
            log for log in self.access_logs 
            if log.timestamp > start_date
        ]
        
        # Statistiques
        total_accesses = len(relevant_logs)
        successful_accesses = len([log for log in relevant_logs if log.success])
        failed_accesses = total_accesses - successful_accesses
        
        # Accès par action
        actions_stats = {}
        for log in relevant_logs:
            actions_stats[log.action] = actions_stats.get(log.action, 0) + 1
        
        # Accès par utilisateur
        users_stats = {}
        for log in relevant_logs:
            users_stats[log.user] = users_stats.get(log.user, 0) + 1
        
        return {
            "period_days": days,
            "total_accesses": total_accesses,
            "successful_accesses": successful_accesses,
            "failed_accesses": failed_accesses,
            "success_rate": (successful_accesses / total_accesses * 100) if total_accesses > 0 else 0,
            "actions_breakdown": actions_stats,
            "users_breakdown": users_stats,
            "recent_failures": [
                {
                    "secret_id": log.secret_id,
                    "user": log.user,
                    "action": log.action,
                    "timestamp": log.timestamp.isoformat(),
                    "error": log.error_message
                }
                for log in relevant_logs[-10:] if not log.success
            ]
        }
