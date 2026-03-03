#!/usr/bin/env pwsh
# Script PowerShell pour la rotation automatique des certificats
# Rotation sécurisée des certificats avec validation et backup

param(
    [string]$CertPath = "./certs",
    [string]$CAName = "flask-app-ca",
    [string]$ServiceName = "flask-app",
    [int]$ValidityDays = 90,
    [int]$WarningDays = 30,
    [switch]$Force,
    [switch]$DryRun
)

# Configuration
$ErrorActionPreference = "Stop"
$BackupDir = "$CertPath/backup/$(Get-Date -Format 'yyyy-MM-dd-HHmmss')"
$CACertFile = "$CertPath/$CAName-cert.pem"
$CAKeyFile = "$CertPath/$CAName-key.pem"
$ServiceCertFile = "$CertPath/$ServiceName-cert.pem"
$ServiceKeyFile = "$CertPath/$ServiceName-key.pem"

Write-Host "🔄 Rotation des certificats pour $ServiceName" -ForegroundColor Green

function Test-CertificateExpiry {
    param([string]$CertFile, [int]$WarningDays)
    
    if (-not (Test-Path $CertFile)) {
        return @{ Exists = $false; DaysLeft = 0; NeedsRotation = $true }
    }
    
    try {
        $certInfo = & openssl x509 -in $CertFile -noout -enddate 2>$null
        if ($LASTEXITCODE -ne 0) {
            return @{ Exists = $true; DaysLeft = 0; NeedsRotation = $true; Error = "Certificat invalide" }
        }
        
        $endDateStr = ($certInfo -split '=')[1]
        $endDate = [DateTime]::ParseExact($endDateStr, "MMM dd HH:mm:ss yyyy GMT", $null)
        $daysLeft = ($endDate - (Get-Date)).Days
        
        return @{
            Exists = $true
            DaysLeft = $daysLeft
            NeedsRotation = ($daysLeft -le $WarningDays)
            EndDate = $endDate
        }
    } catch {
        return @{ Exists = $true; DaysLeft = 0; NeedsRotation = $true; Error = $_.Exception.Message }
    }
}

function Backup-Certificates {
    if ($DryRun) {
        Write-Host "[DRY-RUN] Sauvegarde des certificats vers: $BackupDir" -ForegroundColor Yellow
        return
    }
    
    Write-Host "💾 Sauvegarde des certificats existants..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    
    $filesToBackup = @($ServiceCertFile, $ServiceKeyFile)
    foreach ($file in $filesToBackup) {
        if (Test-Path $file) {
            $fileName = Split-Path $file -Leaf
            Copy-Item $file "$BackupDir/$fileName"
            Write-Host "   ✅ Sauvegardé: $fileName" -ForegroundColor Gray
        }
    }
}

function Generate-ServiceCertificate {
    if ($DryRun) {
        Write-Host "[DRY-RUN] Génération du nouveau certificat pour $ServiceName" -ForegroundColor Yellow
        return
    }
    
    Write-Host "🔑 Génération du nouveau certificat pour $ServiceName..." -ForegroundColor Cyan
    
    # Configuration pour le certificat serveur
    $ServiceConfig = @"
[ req ]
default_bits = 2048
encrypt_key = no
default_md = sha256
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = FR
ST = IDF
L = Paris
O = Flask App DevSecOps
OU = Application Team
CN = $ServiceName.flask-app.svc.cluster.local
emailAddress = app@flask-app.local

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = $ServiceName
DNS.2 = $ServiceName.flask-app
DNS.3 = $ServiceName.flask-app.svc
DNS.4 = $ServiceName.flask-app.svc.cluster.local
DNS.5 = localhost
IP.1 = 127.0.0.1
"@
    
    $configFile = "$CertPath/$ServiceName.conf"
    $ServiceConfig | Out-File -FilePath $configFile -Encoding UTF8
    
    try {
        # Générer la clé privée
        & openssl genrsa -out $ServiceKeyFile 2048
        if ($LASTEXITCODE -ne 0) { throw "Erreur génération clé" }
        
        # Générer la demande de certificat
        $csrFile = "$CertPath/$ServiceName.csr"
        & openssl req -new -key $ServiceKeyFile -out $csrFile -config $configFile
        if ($LASTEXITCODE -ne 0) { throw "Erreur génération CSR" }
        
        # Signer avec la CA
        & openssl x509 -req -in $csrFile -CA $CACertFile -CAkey $CAKeyFile -CAcreateserial -out $ServiceCertFile -days $ValidityDays -extensions v3_req -extfile $configFile
        if ($LASTEXITCODE -ne 0) { throw "Erreur signature certificat" }
        
        # Nettoyer les fichiers temporaires
        Remove-Item $csrFile, $configFile -ErrorAction SilentlyContinue
        
        Write-Host "   ✅ Certificat généré avec succès" -ForegroundColor Green
        
    } catch {
        Write-Host "   ❌ Erreur: $($_.Exception.Message)" -ForegroundColor Red
        throw
    }
}

function Update-KubernetesSecret {
    param([string]$SecretName = "$ServiceName-tls")
    
    if ($DryRun) {
        Write-Host "[DRY-RUN] Mise à jour du secret Kubernetes: $SecretName" -ForegroundColor Yellow
        return
    }
    
    Write-Host "☸️  Mise à jour du secret Kubernetes..." -ForegroundColor Cyan
    
    try {
        # Vérifier si kubectl est disponible
        $kubectl = Get-Command kubectl -ErrorAction SilentlyContinue
        if (-not $kubectl) {
            Write-Host "   ⚠️  kubectl non trouvé, secret non mis à jour" -ForegroundColor Yellow
            return
        }
        
        # Créer ou mettre à jour le secret TLS
        & kubectl create secret tls $SecretName --cert=$ServiceCertFile --key=$ServiceKeyFile --namespace=flask-app --dry-run=client -o yaml | kubectl apply -f -
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ Secret Kubernetes mis à jour" -ForegroundColor Green
        } else {
            Write-Host "   ⚠️  Erreur mise à jour secret Kubernetes" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "   ⚠️  Erreur kubectl: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Vérification des prérequis
try {
    $opensslPath = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $opensslPath) {
        throw "OpenSSL n'est pas installé ou pas dans le PATH"
    }
    
    if (-not (Test-Path $CACertFile) -or -not (Test-Path $CAKeyFile)) {
        throw "Certificats CA non trouvés. Exécutez d'abord mk-ca.ps1"
    }
    
} catch {
    Write-Host "❌ Erreur: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Vérification de l'expiration
$certStatus = Test-CertificateExpiry -CertFile $ServiceCertFile -WarningDays $WarningDays

Write-Host "📊 État du certificat:" -ForegroundColor White
if ($certStatus.Exists) {
    if ($certStatus.Error) {
        Write-Host "   ❌ Erreur: $($certStatus.Error)" -ForegroundColor Red
    } else {
        Write-Host "   📅 Expire dans: $($certStatus.DaysLeft) jours" -ForegroundColor $(if ($certStatus.DaysLeft -le $WarningDays) { "Red" } else { "Green" })
        Write-Host "   📆 Date d'expiration: $($certStatus.EndDate)" -ForegroundColor Gray
    }
} else {
    Write-Host "   ❌ Certificat non trouvé" -ForegroundColor Red
}

# Décision de rotation
if ($Force -or $certStatus.NeedsRotation) {
    if ($Force) {
        Write-Host "🔄 Rotation forcée demandée" -ForegroundColor Yellow
    } else {
        Write-Host "⚠️  Rotation nécessaire (expire dans $($certStatus.DaysLeft) jours)" -ForegroundColor Yellow
    }
    
    try {
        Backup-Certificates
        Generate-ServiceCertificate
        Update-KubernetesSecret
        
        if (-not $DryRun) {
            Write-Host "✅ Rotation terminée avec succès!" -ForegroundColor Green
            Write-Host "📁 Sauvegarde disponible dans: $BackupDir" -ForegroundColor Gray
        }
        
    } catch {
        Write-Host "❌ Erreur lors de la rotation: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    
} else {
    Write-Host "✅ Certificat valide, aucune rotation nécessaire" -ForegroundColor Green
}

Write-Host "🎯 Prochaine vérification recommandée dans $([Math]::Max(1, $certStatus.DaysLeft - $WarningDays)) jours" -ForegroundColor Magenta