#!/usr/bin/env pwsh
# Script PowerShell pour créer une mini-PKI
# Génération d'une autorité de certification (CA) pour mTLS

param(
    [string]$CAName = "flask-app-ca",
    [string]$OutputDir = "./certs",
    [int]$ValidityDays = 365,
    [switch]$Force
)

# Configuration
$ErrorActionPreference = "Stop"
$CAKeyFile = "$OutputDir/$CAName-key.pem"
$CACertFile = "$OutputDir/$CAName-cert.pem"
$CAConfigFile = "$OutputDir/$CAName.conf"

Write-Host "🔐 Création de la mini-PKI pour $CAName" -ForegroundColor Green

# Créer le répertoire de sortie
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Host "📁 Répertoire créé: $OutputDir" -ForegroundColor Yellow
}

# Vérifier si les certificats existent déjà
if ((Test-Path $CACertFile) -and -not $Force) {
    Write-Host "⚠️  Le certificat CA existe déjà. Utilisez -Force pour le recréer." -ForegroundColor Yellow
    exit 0
}

# Configuration OpenSSL pour la CA
$CAConfig = @"
[ req ]
default_bits = 4096
encrypt_key = no
default_md = sha256
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
C = FR
ST = IDF
L = Paris
O = Flask App DevSecOps
OU = Security Team
CN = $CAName Root CA
emailAddress = security@flask-app.local

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical,digitalSignature,cRLSign,keyCertSign
"@

# Écrire la configuration
$CAConfig | Out-File -FilePath $CAConfigFile -Encoding UTF8
Write-Host "📝 Configuration CA créée: $CAConfigFile" -ForegroundColor Cyan

try {
    # Vérifier la présence d'OpenSSL
    $opensslPath = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $opensslPath) {
        throw "OpenSSL n'est pas installé ou pas dans le PATH"
    }

    Write-Host "🔑 Génération de la clé privée CA..." -ForegroundColor Cyan
    & openssl genrsa -out $CAKeyFile 4096
    if ($LASTEXITCODE -ne 0) { throw "Erreur lors de la génération de la clé CA" }

    Write-Host "📜 Génération du certificat CA..." -ForegroundColor Cyan
    & openssl req -new -x509 -days $ValidityDays -key $CAKeyFile -out $CACertFile -config $CAConfigFile
    if ($LASTEXITCODE -ne 0) { throw "Erreur lors de la génération du certificat CA" }

    # Vérification du certificat
    Write-Host "🔍 Vérification du certificat CA..." -ForegroundColor Cyan
    & openssl x509 -in $CACertFile -text -noout | Select-String "Subject:", "Validity", "Public Key"

    # Permissions sécurisées pour la clé privée
    if ($IsLinux -or $IsMacOS) {
        chmod 600 $CAKeyFile
        chmod 644 $CACertFile
    } else {
        # Windows - Restreindre l'accès à la clé privée
        $acl = Get-Acl $CAKeyFile
        $acl.SetAccessRuleProtection($true, $false)
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            "FullControl",
            "Allow"
        )
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path $CAKeyFile -AclObject $acl
    }

    Write-Host "✅ CA créée avec succès!" -ForegroundColor Green
    Write-Host "📁 Fichiers générés:" -ForegroundColor White
    Write-Host "   - Clé privée: $CAKeyFile" -ForegroundColor Gray
    Write-Host "   - Certificat: $CACertFile" -ForegroundColor Gray
    Write-Host "   - Configuration: $CAConfigFile" -ForegroundColor Gray

    # Créer un script de nettoyage
    $CleanupScript = @"
#!/usr/bin/env pwsh
# Script de nettoyage des certificats
Write-Host "🧹 Nettoyage des certificats..." -ForegroundColor Yellow
Remove-Item -Path "$OutputDir" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "✅ Nettoyage terminé" -ForegroundColor Green
"@
    $CleanupScript | Out-File -FilePath "$OutputDir/cleanup.ps1" -Encoding UTF8

} catch {
    Write-Host "❌ Erreur: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "🎯 Prochaines étapes:" -ForegroundColor Magenta
Write-Host "   1. Générer des certificats serveur avec ./generate-server-cert.ps1" -ForegroundColor White
Write-Host "   2. Créer des secrets Kubernetes avec les certificats" -ForegroundColor White
Write-Host "   3. Configurer mTLS dans votre application" -ForegroundColor White