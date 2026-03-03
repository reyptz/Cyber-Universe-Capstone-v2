#!/usr/bin/env pwsh
# Script PowerShell pour le diagnostic TLS/mTLS
# Diagnostic complet des certificats et connexions TLS

param(
    [string]$Target = "localhost:5000",
    [string]$CertPath = "./certs",
    [string]$CAName = "flask-app-ca",
    [string]$ServiceName = "flask-app",
    [switch]$Verbose,
    [switch]$CheckExpiry,
    [switch]$TestConnection,
    [switch]$ValidateChain
)

# Configuration
$ErrorActionPreference = "Stop"
$CACertFile = "$CertPath/$CAName-cert.pem"
$ServiceCertFile = "$CertPath/$ServiceName-cert.pem"
$ServiceKeyFile = "$CertPath/$ServiceName-key.pem"

Write-Host "🔍 Diagnostic TLS pour $Target" -ForegroundColor Green
Write-Host "📁 Répertoire certificats: $CertPath" -ForegroundColor Gray
Write-Host "" # Ligne vide

function Test-OpenSSLAvailable {
    try {
        $null = Get-Command openssl -ErrorAction Stop
        return $true
    } catch {
        Write-Host "❌ OpenSSL non disponible" -ForegroundColor Red
        return $false
    }
}

function Get-CertificateInfo {
    param([string]$CertFile, [string]$Label)
    
    Write-Host "📜 Analyse du certificat: $Label" -ForegroundColor Cyan
    
    if (-not (Test-Path $CertFile)) {
        Write-Host "   ❌ Fichier non trouvé: $CertFile" -ForegroundColor Red
        return $false
    }
    
    try {
        # Informations de base
        Write-Host "   📋 Informations générales:" -ForegroundColor White
        $subject = & openssl x509 -in $CertFile -noout -subject 2>$null
        $issuer = & openssl x509 -in $CertFile -noout -issuer 2>$null
        $serial = & openssl x509 -in $CertFile -noout -serial 2>$null
        
        Write-Host "      Sujet: $($subject -replace 'subject=', '')" -ForegroundColor Gray
        Write-Host "      Émetteur: $($issuer -replace 'issuer=', '')" -ForegroundColor Gray
        Write-Host "      Série: $($serial -replace 'serial=', '')" -ForegroundColor Gray
        
        # Dates de validité
        Write-Host "   📅 Validité:" -ForegroundColor White
        $startDate = & openssl x509 -in $CertFile -noout -startdate 2>$null
        $endDate = & openssl x509 -in $CertFile -noout -enddate 2>$null
        
        $startDateStr = ($startDate -split '=')[1]
        $endDateStr = ($endDate -split '=')[1]
        $endDateTime = [DateTime]::ParseExact($endDateStr, "MMM dd HH:mm:ss yyyy GMT", $null)
        $daysLeft = ($endDateTime - (Get-Date)).Days
        
        Write-Host "      Début: $startDateStr" -ForegroundColor Gray
        Write-Host "      Fin: $endDateStr" -ForegroundColor Gray
        Write-Host "      Jours restants: $daysLeft" -ForegroundColor $(if ($daysLeft -le 30) { "Red" } elseif ($daysLeft -le 90) { "Yellow" } else { "Green" })
        
        # Extensions et SAN
        Write-Host "   🔧 Extensions:" -ForegroundColor White
        $extensions = & openssl x509 -in $CertFile -noout -text 2>$null | Select-String -Pattern "X509v3|DNS:|IP Address:"
        foreach ($ext in $extensions) {
            Write-Host "      $($ext.Line.Trim())" -ForegroundColor Gray
        }
        
        # Algorithme de signature
        $sigAlg = & openssl x509 -in $CertFile -noout -text 2>$null | Select-String "Signature Algorithm" | Select-Object -First 1
        Write-Host "   🔐 $($sigAlg.Line.Trim())" -ForegroundColor White
        
        return $true
        
    } catch {
        Write-Host "   ❌ Erreur analyse: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-CertificateChain {
    Write-Host "🔗 Validation de la chaîne de certificats" -ForegroundColor Cyan
    
    if (-not (Test-Path $CACertFile) -or -not (Test-Path $ServiceCertFile)) {
        Write-Host "   ❌ Certificats manquants pour la validation" -ForegroundColor Red
        return $false
    }
    
    try {
        # Vérifier la chaîne
        $result = & openssl verify -CAfile $CACertFile $ServiceCertFile 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "   ✅ Chaîne de certificats valide" -ForegroundColor Green
            Write-Host "      $result" -ForegroundColor Gray
        } else {
            Write-Host "   ❌ Chaîne de certificats invalide" -ForegroundColor Red
            Write-Host "      $result" -ForegroundColor Gray
        }
        
        return ($LASTEXITCODE -eq 0)
        
    } catch {
        Write-Host "   ❌ Erreur validation: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-PrivateKeyMatch {
    Write-Host "🔑 Vérification correspondance clé/certificat" -ForegroundColor Cyan
    
    if (-not (Test-Path $ServiceCertFile) -or -not (Test-Path $ServiceKeyFile)) {
        Write-Host "   ❌ Fichiers manquants" -ForegroundColor Red
        return $false
    }
    
    try {
        # Extraire les empreintes
        $certHash = & openssl x509 -in $ServiceCertFile -noout -modulus 2>$null | & openssl md5 2>$null
        $keyHash = & openssl rsa -in $ServiceKeyFile -noout -modulus 2>$null | & openssl md5 2>$null
        
        if ($certHash -eq $keyHash) {
            Write-Host "   ✅ Clé privée correspond au certificat" -ForegroundColor Green
        } else {
            Write-Host "   ❌ Clé privée ne correspond pas au certificat" -ForegroundColor Red
            if ($Verbose) {
                Write-Host "      Hash certificat: $certHash" -ForegroundColor Gray
                Write-Host "      Hash clé: $keyHash" -ForegroundColor Gray
            }
        }
        
        return ($certHash -eq $keyHash)
        
    } catch {
        Write-Host "   ❌ Erreur vérification: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Test-TLSConnection {
    param([string]$Target)
    
    Write-Host "🌐 Test de connexion TLS vers $Target" -ForegroundColor Cyan
    
    $host, $port = $Target -split ':'
    if (-not $port) { $port = "443" }
    
    try {
        # Test de connexion basique
        Write-Host "   🔌 Test de connectivité..." -ForegroundColor White
        $tcpTest = Test-NetConnection -ComputerName $host -Port $port -WarningAction SilentlyContinue
        
        if ($tcpTest.TcpTestSucceeded) {
            Write-Host "      ✅ Port $port accessible" -ForegroundColor Green
        } else {
            Write-Host "      ❌ Port $port inaccessible" -ForegroundColor Red
            return $false
        }
        
        # Test TLS avec OpenSSL
        Write-Host "   🔐 Test handshake TLS..." -ForegroundColor White
        $tlsTest = echo "" | & openssl s_client -connect $Target -servername $host -verify_return_error 2>&1
        
        if ($tlsTest -match "Verify return code: 0") {
            Write-Host "      ✅ Handshake TLS réussi" -ForegroundColor Green
            
            # Extraire des informations du certificat serveur
            $protocol = $tlsTest | Select-String "Protocol\s*:"
            $cipher = $tlsTest | Select-String "Cipher\s*:"
            
            if ($protocol) { Write-Host "      Protocole: $($protocol.Line.Trim())" -ForegroundColor Gray }
            if ($cipher) { Write-Host "      Chiffrement: $($cipher.Line.Trim())" -ForegroundColor Gray }
            
        } else {
            Write-Host "      ❌ Handshake TLS échoué" -ForegroundColor Red
            if ($Verbose) {
                $errors = $tlsTest | Select-String "error|fail" -AllMatches
                foreach ($error in $errors) {
                    Write-Host "         $($error.Line.Trim())" -ForegroundColor Gray
                }
            }
        }
        
        return $true
        
    } catch {
        Write-Host "   ❌ Erreur test connexion: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Show-SecurityRecommendations {
    Write-Host "🛡️  Recommandations de sécurité" -ForegroundColor Magenta
    Write-Host "   • Utilisez des certificats avec une validité ≤ 90 jours" -ForegroundColor White
    Write-Host "   • Activez la rotation automatique des certificats" -ForegroundColor White
    Write-Host "   • Surveillez les dates d'expiration" -ForegroundColor White
    Write-Host "   • Utilisez des algorithmes de chiffrement forts (RSA ≥ 2048, ECDSA ≥ 256)" -ForegroundColor White
    Write-Host "   • Implémentez OCSP stapling pour la révocation" -ForegroundColor White
    Write-Host "   • Configurez HSTS et certificate pinning" -ForegroundColor White
}

# Vérifications préliminaires
if (-not (Test-OpenSSLAvailable)) {
    exit 1
}

# Diagnostic principal
$allGood = $true

# Analyse des certificats
if (Test-Path $CACertFile) {
    $allGood = (Get-CertificateInfo -CertFile $CACertFile -Label "CA Root") -and $allGood
    Write-Host ""
}

if (Test-Path $ServiceCertFile) {
    $allGood = (Get-CertificateInfo -CertFile $ServiceCertFile -Label "Service") -and $allGood
    Write-Host ""
}

# Validations spécifiques
if ($ValidateChain) {
    $allGood = (Test-CertificateChain) -and $allGood
    Write-Host ""
}

if (Test-Path $ServiceKeyFile) {
    $allGood = (Test-PrivateKeyMatch) -and $allGood
    Write-Host ""
}

# Test de connexion
if ($TestConnection) {
    $allGood = (Test-TLSConnection -Target $Target) -and $allGood
    Write-Host ""
}

# Résumé final
Write-Host "📊 Résumé du diagnostic" -ForegroundColor White
if ($allGood) {
    Write-Host "✅ Tous les tests sont passés avec succès" -ForegroundColor Green
} else {
    Write-Host "⚠️  Certains problèmes ont été détectés" -ForegroundColor Yellow
}

Write-Host ""
Show-SecurityRecommendations

exit $(if ($allGood) { 0 } else { 1 })