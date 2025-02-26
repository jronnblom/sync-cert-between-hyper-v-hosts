#Requires -RunAsAdministrator
#Requires -Modules FailoverClusters, Hyper-V

<#
.SYNOPSIS
    Synchronizes Shielded VM Local Certificates across all hosts in a failover cluster.

.DESCRIPTION
    This script gets all hosts in a specified failover cluster, checks if each host is online,
    compares the "Shielded VM Local Certificates" store across all online hosts, and updates
    any host that is missing certificates.

.PARAMETER ClusterName
    The name of the failover cluster. If not specified, the script will prompt for it.

.PARAMETER Verify
    If specified, the script will only check and report which certificates are missing on which hosts,
    without performing any synchronization.

.PARAMETER ReplaceExpiring
    If specified, the script will replace certificates with newer versions that have the same subject
    but a more recent expiry date.

.EXAMPLE
    .\hv-sync-certs.ps1 -ClusterName "HVCluster01"

.EXAMPLE
    .\hv-sync-certs.ps1 -ClusterName "HVCluster01" -Verify

.EXAMPLE
    .\hv-sync-certs.ps1 -ClusterName "HVCluster01" -ReplaceExpiring

.NOTES
    Author: Script Generator
    Requires: PowerShell 5.1 or later, Failover Clustering and Hyper-V modules
    Version: 1.2
#>

param (
    [Parameter(Mandatory=$false)]
    [string]$ClusterName,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verify,
    
    [Parameter(Mandatory=$false)]
    [switch]$ReplaceExpiring
)

# Function to check if a host is online
function Test-HostOnline {
    param (
        [Parameter(Mandatory=$true)]
        [string]$HostName
    )
    
    $pingResult = Test-Connection -ComputerName $HostName -Count 1 -Quiet
    return $pingResult
}

# Function to check if the Shielded VM certificate store exists and create it if needed
function Test-ShieldedVMCertStore {
    param (
        [Parameter(Mandatory=$true)]
        [string]$HostName
    )
    
    try {
        $result = Invoke-Command -ComputerName $HostName -ScriptBlock {
            # Check if the certificate store exists
            $storePath = "Cert:\LocalMachine\Shielded VM Local Certificates"
            $storeExists = Test-Path -Path $storePath
            
            if (-not $storeExists) {
                Write-Host "Shielded VM Local Certificates store does not exist on this host." -ForegroundColor Yellow
                
                # Check if the Shielded VM feature is installed
                $featureInstalled = Get-WindowsFeature -Name HostGuardian -ErrorAction SilentlyContinue
                
                if (-not $featureInstalled -or -not $featureInstalled.Installed) {
                    Write-Host "The Host Guardian Service feature is not installed on this host." -ForegroundColor Red
                    Write-Host "This feature is required for Shielded VMs and the associated certificate store." -ForegroundColor Red
                    
                    return @{
                        Success = $false
                        Status = "FeatureNotInstalled"
                        Message = "The Host Guardian Service feature is not installed on this host."
                    }
                }
                
                # Try to create the certificate store
                try {
                    # Create a new X509 store with the correct name including spaces
                    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Shielded VM Local Certificates", "LocalMachine")
                    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    $store.Close()
                    
                    # Verify the store was created
                    $storeExists = Test-Path -Path $storePath
                    
                    if ($storeExists) {
                        Write-Host "Successfully created Shielded VM Local Certificates store." -ForegroundColor Green
                        return @{
                            Success = $true
                            Status = "StoreCreated"
                        }
                    }
                    else {
                        Write-Host "Failed to create Shielded VM Local Certificates store." -ForegroundColor Red
                        return @{
                            Success = $false
                            Status = "CreateFailed"
                            Message = "Failed to create the certificate store even though the feature appears to be installed."
                        }
                    }
                }
                catch {
                    $errorMessage = $_.ToString()
                    Write-Host "Error creating Shielded VM Local Certificates store: $errorMessage" -ForegroundColor Red
                    return @{
                        Success = $false
                        Status = "CreateError"
                        Message = "Error creating certificate store: $errorMessage"
                    }
                }
            }
            
            # Store exists
            return @{
                Success = $true
                Status = "StoreExists"
            }
        } -ErrorAction Stop
        
        return $result
    }
    catch {
        $errorMessage = $_.ToString()
        Write-Warning "Failed to check/create certificate store on $HostName. Error: $errorMessage"
        return @{
            Success = $false
            Status = "ConnectionError"
            Message = "Failed to connect to host: $errorMessage"
        }
    }
}

# Function to get certificates from a host
function Get-ShieldedVMCertificates {
    param (
        [Parameter(Mandatory=$true)]
        [string]$HostName
    )
    
    # First check if the certificate store exists
    $storeCheck = Test-ShieldedVMCertStore -HostName $HostName
    
    if (-not $storeCheck.Success) {
        $errorMsg = $storeCheck.Message
        Write-Warning "Cannot get certificates from $HostName`: $errorMsg"
        return $null
    }
    
    try {
        $certs = Invoke-Command -ComputerName $HostName -ScriptBlock {
            $certificates = Get-Item -Path "Cert:\LocalMachine\Shielded VM Local Certificates\*" -ErrorAction SilentlyContinue
            
            # Convert certificates to a format that can be serialized across the remoting boundary
            $certDetails = @()
            foreach ($cert in $certificates) {
                $certDetails += @{
                    Thumbprint = $cert.Thumbprint
                    Subject = $cert.Subject
                    Issuer = $cert.Issuer
                    NotBefore = $cert.NotBefore
                    NotAfter = $cert.NotAfter
                    SerialNumber = $cert.SerialNumber
                    HasPrivateKey = $cert.HasPrivateKey
                    Certificate = $cert
                }
            }
            
            return $certDetails
        } -ErrorAction Stop
        
        return $certs
    }
    catch {
        $errorMessage = $_.ToString()
        Write-Warning "Failed to get certificates from $HostName. Error: $errorMessage"
        return $null
    }
}

# Function to export a certificate to a file
function Export-CertificateToFile {
    param (
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )
    
    try {
        $certBytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        [System.IO.File]::WriteAllBytes($FilePath, $certBytes)
        return $true
    }
    catch {
        $errorMessage = $_.ToString()
        Write-Warning "Failed to export certificate to $FilePath. Error: $errorMessage"
        return $false
    }
}

# Function to import a certificate to a host
function Import-CertificateToHost {
    param (
        [Parameter(Mandatory=$true)]
        [string]$HostName,
        
        [Parameter(Mandatory=$true)]
        [string]$CertificatePath,
        
        [Parameter(Mandatory=$true)]
        [string]$Thumbprint,
        
        [Parameter(Mandatory=$false)]
        [switch]$ReplaceExpiring
    )
    
    # First check if the certificate store exists
    $storeCheck = Test-ShieldedVMCertStore -HostName $HostName
    
    if (-not $storeCheck.Success) {
        $errorMsg = $storeCheck.Message
        Write-Warning "Cannot import certificate to $HostName`: $errorMsg"
        return @{
            Success = $false
            Status = "StoreNotAvailable"
            ErrorMessage = $errorMsg
        }
    }
    
    try {
        $result = Invoke-Command -ComputerName $HostName -ScriptBlock {
            param($CertPath, $CertThumbprint, $ShouldReplaceExpiring)
            
            # Import the new certificate first to examine its properties
            $newCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $newCert.Import($CertPath)
            
            # Verify the thumbprint matches what we expect
            if ($newCert.Thumbprint -ne $CertThumbprint) {
                Write-Warning "Certificate thumbprint mismatch. Expected: $CertThumbprint, Actual: $($newCert.Thumbprint)"
                return @{
                    Success = $false
                    Status = "ThumbprintMismatch"
                }
            }
            
            # Check if certificate already exists
            $existingCert = Get-Item -Path "Cert:\LocalMachine\Shielded VM Local Certificates\$CertThumbprint" -ErrorAction SilentlyContinue
            
            if ($existingCert) {
                Write-Host "Certificate with thumbprint $CertThumbprint already exists on this host." -ForegroundColor Yellow
                # Certificate already exists, no need to import
                return @{
                    Success = $true
                    Status = "AlreadyExists"
                }
            }
            
            # If we're replacing expiring certificates, check for certificates with the same subject
            if ($ShouldReplaceExpiring) {
                $subjectCerts = Get-ChildItem -Path "Cert:\LocalMachine\Shielded VM Local Certificates\" | 
                                Where-Object { $_.Subject -eq $newCert.Subject }
                
                if ($subjectCerts) {
                    $replacedCerts = @()
                    
                    foreach ($existingCert in $subjectCerts) {
                        # If the new certificate expires later than the existing one, replace it
                        if ($newCert.NotAfter -gt $existingCert.NotAfter) {
                            Write-Host "Found certificate with same subject but earlier expiry date: $($existingCert.Thumbprint), expires: $($existingCert.NotAfter)" -ForegroundColor Yellow
                            Write-Host "New certificate expires: $($newCert.NotAfter)" -ForegroundColor Yellow
                            
                            # Store the thumbprint for reporting
                            $replacedCerts += @{
                                Thumbprint = $existingCert.Thumbprint
                                ExpiryDate = $existingCert.NotAfter
                            }
                        }
                    }
                    
                    if ($replacedCerts.Count -gt 0) {
                        # We found certificates to replace, proceed with import
                        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Shielded VM Local Certificates", "LocalMachine")
                        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                        $store.Add($newCert)
                        $store.Close()
                        
                        return @{
                            Success = $true
                            Status = "ReplacedExpiring"
                            ReplacedCertificates = $replacedCerts
                        }
                    }
                }
            }
            
            # Standard import case - no existing certificate with same thumbprint or subject to replace
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Shielded VM Local Certificates", "LocalMachine")
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $store.Add($newCert)
            $store.Close()
            
            # Clean up the temporary file
            Remove-Item -Path $CertPath -Force
            
            return @{
                Success = $true
                Status = "Imported"
            }
        } -ArgumentList $CertificatePath, $Thumbprint, $ReplaceExpiring -ErrorAction Stop
        
        return $result
    }
    catch {
        $errorMessage = $_.ToString()
        Write-Warning "Failed to import certificate to $HostName. Error: $errorMessage"
        return @{
            Success = $false
            Status = "Error"
            ErrorMessage = $errorMessage
        }
    }
}

# Main script execution starts here
Write-Host "Shielded VM Certificate Synchronization Tool" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

if ($Verify) {
    Write-Host "Running in VERIFY mode - certificates will be checked but NOT synchronized" -ForegroundColor Yellow
}

if ($ReplaceExpiring) {
    Write-Host "Running with REPLACE EXPIRING mode - certificates with newer expiry dates will replace older ones" -ForegroundColor Yellow
}

# Prompt for cluster name if not provided
if (-not $ClusterName) {
    $ClusterName = Read-Host "Enter the name of the failover cluster"
}

# Get all nodes in the cluster
try {
    Write-Host "Getting nodes from cluster '$ClusterName'..." -ForegroundColor Yellow
    $clusterNodes = Get-ClusterNode -Cluster $ClusterName -ErrorAction Stop
    
    if (-not $clusterNodes -or $clusterNodes.Count -eq 0) {
        Write-Host "No nodes found in cluster '$ClusterName'." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Found $($clusterNodes.Count) nodes in the cluster." -ForegroundColor Green
}
catch {
    Write-Host "Failed to get nodes from cluster '$ClusterName'. Error: $_" -ForegroundColor Red
    exit 1
}

# Check which hosts are online and have the required certificate store
$onlineHosts = @()
$offlineHosts = @()
$incompatibleHosts = @()

foreach ($node in $clusterNodes) {
    $nodeName = $node.Name
    Write-Host "Checking if host '$nodeName' is online..." -ForegroundColor Yellow
    
    if (Test-HostOnline -HostName $nodeName) {
        Write-Host "Host '$nodeName' is online." -ForegroundColor Green
        
        # Check if the host has the Shielded VM certificate store
        Write-Host "Checking if host '$nodeName' has the Shielded VM certificate store..." -ForegroundColor Yellow
        $storeCheck = Test-ShieldedVMCertStore -HostName $nodeName
        
        if ($storeCheck.Success) {
            Write-Host "Host '$nodeName' has the Shielded VM certificate store." -ForegroundColor Green
            $onlineHosts += $nodeName
        }
        else {
            Write-Host "Host '$nodeName' does not have the Shielded VM certificate store and cannot be used." -ForegroundColor Red
            Write-Host "  Reason: $($storeCheck.Message)" -ForegroundColor Red
            $incompatibleHosts += @{
                Name = $nodeName
                Reason = $storeCheck.Message
            }
        }
    }
    else {
        Write-Host "Host '$nodeName' is offline." -ForegroundColor Red
        $offlineHosts += $nodeName
    }
}

if ($onlineHosts.Count -eq 0) {
    Write-Host "No compatible online hosts found. Exiting." -ForegroundColor Red
    exit 1
}

# Create a temporary directory for certificate exchange
$tempDir = Join-Path -Path $env:TEMP -ChildPath "ShieldedVMCerts_$(Get-Random)"
if (-not $Verify) {
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
}

try {
    # Get certificates from all online hosts
    $hostCertificates = @{}
    $allCertificates = @{}
    
    foreach ($hostName in $onlineHosts) {
        Write-Host "Getting certificates from host '$hostName'..." -ForegroundColor Yellow
        $certificates = Get-ShieldedVMCertificates -HostName $hostName
        
        if ($certificates) {
            $hostCertificates[$hostName] = $certificates
            
            foreach ($cert in $certificates) {
                $thumbprint = $cert.Thumbprint
                
                if (-not $allCertificates.ContainsKey($thumbprint)) {
                    $allCertificates[$thumbprint] = @{
                        Certificate = $cert
                        SourceHost = $hostName
                        Hosts = @($hostName)
                    }
                }
                else {
                    $allCertificates[$thumbprint].Hosts += $hostName
                }
            }
            
            Write-Host "Found $($certificates.Count) certificates on host '$hostName'." -ForegroundColor Green
        }
        else {
            Write-Host "No certificates found on host '$hostName'." -ForegroundColor Yellow
            $hostCertificates[$hostName] = @()
        }
    }
    
    # Identify missing certificates for each host
    $syncOperations = @()
    
    foreach ($hostName in $onlineHosts) {
        $hostCerts = $hostCertificates[$hostName]
        $hostThumbprints = $hostCerts | ForEach-Object { $_.Thumbprint }
        
        foreach ($thumbprint in $allCertificates.Keys) {
            if ($hostThumbprints -notcontains $thumbprint) {
                $sourceHost = $allCertificates[$thumbprint].SourceHost
                
                # Skip if the source host is the same as the target host (prevent self-importing)
                if ($sourceHost -eq $hostName) {
                    Write-Host "Warning: Certificate $thumbprint appears to be from host '$hostName' but wasn't detected in the initial scan. Skipping self-import." -ForegroundColor Yellow
                    continue
                }
                
                $syncOperations += @{
                    TargetHost = $hostName
                    SourceHost = $sourceHost
                    Certificate = $allCertificates[$thumbprint].Certificate
                    Thumbprint = $thumbprint
                }
            }
        }
    }
    
    # Perform synchronization or just report in verify mode
    if ($syncOperations.Count -eq 0) {
        Write-Host "All hosts have the same certificates. No synchronization needed." -ForegroundColor Green
    }
    else {
        Write-Host "Found $($syncOperations.Count) certificates that need to be synchronized." -ForegroundColor Yellow
        
        # Group operations by target host for better reporting
        $groupedOperations = $syncOperations | Group-Object -Property TargetHost
        
        foreach ($group in $groupedOperations) {
            $targetHost = $group.Name
            $missingCerts = $group.Group
            
            Write-Host "`nHost '$targetHost' is missing $($missingCerts.Count) certificates:" -ForegroundColor Yellow
            
            foreach ($operation in $missingCerts) {
                $sourceHost = $operation.SourceHost
                $thumbprint = $operation.Thumbprint
                
                Write-Host "  - Certificate $thumbprint (available on '$sourceHost')" -ForegroundColor White
            }
        }
        
        # Only perform synchronization if not in verify mode
        if (-not $Verify) {
            Write-Host "`nPerforming synchronization..." -ForegroundColor Yellow
            
            foreach ($operation in $syncOperations) {
                $sourceHost = $operation.SourceHost
                $targetHost = $operation.TargetHost
                $cert = $operation.Certificate
                $thumbprint = $operation.Thumbprint
                
                Write-Host "Synchronizing certificate $thumbprint from '$sourceHost' to '$targetHost'..." -ForegroundColor Yellow
                
                # Export certificate to a file
                $certFile = Join-Path -Path $tempDir -ChildPath "$thumbprint.cer"
                $exportResult = Export-CertificateToFile -Certificate $cert.Certificate -FilePath $certFile
                
                if ($exportResult) {
                    # Copy the certificate file to the target host
                    $targetCertPath = "\\$targetHost\C$\Windows\Temp\$thumbprint.cer"
                    Copy-Item -Path $certFile -Destination $targetCertPath -Force
                    
                    # Import the certificate on the target host
                    $importResult = Import-CertificateToHost -HostName $targetHost -CertificatePath "C:\Windows\Temp\$thumbprint.cer" -Thumbprint $thumbprint -ReplaceExpiring:$ReplaceExpiring
                    
                    if ($importResult.Success) {
                        switch ($importResult.Status) {
                            "AlreadyExists" {
                                Write-Host "Certificate $thumbprint already exists on '$targetHost'. No changes made." -ForegroundColor Yellow
                            }
                            "ReplacedExpiring" {
                                Write-Host "Successfully imported certificate $thumbprint to '$targetHost', replacing older certificates with same subject." -ForegroundColor Green
                                foreach ($replaced in $importResult.ReplacedCertificates) {
                                    Write-Host "  - Replaced certificate: $($replaced.Thumbprint) (expired: $($replaced.ExpiryDate))" -ForegroundColor Yellow
                                }
                            }
                            default {
                                Write-Host "Successfully synchronized certificate $thumbprint to '$targetHost'." -ForegroundColor Green
                            }
                        }
                    }
                    else {
                        if ($importResult.Status -eq "ThumbprintMismatch") {
                            Write-Host "Failed to import certificate to '$targetHost'. Thumbprint mismatch detected." -ForegroundColor Red
                        } else {
                            Write-Host "Failed to import certificate $thumbprint to '$targetHost'. Error: $($importResult.ErrorMessage)" -ForegroundColor Red
                        }
                    }
                    
                    # Clean up the local certificate file
                    Remove-Item -Path $certFile -Force -ErrorAction SilentlyContinue
                }
                else {
                    Write-Host "Failed to export certificate $thumbprint from '$sourceHost'." -ForegroundColor Red
                }
            }
        }
        else {
            Write-Host "`nVerify mode is enabled. No certificates will be synchronized." -ForegroundColor Yellow
            Write-Host "Run the script without the -Verify parameter to perform synchronization." -ForegroundColor Yellow
        }
    }
    
    # Summary
    Write-Host "`nSynchronization Summary:" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    Write-Host "Total hosts in cluster: $($clusterNodes.Count)" -ForegroundColor White
    Write-Host "Online hosts with Shielded VM support: $($onlineHosts.Count)" -ForegroundColor Green
    Write-Host "Offline hosts: $($offlineHosts.Count)" -ForegroundColor Red
    if ($incompatibleHosts.Count -gt 0) {
        Write-Host "Incompatible hosts: $($incompatibleHosts.Count)" -ForegroundColor Red
    }
    Write-Host "Total unique certificates: $($allCertificates.Count)" -ForegroundColor White
    Write-Host "Certificates that need synchronization: $($syncOperations.Count)" -ForegroundColor Yellow
    
    if ($Verify) {
        Write-Host "Mode: VERIFY (no synchronization performed)" -ForegroundColor Yellow
    }
    else {
        if ($ReplaceExpiring) {
            Write-Host "Mode: SYNCHRONIZE WITH CERTIFICATE RENEWAL" -ForegroundColor Green
        }
        else {
            Write-Host "Mode: SYNCHRONIZE" -ForegroundColor Green
        }
    }
    
    if ($offlineHosts.Count -gt 0) {
        Write-Host "`nWarning: The following hosts were offline and could not be checked/synchronized:" -ForegroundColor Yellow
        foreach ($offlineHost in $offlineHosts) {
            Write-Host "  - $offlineHost" -ForegroundColor Red
        }
        Write-Host "Please run this script again when these hosts are online." -ForegroundColor Yellow
    }

    if ($incompatibleHosts.Count -gt 0) {
        Write-Host "`nWarning: The following hosts do not have Shielded VM support configured:" -ForegroundColor Yellow
        foreach ($host in $incompatibleHosts) {
            Write-Host "  - $($host.Name): $($host.Reason)" -ForegroundColor Red
        }
        Write-Host "These hosts were excluded from certificate synchronization." -ForegroundColor Yellow
        Write-Host "To include these hosts, ensure the Host Guardian Service feature is installed and configured." -ForegroundColor Yellow
    }
}
finally {
    # Clean up
    if (-not $Verify -and (Test-Path -Path $tempDir)) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`nScript completed." -ForegroundColor Cyan


