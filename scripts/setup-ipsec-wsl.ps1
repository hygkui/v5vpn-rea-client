#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Import the v5vpn WSL distribution and install strongSwan for the IPsec
  (Network Connect) data plane.

.DESCRIPTION
  The V5VPN client brings IPsec subnets up through strongSwan inside WSL2.
  This script is a one-time setup; it must run elevated. It imports an
  Ubuntu rootfs with `wsl --import` (no Microsoft Store needed) and installs
  strongSwan, iptables and iproute2 inside it.

.PARAMETER RootFS
  Path to an Ubuntu rootfs tarball (e.g. ubuntu-base-24.04.3-base-amd64.tar.gz).

.PARAMETER Distro
  WSL distribution name. Must match ipsec.DefaultDistro (v5vpn).

.PARAMETER InstallDir
  Directory that will hold the distribution's virtual disk.

.EXAMPLE
  .\setup-ipsec-wsl.ps1 -RootFS C:\wsl\ubuntu-base-24.04.tar.gz
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$RootFS,
    [string]$Distro = 'v5vpn',
    [string]$InstallDir = "C:\wsl\v5vpn"
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $RootFS)) {
    throw "RootFS not found: $RootFS"
}

Write-Host "=== Checking WSL ==="
& wsl.exe --status 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "WSL is not installed. Enable the Microsoft-Windows-Subsystem-Linux and VirtualMachinePlatform features and reboot first."
}

$existing = (& wsl.exe -l -q 2>$null) -join ' '
if ($existing -match [regex]::Escape($Distro)) {
    Write-Host "Distribution '$Distro' already exists; reusing it."
} else {
    Write-Host "=== Importing $Distro from $RootFS ==="
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    & wsl.exe --import $Distro $InstallDir $RootFS --version 2
    if ($LASTEXITCODE -ne 0) {
        throw "wsl --import failed with exit code $LASTEXITCODE"
    }
}

Write-Host "=== Installing strongSwan inside $Distro ==="
& wsl.exe -d $Distro -u root -- bash -lc "export DEBIAN_FRONTEND=noninteractive; apt-get update && apt-get install -y strongswan strongswan-swanctl iptables iproute2 ca-certificates"
if ($LASTEXITCODE -ne 0) {
    throw "strongSwan installation failed with exit code $LASTEXITCODE"
}

Write-Host "=== Configuring forwarding and IKE port ==="
& wsl.exe -d $Distro -u root -- bash -lc "sysctl -w net.ipv4.ip_forward=1; iptables -C FORWARD -j ACCEPT 2>/dev/null || iptables -A FORWARD -j ACCEPT; grep -q 'port = 1194' /etc/strongswan.d/charon.conf || sed -i '0,/charon {/s//charon {\n    port = 1194/' /etc/strongswan.d/charon.conf; ipsec restart >/dev/null 2>&1 || true; echo ok"

Write-Host ""
Write-Host "Done. The client writes /etc/swanctl/conf.d/v5vpn.conf, ensures charon listens on 1194,"
Write-Host "installs the session VIP, adds the SNAT rules and (elevated) the Windows routes."
Write-Host "Verify with: wsl -d $Distro -u root -- swanctl --list-sas"
