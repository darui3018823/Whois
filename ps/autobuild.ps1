# ps/autobuild.ps1 - Cross platform/cross-compile build helper for Whois CLI App
# Recommended PowerShell Core Version: 7.5+

# 2025 Whois CLI App: darui3018823 All rights reserved.
# All works created by darui3018823 associated with this repository are the intellectual property of darui3018823.
# Packages and other third-party materials used in this repository are subject to their respective licenses and copyrights.

param(
    [switch]$All,           # Build all common targets
    [switch]$Clean,         # Clean dist before build
    [string]$Version        # Optional version suffix for artifact naming
)

$ErrorActionPreference = 'Stop'

function New-DistTree {
    param([string]$Base)
    New-Item -ItemType Directory -Force -Path (Join-Path $Base 'win') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $Base 'mac') | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $Base 'linux') | Out-Null
}

function Remove-Dist {
    param([string]$Base)
    if (Test-Path $Base) { Remove-Item $Base -Recurse -Force }
}

function Build-One {
    param(
        [string]$GoOS,
        [string]$GoArch
    )

    $dist = Join-Path (Get-Location) 'dist'
    $exe = if ($GoOS -eq 'windows') { 'whois.exe' } else { 'whois' }
    $sub = switch ($GoOS) {
        'windows' { 'win' }
        'darwin'  { 'mac' }
        'linux'   { 'linux' }
        default   { $GoOS }
    }

    $outDir = Join-Path $dist $sub
    $out = Join-Path $outDir $exe

    Write-Host "🔨 Building: $GoOS-$GoArch -> $out" -ForegroundColor Green
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $env:GOOS = $GoOS
    $env:GOARCH = $GoArch
    go build -o $out main.go
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue

    Write-Host "✅ Done: $out" -ForegroundColor Green
}

# Entry
Write-Host "💡 Whois CLI – Auto Build" -ForegroundColor Cyan
$distRoot = Join-Path (Get-Location) 'dist'

if ($Clean) { Remove-Dist $distRoot }
New-DistTree $distRoot

if ($All) {
    $targets = @(
        @{os='windows'; arch='amd64'},
        @{os='windows'; arch='arm64'},
        @{os='darwin';  arch='amd64'},
        @{os='darwin';  arch='arm64'},
        @{os='linux';   arch='amd64'},
        @{os='linux';   arch='arm64'}
    )
    foreach ($t in $targets) { Build-One $t.os $t.arch }
}
else {
    # Build for current host OS/arch
    $os = if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'darwin' } else { 'linux' }
    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'amd64' }
        'ARM64' { 'arm64' }
        'x86'   { '386' }
        default { 'amd64' }
    }
    Build-One $os $arch
}

Write-Host "🎉 Build finished. Artifacts in ./dist" -ForegroundColor Cyan
