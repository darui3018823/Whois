# Recomended PowerShell Core Version: 7.5.0 or later
# Repo: https://github.com/darui3018823/pwsh_golang_build_sample

$ErrorActionPreference = 'Stop'

$exeName = "whois.exe"
${distDir} = Join-Path "." "dist/win"

Write-Host "Building $exeName for Windows AMD64..."
Write-Host "Preparing dist directory..."
New-Item -ItemType Directory -Path ${distDir} -Force | Out-Null
if (Test-Path (Join-Path ${distDir} $exeName)) {
	Write-Host "Removing old executable..."
	Remove-Item (Join-Path ${distDir} $exeName) -Force -ErrorAction SilentlyContinue
}

$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o (Join-Path ${distDir} $exeName) main.go
Remove-Item Env:GOOS
Remove-Item Env:GOARCH
Write-Host "Building $exeName for Windows AMD64 complete."
Write-Host "Run: ./dist/win/$exeName"