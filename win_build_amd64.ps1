# Recomended PowerShell Core Version: 7.5.0 or later
# Repo: https://github.com/darui3018823/pwsh_golang_build_sample

$exeName = "whois.exe"

Write-Host "Building $exeName for Windows AMD64..."
Write-Host "Removing old executables..."
Remove-Item "./dist/win/$exeName" -Force

$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o "./dist/win/$exeName" main.go
Remove-Item Env:GOOS
Remove-Item Env:GOARCH
Write-Host "Building $exeName for Windows AMD64 complete."
Write-Host "Server run command: ./dist/win/$exeName"