# build_release.ps1
$ErrorActionPreference = "Stop"

$version = (git describe --tags --abbrev=0) 2>$null
if (-not $version) { $version = "v0.1.0" }  # fallback if you haven't tagged yet

$dist = "dist"
Remove-Item -Recurse -Force $dist -ErrorAction Ignore
New-Item -ItemType Directory -Force -Path "$dist/win-x64","$dist/linux-x64" | Out-Null

Write-Host "Publishing Windows (self-contained, single-file)..."
dotnet publish PerfMonDotNet9.csproj `
  -f net9.0-windows -r win-x64 -c Release `
  -p:PublishSingleFile=true --self-contained true `
  -o "$dist/win-x64"

Write-Host "Publishing Linux (self-contained, single-file)..."
dotnet publish PerfMonDotNet9.csproj `
  -f net9.0 -r linux-x64 -c Release `
  -p:PublishSingleFile=true --self-contained true `
  -o "$dist/linux-x64"

# Package
Compress-Archive -Path "$dist/win-x64/*" -DestinationPath "$dist/PerfMonDotNet9-$version-win-x64.zip" -Force
# For Linux tar.gz (uses tar from Windows 10+ or Git Bash in PATH)
tar -C "$dist/linux-x64" -czf "$dist/PerfMonDotNet9-$version-linux-x64.tar.gz" .

# Checksums
Get-FileHash "$dist/PerfMonDotNet9-$version-win-x64.zip" -Algorithm SHA256 | ForEach-Object { $_.Hash + "  PerfMonDotNet9-$version-win-x64.zip" } | Out-File "$dist/SHA256SUMS.txt"
Get-FileHash "$dist/PerfMonDotNet9-$version-linux-x64.tar.gz" -Algorithm SHA256 | ForEach-Object { $_.Hash + "  PerfMonDotNet9-$version-linux-x64.tar.gz" } >> "$dist/SHA256SUMS.txt"

Write-Host "`nArtifacts:"
Get-ChildItem $dist | Select Name,Length
