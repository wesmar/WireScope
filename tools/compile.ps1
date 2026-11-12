# WireScope - Compiles only the given translation units, with the project's settings and without
# linking: a quick check of a few changed files. Uses the toolchain that build.ps1 found and wrote
# into bin\build-receipt.json, so run build.ps1 once first.
#   .\tools\compile.ps1 src\core\Rules.cpp, src\gui\ProcessList.cpp
param([Parameter(Mandatory)][string[]]$Files)
$root = Split-Path -Parent $PSScriptRoot
$receiptPath = Join-Path $root 'bin\build-receipt.json'
if (-not (Test-Path $receiptPath)) { throw "${receiptPath} not found: run build.ps1 first." }
$receipt = Get-Content $receiptPath | ConvertFrom-Json
$msbuild = Join-Path $receipt.visualStudio 'MSBuild\Current\Bin\amd64\MSBuild.exe'
$output = & $msbuild (Join-Path $root 'WireScope.vcxproj') /t:ClCompile "/p:SelectedFiles=$($Files -join '%3B')" /p:Configuration=Release /p:Platform=x64 `
    "/p:VCToolsVersion=$($receipt.msvc)" "/p:WindowsTargetPlatformVersion=$($receipt.sdk)" /nologo /v:minimal /m 2>&1
$code = $LASTEXITCODE
$output | Where-Object { $_ -match 'error|warning' } | ForEach-Object { $_ -replace ' \[[^\]]*\.vcxproj\]$', '' } | Select-Object -Unique -First 60
"exit: $code"
exit $code
