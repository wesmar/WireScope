# WireScope CLI automated showcase
Set-Location 'C:\Projekty\WireScope\bin'
Write-Host -ForegroundColor Cyan "`n============================================================"
Write-Host -ForegroundColor Cyan "   WireScope CLI: High-Performance Network Adapters Discovery"
Write-Host -ForegroundColor Cyan "============================================================"
& .\WireScope.exe --adapters

Start-Sleep -Seconds 3

Write-Host -ForegroundColor Yellow "`n============================================================"
Write-Host -ForegroundColor Yellow "   WireScope CLI: Impairment Simulator Parameter Validation"
Write-Host -ForegroundColor Yellow "============================================================"
& .\WireScope.exe --check --latency 80 --loss 5

Start-Sleep -Seconds 3
exit
