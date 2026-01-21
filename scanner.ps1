
$SigPatterns = "malware|trojan|miner|base64_decode|eval\(|osascript|cmd\.exe|powershell -e|WScript\.Shell"


$TempDir = "$env:TEMP\HyperscanLite_Extract"


Clear-Host

Write-Host "╔════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     WINDOWS THREAT SCANNER v3.1 (Pro)      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan


while ($true) {
    Write-Host "`nDrag and drop folder to scan (or type 'q' to quit):" -ForegroundColor Yellow
    $InputPath = Read-Host " > "

   
    $Target = $InputPath.Trim('"').Trim("'")

    if ($Target -eq "q" -or $Target -eq "exit") { break }
    if (-not (Test-Path $Target)) {
        Write-Host "[!] Error: Folder not found." -ForegroundColor Red
        continue
    }

    Write-Host "`n [.] Target: $Target"
    Write-Host " [.] Engine: PowerShell Native (Recursive)"
    Write-Host " [.] Filters: Ignoring .git, node_modules, Unity Library" -ForegroundColor Gray
    Write-Host " ------------------------------------------------"

    $TotalScanned = 0
    $ThreatsFound = 0
    $LogFile = "$PSScriptRoot\scan_report.txt"
    "Scan Report - $(Get-Date)" | Out-File -FilePath $LogFile -Encoding UTF8

    # 3. SCANNING ENGINE

    $Files = Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue | 
        Where-Object { 
            $_.FullName -notmatch "\\\.git\\" -and 
            $_.FullName -notmatch "\\Library\\" -and 
            $_.FullName -notmatch "\\node_modules\\" -and
            $_.Extension -notin ".xml", ".json", ".meta", ".png", ".jpg", ".mp4", ".dll"
        }

    foreach ($File in $Files) {
        $TotalScanned++
        $IsInfected = $false
        $ThreatType = ""
        
        
        Write-Host -NoNewline "`r Scanning: $($File.Name.Substring(0, [math]::Min(30, $File.Name.Length)).PadRight(30))"


        if ($File.Extension -eq ".zip") {
            try {
                if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue }
                Expand-Archive -Path $File.FullName -DestinationPath $TempDir -Force -ErrorAction SilentlyContinue
   
                $Match = Select-String -Path "$TempDir\*" -Pattern $SigPatterns -Quiet
                if ($Match) {
                    $IsInfected = $true
                    $ThreatType = "Malware inside ZIP Archive"
                }
            } catch {
         
            }
            if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue }


        } else {
  
            $Match = Select-String -Path $File.FullName -Pattern $SigPatterns -Quiet
            if ($Match) {
                $IsInfected = $true
                $ThreatType = "Malicious Signature Found"
            }
        }

       
        if ($IsInfected) {
            Write-Host "`n[!!!] THREAT DETECTED: $($File.Name)" -ForegroundColor Red
            Add-Content -Path $LogFile -Value "THREAT: $($File.FullName) ($ThreatType)"
            $ThreatsFound++
        }
    }

    
    Write-Host "`n`n════════════════════════════════════════════" -ForegroundColor Gray
    Write-Host " Files Analyzed: $TotalScanned"
    
    if ($ThreatsFound -gt 0) {
        Write-Host " Status: $ThreatsFound THREATS DETECTED" -ForegroundColor Red
        Write-Host " Check scan_report.txt for details."
        Invoke-Item $LogFile
    } else {
        Write-Host " Status: SYSTEM CLEAN" -ForegroundColor Green
    }
    Write-Host "════════════════════════════════════════════" -ForegroundColor Gray
}
