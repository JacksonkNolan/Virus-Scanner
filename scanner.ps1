<#
 =================================================================
  ADVANCED WINDOWS THREAT SCANNER v3.1
  Features: Zip Support + Dev Exclusions + Recursive + Loop
 =================================================================
#>

# 1. CONFIGURATION
# ----------------
# Regex patterns to look for (Powershell uses similar Regex to Mac)
$SigPatterns = "malware|trojan|miner|base64_decode|eval\(|osascript|cmd\.exe|powershell -e|WScript\.Shell"

# Temp folder for unzipping
$TempDir = "$env:TEMP\HyperscanLite_Extract"

# Clear screen at start
Clear-Host

Write-Host "╔════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     WINDOWS THREAT SCANNER v3.1 (Pro)      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan

# 2. MAIN LOOP
# ----------------
while ($true) {
    Write-Host "`nDrag and drop folder to scan (or type 'q' to quit):" -ForegroundColor Yellow
    $InputPath = Read-Host " > "

    # Clean up input (remove quotes if Windows adds them)
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
    # ------------------
    # Get-ChildItem is the Windows version of 'find'
    # We exclude common Dev folders to prevent false positives
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
        
        # Progress Indicator (Overwrites line)
        Write-Host -NoNewline "`r Scanning: $($File.Name.Substring(0, [math]::Min(30, $File.Name.Length)).PadRight(30))"

        # --- A. ZIP FILE HANDLING ---
        if ($File.Extension -eq ".zip") {
            try {
                if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue }
                Expand-Archive -Path $File.FullName -DestinationPath $TempDir -Force -ErrorAction SilentlyContinue
                
                # Scan extracted files
                $Match = Select-String -Path "$TempDir\*" -Pattern $SigPatterns -Quiet
                if ($Match) {
                    $IsInfected = $true
                    $ThreatType = "Malware inside ZIP Archive"
                }
            } catch {
                # Ignore zip errors (encrypted zips, etc)
            }
            if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue }

        # --- B. NORMAL FILE SCANNING ---
        } else {
            # Select-String is the Windows version of 'grep'
            $Match = Select-String -Path $File.FullName -Pattern $SigPatterns -Quiet
            if ($Match) {
                $IsInfected = $true
                $ThreatType = "Malicious Signature Found"
            }
        }

        # --- REPORTING ---
        if ($IsInfected) {
            Write-Host "`n[!!!] THREAT DETECTED: $($File.Name)" -ForegroundColor Red
            Add-Content -Path $LogFile -Value "THREAT: $($File.FullName) ($ThreatType)"
            $ThreatsFound++
        }
    }

    # 4. SUMMARY
    # ----------
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
