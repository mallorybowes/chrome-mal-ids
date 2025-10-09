<#
####################################
# Chrome Malicious Extension Check #
####################################

Original bash script by Mallory Bowes:
https://github.com/mallorybowes/chrome-mal-ids

Converted to PowerShell.
#>

# --- Configuration ---
$SourceUrlExts = "https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list-meta.csv"
$TempFile = "$env:TEMP\bad-chrome-extensions.csv"
$MaliciousCount = 0

# --- Debug mode ---
if ($args.Count -gt 0) {
    if ($args[0] -eq "-v") {
        $DebugPreference = "Continue"
    } else {
        Write-Host "Only one optional argument: -v (debug mode)"
        exit 1
    }
}

# --- Extension paths ---
$ExtensionPaths = @(
    "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Extensions\",
    "$env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Extensions\",
    "$env:HOME\.config\google-chrome\Default\Extensions\",
    "$env:HOME\snap\brave\current\.config\BraveSoftware\Brave-Browser\Default\Extensions\",
    "$env:HOME\Library\Application Support\Google\Chrome\Default\Extensions\",
    "$env:HOME\Library\Application Support\BraveSoftware\Brave-Browser-Beta\Default\Extensions\"
)

$ExistingPaths = $ExtensionPaths | Where-Object { Test-Path $_ }

# --- Download list if newer ---
if (Test-Path $TempFile) {
    # Use If-Modified-Since
    $Headers = @{'If-Modified-Since' = (Get-Item $TempFile).LastWriteTime.ToUniversalTime().ToString("R")}
    try {
        Invoke-WebRequest -Uri $SourceUrlExts -Headers $Headers -OutFile $TempFile -ErrorAction Stop
    } catch {
        Write-Debug "No new update or download failed, continuing with existing file..."
    }
} else {
    Invoke-WebRequest -Uri $SourceUrlExts -OutFile $TempFile
}

# --- Read CSV lines ---
$CompromisedExtensions = Get-Content -Path $TempFile

# --- Verify header ---
if ($CompromisedExtensions[0] -ne "EXTID,EXTID-NAME,DATE-DIS,DATE-ADD,SOURCE,ARTICLE,ADD-SOURCES,CONTRIB,CONTRIB-METHOD,CONFIRM-MAL,REPORTED-MAL,NOTES") {
    Write-Host "Download failed or file is invalid. Try again."
    exit 1
}

Write-Host "Going to check for $($CompromisedExtensions.Count) currently known malicious extensions.`nSee: https://github.com/mallorybowes/chrome-mal-ids"

# --- Search ---
foreach ($line in $CompromisedExtensions) {
    if ($line -match "^EXTID") { continue }  # skip header
    $fields = $line -split ","
    $extId = $fields[0]
    foreach ($path in $ExistingPaths) {
        $target = Join-Path $path $extId
        if (Test-Path $target) {
            Write-Host "`nWe found something suspicious at $target" -ForegroundColor Yellow
            Write-Host "Name: $($fields[1])"
            Write-Host "Source: $($fields[4])"
            Write-Host "More info: $($fields[5])"
            $MaliciousCount++
        }
    }
}

# --- Summary ---
if ($MaliciousCount -eq 0) {
    Write-Host "No malicious extensions found." -ForegroundColor Green
} else {
    Write-Host "There were $MaliciousCount malicious extensions found." -ForegroundColor Red
}
