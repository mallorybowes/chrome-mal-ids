<#
.SYNOPSIS
Scan Chrome extensions for known malicious extensions
.DESCRIPTION
Scan one or more extension directories for known malicious extensions.
You can scan all users or the current user.
https://github.com/mallorybowes/chrome-mal-ids
.PARAMETER Path
One or more additional extension directories to scan. Default Chrome directory already included.
.PARAMETER User
One or more local users to scan.
.PARAMETER AllUsers
Scan all local users.
.PARAMETER local
Use local file current-list-meta.csv 
.EXAMPLE
Scan-ChromeExtensions
.EXAMPLE
Scan-ChromeExtensions -local
.EXAMPLE
Scan-ChromeExtensions -AllUsers
.EXAMPLE
Scan-ChromeExtensions -Path "C:users\another\dir\with\extensions"
.EXAMPLE
Scan-ChromeExtensions -User bob
#>
param(
    [string[]]$Path,
    [string[]]$User = (Get-ChildItem Env:\USERNAME).Value,
    [switch]$AllUsers,
    [switch]$local
)

$SOURCEURL_EXTS="https://raw.githubusercontent.com/mallorybowes/chrome-mal-ids/master/current-list-meta.csv"

# evaluate file current-list-meta.csv
if ($local){
    $malicious_ext_list = Get-Content -Path ".\current-list-meta.csv"
            
} else {
    # download malicious extensions csv data
    $malicious_ext_list = Invoke-WebRequest -Method Get -Uri $SOURCEURL_EXTS
}

# convert malicious extensions data to csv object
$malicious_ext_CSV = ConvertFrom-Csv -InputObject $malicious_ext_list

# evaluate users to scan
if($User){
    $users = $User
} elseif($AllUsers) {
    # all users
    $users = Get-LocalUser | Where-Object -Property Enabled -eq $True | Select-Object -Property Name
} else{
    # current user
    $users = (Get-ChildItem Env:\USERNAME).Value
}

# evaluate extension directories to scan
$chrome_ext_path = "C:\Users\$user\AppData\Local\Google\Chrome\User Data\Default\Extensions"
$Path += $chrome_ext_path

# search user extensions
foreach ($user in $users){
    foreach ($filepath in $Path){
    
        if(Test-Path -Path $chrome_ext_path){
            
            $installed_ext = (Get-ChildItem -Path $filepath).Name

            $count = 0
            foreach ($ext in $installed_ext){
                if ($malicious_ext_CSV.EXTID -contains $ext){
                    $count += 1
                    $mal_ext_details = $malicious_ext_CSV | Where-Object {$_.EXTID -eq $ext}
                    $extid_name = $mal_ext_details.'EXTID-NAME'
                    $source = $mal_ext_details.SOURCE
                    $article = $mal_ext_details.ARTICLE
                
                    Write-Host "We found something suspicious:" -ForegroundColor Yellow
                    Write-Host "File Path: $filepath\$ext"
                    Write-Host "Name: $extid_name"
                    Write-Host "Source: $source"
                    Write-Host "More info: $article"
                    Write-Host ""
                }
            }
        }else{
            Write-Error "File path $chrome_ext_path does not exist"
        }
    }
}
    
# summary info
if ($count -eq 0){
    Write-Host "No malicious extensions found" -ForegroundColor Green
}else{
    Write-Host "There were $count malicious extensions found" -ForegroundColor Red
}