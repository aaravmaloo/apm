$ErrorActionPreference = "Stop"

$Repo = "aaravmaloo/apm"
$LatestApi = "https://api.github.com/repos/$Repo/releases/latest"
$InstallDir = Join-Path $env:LOCALAPPDATA "pm"
$TargetExe = Join-Path $InstallDir "apm.exe"

$archRaw = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
$arch = switch ($archRaw) {
    "x64" { "amd64" }
    "arm64" { "arm64" }
    default { throw "Unsupported Windows architecture: $archRaw" }
}

$tempRoot = Join-Path $env:TEMP ("apm-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tempRoot | Out-Null

try {
    $headers = @{ "User-Agent" = "apm-installer" }
    $release = Invoke-RestMethod -Uri $LatestApi -Headers $headers

    $asset = $release.assets |
        Where-Object { $_.name -match "^stable-.*-windows_${arch}\\.exe\\.zip$" } |
        Select-Object -First 1

    if (-not $asset) {
        $asset = $release.assets |
            Where-Object { $_.name -match "_windows_${arch}\\.zip$" } |
            Select-Object -First 1
    }

    if (-not $asset) {
        throw "Could not find a Windows ($arch) release asset in $LatestApi (expected stable-v*-windows_${arch}.exe.zip)"
    }

    $zipPath = Join-Path $tempRoot "apm.zip"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -Headers $headers

    $extractDir = Join-Path $tempRoot "extract"
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    $binary = Get-ChildItem -Path $extractDir -Recurse -File |
        Where-Object { $_.Name -in @("apm.exe", "pm.exe") } |
        Select-Object -First 1

    if (-not $binary) {
        throw "Could not find apm.exe or pm.exe in downloaded release archive"
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path $binary.FullName -Destination $TargetExe -Force

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $pathEntries = @()
    if (-not [string]::IsNullOrWhiteSpace($userPath)) {
        $pathEntries = $userPath.Split(";", [System.StringSplitOptions]::RemoveEmptyEntries)
    }

    $alreadyInPath = $false
    foreach ($entry in $pathEntries) {
        if ([string]::Equals($entry.TrimEnd("\\"), $InstallDir.TrimEnd("\\"), [System.StringComparison]::OrdinalIgnoreCase)) {
            $alreadyInPath = $true
            break
        }
    }

    $pathUpdated = $false
    if (-not $alreadyInPath) {
        $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
            $InstallDir
        } else {
            "$userPath;$InstallDir"
        }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        $pathUpdated = $true
    }

    $version = if ($release.tag_name) { $release.tag_name } else { "latest" }
    Write-Host "Installed apm ($version)"
    Write-Host "Binary: $TargetExe"
    if ($pathUpdated) {
        Write-Host "Added to user PATH: $InstallDir"
        Write-Host "Restart your terminal to use 'apm' from anywhere."
    } else {
        Write-Host "PATH already contains: $InstallDir"
    }
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item -Path $tempRoot -Recurse -Force
    }
}
