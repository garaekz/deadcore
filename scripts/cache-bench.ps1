param(
    [string[]]$Fixture = @("minimal", "api", "complex"),
    [string]$Binary
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot

function Resolve-Binary {
    param(
        [string]$Requested
    )

    if (-not [string]::IsNullOrWhiteSpace($Requested)) {
        return (Resolve-Path $Requested).Path
    }

    $releaseBinary = Join-Path $RepoRoot "target\release\oxinfer.exe"
    if (-not (Test-Path $releaseBinary)) {
        & cargo build --locked --release
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }

    return $releaseBinary
}

function New-CacheManifest {
    param(
        [string]$FixtureName,
        [string]$TempRoot
    )

    $fixtureManifest = Join-Path $RepoRoot "fixtures\$FixtureName.manifest.json"
    if (-not (Test-Path $fixtureManifest)) {
        throw "fixture manifest not found: $fixtureManifest"
    }

    $manifest = Get-Content $fixtureManifest -Raw | ConvertFrom-Json
    $manifest.project.root = [System.IO.Path]::GetFullPath(
        (Join-Path (Split-Path -Parent $fixtureManifest) $manifest.project.root)
    )
    $cacheConfig = [pscustomobject]@{
        enabled = $true
        kind = "mtime"
    }
    $manifest | Add-Member -NotePropertyName cache -NotePropertyValue $cacheConfig -Force

    $target = Join-Path $TempRoot "$FixtureName.manifest.json"
    $json = $manifest | ConvertTo-Json -Depth 100
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($target, $json, $utf8NoBom)
    return $target
}

function Invoke-OxinferRun {
    param(
        [string]$Executable,
        [string]$ManifestPath,
        [string]$CacheDir
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.WorkingDirectory = $RepoRoot
    $arguments = @("--manifest", $ManifestPath, "--cache-dir", $CacheDir, "--log-level", "info") |
        ForEach-Object {
            if ($_ -match '[\s"]') {
                '"' + $_.Replace('"', '\"') + '"'
            }
            else {
                $_
            }
        }
    $startInfo.Arguments = [string]::Join(" ", $arguments)

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    [void]$process.Start()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $stopwatch.Stop()

    if ($process.ExitCode -ne 0) {
        throw "oxinfer failed: $stderr"
    }

    return @{
        DurationMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
        Payload = $stdout | ConvertFrom-Json
        Stderr = $stderr.Trim()
    }
}

function Get-CacheCounts {
    param(
        [string]$Stderr
    )

    $match = [regex]::Match($Stderr, 'cache=(\d+) hit\(s\), (\d+) miss\(es\)')
    if (-not $match.Success) {
        throw "cache stats were not found in stderr: $Stderr"
    }

    return @{
        Hits = [int]$match.Groups[1].Value
        Misses = [int]$match.Groups[2].Value
    }
}

$binaryPath = Resolve-Binary -Requested $Binary
$rows = @()

foreach ($fixtureName in $Fixture) {
    $tempRoot = Join-Path $env:TEMP ("oxinfer-cache-bench-" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    try {
        $cacheDir = Join-Path $tempRoot "cache"
        $manifestPath = New-CacheManifest -FixtureName $fixtureName -TempRoot $tempRoot

        $cold = Invoke-OxinferRun -Executable $binaryPath -ManifestPath $manifestPath -CacheDir $cacheDir
        $warm = Invoke-OxinferRun -Executable $binaryPath -ManifestPath $manifestPath -CacheDir $cacheDir
        $coldCache = Get-CacheCounts -Stderr $cold.Stderr
        $warmCache = Get-CacheCounts -Stderr $warm.Stderr
        $filesParsed = [int]$cold.Payload.meta.stats.filesParsed

        if ($coldCache.Hits -ne 0 -or $coldCache.Misses -ne $filesParsed) {
            throw "$fixtureName cold run did not populate the cache cleanly: $($cold.Stderr)"
        }
        if ($warmCache.Hits -ne $filesParsed -or $warmCache.Misses -ne 0) {
            throw "$fixtureName warm run did not fully reuse the cache: $($warm.Stderr)"
        }

        $speedup = if ($warm.DurationMs -le 0) {
            [double]::PositiveInfinity
        } else {
            [math]::Round($cold.DurationMs / $warm.DurationMs, 2)
        }

        $rows += [pscustomobject]@{
            Fixture = $fixtureName
            Files = $filesParsed
            ColdMs = $cold.DurationMs
            WarmMs = $warm.DurationMs
            SpeedupX = $speedup
            ColdCache = "$($coldCache.Hits) hit / $($coldCache.Misses) miss"
            WarmCache = "$($warmCache.Hits) hit / $($warmCache.Misses) miss"
            Status = "warm-reused"
        }
    }
    finally {
        if (Test-Path $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }
}

$rows | Format-Table -AutoSize
