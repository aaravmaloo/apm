$ErrorActionPreference = "Stop"

$RootDir = Resolve-Path (Join-Path $PSScriptRoot "..")

if (-not $env:CARGO_TARGET_DIR) {
    $env:CARGO_TARGET_DIR = Join-Path $RootDir "rust\target"
}

Write-Host "Testing Go root module..."
go test ./...
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Testing Go team module..."
Push-Location (Join-Path $RootDir "team")
go test ./...
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    exit $LASTEXITCODE
}
Pop-Location

Write-Host "Testing rust/apm-get..."
cargo test --manifest-path (Join-Path $RootDir "rust\apm-get\Cargo.toml")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Checking rust/apm-native..."
cargo check --manifest-path (Join-Path $RootDir "rust\apm-native\Cargo.toml") --all-targets
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Checking rust/faceid..."
cargo check --manifest-path (Join-Path $RootDir "rust\faceid\Cargo.toml") --lib
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
