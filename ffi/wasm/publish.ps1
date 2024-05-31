#!/bin/env pwsh

$ErrorActionPreference = "Stop"

wasm-pack build --target web --scope devolutions --out-name picky

if ($LastExitCode -ne 0)
{
    throw "wasm-pack build failed"
}

wasm-pack publish --access=public

if ($LastExitCode -ne 0)
{
    throw "wasm-pack publish failed"
}

Write-Host "Success!"
