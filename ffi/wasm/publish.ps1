#!/bin/env pwsh

$ErrorActionPreference = "Stop"

npm run build:wasm && npm run build

if ($LastExitCode -ne 0)
{
    throw "wasm-pack build failed"
}

npm run publish 

if ($LastExitCode -ne 0)
{
    throw "wasm-pack publish failed"
}

Write-Host "Success!"
