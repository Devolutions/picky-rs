#!/bin/env pwsh

$ErrorActionPreference = "Stop"

npm install

if ($LastExitCode -ne 0)
{
    throw "npm install failed"
}

npm run build

if ($LastExitCode -ne 0)
{
    throw "npm run build failed"
}

npm publish --access public

if ($LastExitCode -ne 0)
{
    throw "wasm-pack publish failed"
}

Write-Host "Success!"
