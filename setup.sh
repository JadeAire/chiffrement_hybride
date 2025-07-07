#!/bin/bash

echo "Creating venv with uv"
uv venv

echo "Venv created"

if [[ "$OSTYPE" == "darwin"* || "$OSTYPE" == "linux-gnu"* ]]; then
    source .venv/bin/activate
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32"* ]]; then
    .venv/Script/activate
else
    echo "unsuported OS for automatic solution. Please do it manually"
    exit 1
fi

echo "Installing dependancies"
uv pip sync

echo "Environnement prêt"