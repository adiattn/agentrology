#!/usr/bin/env bash
set -e

echo "[FORMAT] Running Ruff (lint + fix)..."
uv run ruff check . --fix

echo "[FORMAT] Running Black..."
uv run black .

echo "[DONE] Codebase formatted with Ruff + Black"
