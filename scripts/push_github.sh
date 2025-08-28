#!/usr/bin/env bash
set -euo pipefail
REPO_SLUG="${1:-yourname/pocketwatcher}"
git init
git add .
git commit -m "feat: initial Pocketwatcher v0.2.0 with Geo/ASN enrichment and publish workflow"
git branch -M main
git remote add origin "https://github.com/${REPO_SLUG}.git"
git push -u origin main
# Tag for PyPI publish via GH Actions
git tag "v0.2.0"
git push origin "v0.2.0"
echo "Pushed to https://github.com/${REPO_SLUG} and tagged v0.2.0"
