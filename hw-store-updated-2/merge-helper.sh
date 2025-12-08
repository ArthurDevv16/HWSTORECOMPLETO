#!/bin/bash
# Usage: run from your project root. This will create a branch and copy files from the update zip after you extract them.
echo "This script assumes you've extracted the updated package into ../hw-store-updated and are running from your repo root."
BRANCH="hwstore-updates-automatic"
git checkout -b "$BRANCH"
cp -r ../hw-store-updated/* .
git add .
git commit -m "Integrate hw-store updates (auth, stripe, ws, redux)"
echo "Committed changes to $BRANCH. Push and open PR to merge with history preserved."
