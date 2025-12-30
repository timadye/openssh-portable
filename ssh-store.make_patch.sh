#!/bin/bash
[ $# -gt 0 ] || set -- V_7_4_P1
cat ssh-store.BUILD
for f in $(git diff --name-only "$1" | grep -ve '\.patch$' -e '^ssh-store\....*$' -e '^.gitignore' | sort); do
  git diff "$1" -- "$f"
done
