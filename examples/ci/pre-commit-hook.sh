#!/usr/bin/env bash
# Pre-commit hook for Detection-as-Code validation with ODCP.
#
# Install:
#   cp examples/ci/pre-commit-hook.sh .git/hooks/pre-commit
#   chmod +x .git/hooks/pre-commit
#
# Or use with pre-commit framework (.pre-commit-config.yaml):
#   - repo: local
#     hooks:
#       - id: odcp-validate
#         name: ODCP Detection Validation
#         entry: bash examples/ci/pre-commit-hook.sh
#         language: system
#         pass_filenames: false

set -euo pipefail

# Detect which detection directories have staged changes
CHANGED_SIGMA=$(git diff --cached --name-only -- 'sigma_rules/' '*.yml' '*.yaml' 2>/dev/null || true)
CHANGED_ELASTIC=$(git diff --cached --name-only -- 'elastic_rules/' 2>/dev/null || true)
CHANGED_SENTINEL=$(git diff --cached --name-only -- 'sentinel_rules/' 2>/dev/null || true)
CHANGED_CHRONICLE=$(git diff --cached --name-only -- 'chronicle_rules/' 2>/dev/null || true)
CHANGED_SPLUNK=$(git diff --cached --name-only -- 'splunk_app/' 2>/dev/null || true)

EXIT_CODE=0

if [ -n "$CHANGED_SIGMA" ] && [ -d "sigma_rules" ]; then
    echo "==> Validating Sigma rules..."
    odcp validate sigma_rules/ --platform sigma --require-description || EXIT_CODE=1
fi

if [ -n "$CHANGED_ELASTIC" ] && [ -d "elastic_rules" ]; then
    echo "==> Validating Elastic rules..."
    odcp validate elastic_rules/ --platform elastic --require-description || EXIT_CODE=1
fi

if [ -n "$CHANGED_SENTINEL" ] && [ -d "sentinel_rules" ]; then
    echo "==> Validating Sentinel rules..."
    odcp validate sentinel_rules/ --platform sentinel --require-description || EXIT_CODE=1
fi

if [ -n "$CHANGED_CHRONICLE" ] && [ -d "chronicle_rules" ]; then
    echo "==> Validating Chronicle rules..."
    odcp validate chronicle_rules/ --platform chronicle --require-description || EXIT_CODE=1
fi

if [ -n "$CHANGED_SPLUNK" ] && [ -d "splunk_app" ]; then
    echo "==> Validating Splunk app..."
    odcp validate splunk_app/ --platform splunk --require-description || EXIT_CODE=1
fi

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "Detection validation failed. Fix the issues above before committing."
fi

exit $EXIT_CODE
