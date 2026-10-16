#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: run-harness-scope.sh COMMAND [ARG ...]" >&2
  exit 2
fi

SCOPE_NAME="${AGENTDLP_SCOPE_NAME:-agentdlp-harness}"
exec systemd-run \
  --user \
  --scope \
  --unit "$SCOPE_NAME" \
  --property "CollectMode=inactive-or-failed" \
  --property "NoNewPrivileges=yes" \
  --property "SystemCallFilter=~bpf" \
  -- "$@"
