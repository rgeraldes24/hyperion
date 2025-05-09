#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/common.sh
source "${REPO_ROOT}/scripts/common.sh"

echo '' | msg_on_error --no-stdout "$HYPC" - --link --libraries a=Z4cDfb4685E7B16fA1174AeFE38E4977D0739543f3330f082
echo '' | "$HYPC" - --link --libraries a=Zf1464D1d35ea0D0D0087Db2549479cefd0e8ACf972727Eea &>/dev/null && \
    fail "hypc --link did not reject a library address with an invalid checksum."

exit 0
