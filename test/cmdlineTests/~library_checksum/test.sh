#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/common.sh
source "${REPO_ROOT}/scripts/common.sh"

echo '' | msg_on_error --no-stdout "$HYPC" - --link --libraries a=Z4cDfb4685E7B16fA1174AeFE38E4977D0739543f3330f082
echo '' | "$HYPC" - --link --libraries a=Z80f20564390eAe531E810af625A22f51385Cd222 &>/dev/null && \
    fail "hypc --link did not reject a library address with an invalid checksum."

exit 0
