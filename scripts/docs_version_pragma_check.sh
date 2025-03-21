#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# This file is part of hyperion.
#
# hyperion is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# hyperion is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with hyperion.  If not, see <http://www.gnu.org/licenses/>
#
# (c) 2016 hyperion contributors.
#------------------------------------------------------------------------------

# This script verifies that the examples compile with the oldest version mentioned in the pragma.
# It does not verify that it cannot be compiled with an older version
# and it also does not verify that it can be compiled with the newest version compatible with the pragma.

set -e

## GLOBAL VARIABLES

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
HYPERION_BUILD_DIR=${HYPERION_BUILD_DIR:-${REPO_ROOT}/build}
# shellcheck source=scripts/common.sh
source "${REPO_ROOT}/scripts/common.sh"
# shellcheck source=scripts/common_cmdline.sh
source "${REPO_ROOT}/scripts/common_cmdline.sh"

developmentVersion=$("$REPO_ROOT/scripts/get_version.sh")

function versionGreater
{
    v1=$1
    v2=$2
    # shellcheck disable=SC2206
    ver1=( ${v1//./ } )
    # shellcheck disable=SC2206
    ver2=( ${v2//./ } )

    if (( "${ver1[0]}" > "${ver2[0]}" ))
    then
        return 0
    elif (( "${ver1[0]}" == "${ver2[0]}" )) && (( "${ver1[1]}" > "${ver2[1]}" ))
    then
        return 0
    elif (( "${ver1[0]}" == "${ver2[0]}" )) && (( "${ver1[1]}" == "${ver2[1]}" )) && (( "${ver1[2]}" > "${ver2[2]}" ))
    then
        return 0
    fi
    return 1
}

function versionEqual
{
    if [[ "$1" == "$2" ]]
    then
        return 0
    fi
    return 1
}

function getAllAvailableVersions
{
    allVersions=()
    local allListedVersions
    mapfile -t allListedVersions <<< "$(
        wget -q -O- https://binaries.soliditylang.org/bin/list.txt |
        grep -Po '(?<=hypjson-v)\d+.\d+.\d+(?=\+commit)' |
        sort -V
    )"
    for listed in "${allListedVersions[@]}"
    do
        if versionGreater "$listed" "0.4.10"
        then
            allVersions+=( "$listed" )
        fi
    done
}

function findMinimalVersion
{
    local f=$1
    local greater=false
    local pragmaVersion

    # Get minimum compiler version defined by pragma
    if (grep -Po '(?<=pragma hyperion >=)\d+.\d+.\d+' "$f" >/dev/null)
    then
        pragmaVersion="$(grep -Po '(?<=pragma hyperion >=)\d+.\d+.\d+' "$f")"
        sign=">="
    elif (grep -Po '(?<=pragma hyperion \^)\d+.\d+.\d+' "$f" >/dev/null)
    then
        pragmaVersion="$(grep -Po '(?<=pragma hyperion \^)\d+.\d+.\d+' "$f")"
        sign="^"
    elif (grep -Po '(?<=pragma hyperion >)\d+.\d+.\d+' "$f" >/dev/null)
    then
        pragmaVersion="$(grep -Po '(?<=pragma hyperion >)\d+.\d+.\d+' "$f")"
        sign=">"
        greater=true;
    else
        printError "No valid pragma statement in file. Skipping..."
        return
    fi

    version=""
    for ver in "${allVersions[@]}" "$developmentVersion"
    do
        if versionGreater "$ver" "$pragmaVersion"
        then
            version="$ver"
            break
        elif [[ "$greater" == false ]] && versionEqual "$ver" "$pragmaVersion"
        then
            version="$ver"
            break
        fi
    done

    if [[ "$version" == "" ]]
    then
        printError "No release ${sign}${pragmaVersion} was listed in available releases!"
        exit 1
    fi
}

printTask "Verifying that all examples from the documentation have the correct version range..."
HYPTMPDIR=$(mktemp -d)
(
    set -e
    cd "$HYPTMPDIR"
    "$REPO_ROOT"/scripts/isolate_tests.py "$REPO_ROOT"/docs/

    getAllAvailableVersions

    for f in *.hyp
    do
        # The contributors guide uses syntax tests, but we cannot
        # really handle them here.
        if grep -E 'DeclarationError:|// ----' "$f" >/dev/null
        then
            continue
        fi
        echo "$f"

        opts=()
        # We expect errors if explicitly stated, or if imports
        # are used (in the style guide)
        if ( ! grep -E "This will not compile after" "$f" >/dev/null && \
            grep -E "This will not compile|import \"" "$f" >/dev/null )
        then
            opts=(--expect-errors)
        fi

        # ignore warnings in this case
        opts+=(--ignore-warnings)

        findMinimalVersion "$f"
        if [[ "$version" == "" ]]
        then
            continue
        fi
        if [[ "$version" == "$developmentVersion" ]]
        then
            printWarning "Skipping unreleased development version $developmentVersion"
            continue
        fi

        opts+=(-v "$version")

        hypc_bin="hypc-$version"
        echo "$hypc_bin"
        if [[ ! -f "$hypc_bin" ]]
        then
            echo "Downloading release from github..."
            if wget -q "https://github.com/theQRL/hyperion/releases/download/v$version/hypc-static-linux" >/dev/null
            then
                mv hypc-static-linux "$hypc_bin"
            else
                printError "No release $version was found on github!"
                continue
            fi
        fi

        ln -sf "$hypc_bin" "hypc"
        chmod a+x hypc

        HYPC="$HYPTMPDIR/hypc" compileFull "${opts[@]}" "$HYPTMPDIR/$f"
    done
)
rm -rf "$HYPTMPDIR"
echo "Done."
