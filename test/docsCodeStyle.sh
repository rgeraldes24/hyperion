#!/usr/bin/env bash

set -e

## GLOBAL VARIABLES

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)

## FUNCTIONS

if [ "$CIRCLECI" ]
then
    function printTask { echo "$(tput bold)$(tput setaf 2)$1$(tput setaf 7)"; }
    function printError { echo "$(tput setaf 1)$1$(tput setaf 7)"; }
else
    function printTask { echo "$(tput bold)$(tput setaf 2)$1$(tput sgr0)"; }
    function printError { echo "$(tput setaf 1)$1$(tput sgr0)"; }
fi

printTask "Checking docs examples style"
HYPTMPDIR=$(mktemp -d)
(
    set -e
    cd "$HYPTMPDIR"
    "$REPO_ROOT"/scripts/isolate_tests.py "$REPO_ROOT"/docs/

    if npm -v >/dev/null 2>&1; then
        if npm list -g | grep solhint >/dev/null 2>&1; then
            echo "node is installed, setting up solhint"
            cp "$REPO_ROOT"/test/.solhint.json "$HYPTMPDIR"/.solhint.json
            cp "$REPO_ROOT"/test/.solhintignore "$HYPTMPDIR"/.solhintignore

            for f in *.hyp
            do
                echo "$f"
                # Only report errors
                solhint -f unix "$HYPTMPDIR/$f"
            done
        else
            echo "node is installed, but not solhint"
            exit 1
        fi
    else
        echo "node not installed, skipping docs style checker"
        exit 1
    fi
)
rm -rf "$HYPTMPDIR"
echo "Done."
